import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from app.utils.domain import clean_domain


ENGAGEMENT_VERSION = "wse1"
ENGAGEMENT_PURPOSE = "verified_engagement"
ALLOWED_ENVIRONMENTS = {"production", "staging", "development"}
ALLOWED_SCANNERS = {
    "crawler",
    "exposure_checks",
    "cors",
    "http_methods",
    "subdomains",
    "ports",
    "javascript_advisories",
    "zap_baseline",
}
DEFAULT_SCANNERS = sorted(ALLOWED_SCANNERS - {"zap_baseline"})


class EngagementProfileError(ValueError):
    pass


def _timestamp(now=None):
    value = now or datetime.now(timezone.utc)
    return int(value.timestamp())


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except Exception as error:
        raise EngagementProfileError(
            "The engagement receipt is malformed."
        ) from error

    if _encode(decoded) != value:
        raise EngagementProfileError(
            "The engagement receipt uses invalid encoding."
        )
    return decoded


def _validate_secret(secret: str):
    if not isinstance(secret, str) or len(secret) < 32:
        raise EngagementProfileError(
            "The engagement signing secret must contain at least 32 characters."
        )


def _clean_text(value, field_name, minimum=2, maximum=120):
    cleaned = " ".join(str(value or "").split())
    if not minimum <= len(cleaned) <= maximum:
        raise EngagementProfileError(
            f"{field_name} must contain between {minimum} and {maximum} characters."
        )
    return cleaned


def _validate_settings(settings: dict) -> dict:
    if not isinstance(settings, dict):
        raise EngagementProfileError("Engagement settings are required.")

    environment = str(settings.get("environment", "production")).lower()
    if environment not in ALLOWED_ENVIRONMENTS:
        raise EngagementProfileError("The engagement environment is unsupported.")

    try:
        max_pages = int(settings.get("max_pages", 25))
        max_depth = int(settings.get("max_depth", 2))
        zap_spider_minutes = int(settings.get("zap_spider_minutes", 1))
        zap_maximum_minutes = int(settings.get("zap_maximum_minutes", 5))
    except (TypeError, ValueError) as error:
        raise EngagementProfileError(
            "Engagement scan limits must be whole numbers."
        ) from error

    if not 1 <= max_pages <= 50:
        raise EngagementProfileError("The page limit must be between 1 and 50.")
    if not 0 <= max_depth <= 3:
        raise EngagementProfileError("The crawl depth must be between 0 and 3.")
    if not 1 <= zap_spider_minutes <= 3:
        raise EngagementProfileError("ZAP spider time must be between 1 and 3 minutes.")
    if not 2 <= zap_maximum_minutes <= 10:
        raise EngagementProfileError("ZAP maximum time must be between 2 and 10 minutes.")

    scanners = settings.get("approved_scanners", DEFAULT_SCANNERS)
    if not isinstance(scanners, list) or not scanners:
        raise EngagementProfileError("At least one scanner must be approved.")
    normalized_scanners = sorted(set(str(item) for item in scanners))
    unsupported = set(normalized_scanners) - ALLOWED_SCANNERS
    if unsupported:
        raise EngagementProfileError(
            "The engagement contains an unsupported scanner permission."
        )

    include_zap = bool(settings.get("include_zap", False))
    if include_zap and "zap_baseline" not in normalized_scanners:
        raise EngagementProfileError(
            "ZAP must be explicitly included in the approved scanner list."
        )
    if not include_zap and "zap_baseline" in normalized_scanners:
        normalized_scanners.remove("zap_baseline")

    if settings.get("authorization_confirmed") is not True:
        raise EngagementProfileError(
            "Explicit assessment authorization must be confirmed."
        )

    return {
        "client_reference": _clean_text(
            settings.get("client_reference"), "Client reference"
        ),
        "authorized_by": _clean_text(
            settings.get("authorized_by"), "Authorizer name"
        ),
        "environment": environment,
        "max_pages": max_pages,
        "max_depth": max_depth,
        "include_zap": include_zap,
        "zap_spider_minutes": zap_spider_minutes,
        "zap_maximum_minutes": zap_maximum_minutes,
        "approved_scanners": normalized_scanners,
        "authorization_confirmed": True,
    }


def create_engagement_profile(
    domain: str,
    ownership_payload: dict,
    settings: dict,
    secret: str,
    now=None,
    ttl_seconds: int = 86400,
) -> dict:
    _validate_secret(secret)
    safe_domain = clean_domain(domain)

    if ownership_payload.get("domain") != safe_domain:
        raise EngagementProfileError(
            "The ownership authorization belongs to a different domain."
        )
    if ttl_seconds < 1800 or ttl_seconds > 604800:
        raise EngagementProfileError(
            "Engagement access must last between 30 minutes and seven days."
        )

    validated = _validate_settings(settings)
    issued_at = _timestamp(now)
    payload = {
        "purpose": ENGAGEMENT_PURPOSE,
        "engagement_id": secrets.token_urlsafe(12),
        "domain": safe_domain,
        "scope": [safe_domain],
        "verification_method": ownership_payload.get("verification_method"),
        "issued_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
        **validated,
    }
    encoded_payload = _encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature = hmac.new(
        secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256
    ).digest()
    receipt = f"{ENGAGEMENT_VERSION}.{encoded_payload}.{_encode(signature)}"

    return {
        **payload,
        "receipt": receipt,
        "expires_in_seconds": ttl_seconds,
    }


def validate_engagement_profile(
    receipt: str,
    expected_domain: str,
    secret: str,
    now=None,
) -> dict:
    _validate_secret(secret)
    try:
        version, encoded_payload, encoded_signature = receipt.split(".")
    except ValueError as error:
        raise EngagementProfileError(
            "The engagement receipt is malformed."
        ) from error

    if version != ENGAGEMENT_VERSION:
        raise EngagementProfileError("The engagement receipt version is unsupported.")

    expected_signature = hmac.new(
        secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256
    ).digest()
    supplied_signature = _decode(encoded_signature)
    if not hmac.compare_digest(expected_signature, supplied_signature):
        raise EngagementProfileError("The engagement receipt signature is invalid.")

    try:
        payload = json.loads(_decode(encoded_payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EngagementProfileError(
            "The engagement receipt payload is invalid."
        ) from error

    safe_domain = clean_domain(expected_domain)
    if payload.get("purpose") != ENGAGEMENT_PURPOSE:
        raise EngagementProfileError("This receipt does not authorize an engagement.")
    if payload.get("domain") != safe_domain or payload.get("scope") != [safe_domain]:
        raise EngagementProfileError(
            "This engagement receipt belongs to a different domain."
        )

    _validate_settings(payload)
    current_time = _timestamp(now)
    try:
        issued_at = int(payload["issued_at"])
        expires_at = int(payload["expires_at"])
    except (KeyError, TypeError, ValueError) as error:
        raise EngagementProfileError("The engagement receipt is incomplete.") from error
    if current_time > expires_at:
        raise EngagementProfileError("The engagement authorization has expired.")
    if issued_at > current_time + 60 or expires_at <= issued_at:
        raise EngagementProfileError("The engagement receipt has invalid timing.")

    return payload
