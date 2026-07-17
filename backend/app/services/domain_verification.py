import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests

from app.utils.safe_http import safe_get

from app.utils.domain import clean_domain


TOKEN_VERSION = "ws1"
AUTHORIZATION_VERSION = "wsa1"
VERIFICATION_PREFIX = "webshield-verification="


class VerificationError(ValueError):
    pass


def _encode_base64(value: bytes) -> str:
    return (
        base64.urlsafe_b64encode(value)
        .decode("ascii")
        .rstrip("=")
    )


def _decode_base64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)

    try:
        decoded_value = base64.urlsafe_b64decode(
            value + padding
        )
    except Exception as error:
        raise VerificationError(
            "The verification token is malformed."
        ) from error

    if _encode_base64(decoded_value) != value:
        raise VerificationError(
            "The verification token uses an invalid "
            "Base64 encoding."
        )

    return decoded_value
    padding = "=" * (-len(value) % 4)

   

def _validate_secret(secret: str):
    if not isinstance(secret, str) or len(secret) < 32:
        raise VerificationError(
            "The verification secret must contain "
            "at least 32 characters."
        )


def _timestamp(value: datetime | None = None) -> int:
    current_time = value or datetime.now(timezone.utc)

    if current_time.tzinfo is None:
        current_time = current_time.replace(
            tzinfo=timezone.utc
        )

    return int(current_time.timestamp())


def create_verification_challenge(
    domain: str,
    secret: str,
    now: datetime | None = None,
    ttl_seconds: int = 900,
):
    _validate_secret(secret)

    if ttl_seconds < 60 or ttl_seconds > 3600:
        raise VerificationError(
            "Verification challenges must last between "
            "60 seconds and one hour."
        )

    safe_domain = clean_domain(domain)
    issued_at = _timestamp(now)
    expires_at = issued_at + ttl_seconds

    payload = {
        "domain": safe_domain,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": secrets.token_urlsafe(16),
    }

    payload_bytes = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    encoded_payload = _encode_base64(payload_bytes)

    signature = hmac.new(
        secret.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()

    token = (
        f"{TOKEN_VERSION}."
        f"{encoded_payload}."
        f"{_encode_base64(signature)}"
    )

    verification_value = (
        f"{VERIFICATION_PREFIX}{token}"
    )

    return {
        "domain": safe_domain,
        "token": token,
        "verification_value": verification_value,
        "dns_record_name": (
            f"_webshield-verification.{safe_domain}"
        ),
        "dns_record_type": "TXT",
        "dns_record_value": verification_value,
        "file_url": (
            f"https://{safe_domain}/.well-known/"
            f"webshield-verification.txt"
        ),
        "file_content": verification_value,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "expires_in_seconds": ttl_seconds,
    }


def validate_verification_token(
    token: str,
    expected_domain: str,
    secret: str,
    now: datetime | None = None,
):
    _validate_secret(secret)

    try:
        version, encoded_payload, encoded_signature = (
            token.split(".")
        )
    except ValueError as error:
        raise VerificationError(
            "The verification token is malformed."
        ) from error

    if version != TOKEN_VERSION:
        raise VerificationError(
            "The verification token version is unsupported."
        )

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()

    supplied_signature = _decode_base64(
        encoded_signature
    )

    if not hmac.compare_digest(
        expected_signature,
        supplied_signature,
    ):
        raise VerificationError(
            "The verification token signature is invalid."
        )

    try:
        payload = json.loads(
            _decode_base64(encoded_payload).decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise VerificationError(
            "The verification token payload is invalid."
        ) from error

    safe_domain = clean_domain(expected_domain)

    if payload.get("domain") != safe_domain:
        raise VerificationError(
            "This verification token belongs to "
            "a different domain."
        )

    try:
        expires_at = int(payload["expires_at"])
        issued_at = int(payload["issued_at"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise VerificationError(
            "The verification token is incomplete."
        ) from error

    current_time = _timestamp(now)

    if current_time > expires_at:
        raise VerificationError(
            "The verification challenge has expired."
        )

    if issued_at > current_time + 60:
        raise VerificationError(
            "The verification token has an invalid "
            "issue time."
        )

    return payload

def _read_txt_value(record) -> str:
    strings = getattr(record, "strings", None)

    if strings is not None:
        return b"".join(strings).decode(
            "utf-8",
            errors="replace",
        )

    value = record.to_text().strip()

    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]

    return value.replace('" "', "")


def verify_dns_proof(
    domain: str,
    token: str,
    secret: str,
    resolver=None,
    now: datetime | None = None,
):
    payload = validate_verification_token(
        token,
        domain,
        secret,
        now=now,
    )

    safe_domain = payload["domain"]
    record_name = (
        f"_webshield-verification.{safe_domain}"
    )
    expected_value = (
        f"{VERIFICATION_PREFIX}{token}"
    )

    try:
        active_resolver = resolver

        if active_resolver is None:
            active_resolver = dns.resolver.Resolver()
            active_resolver.timeout = 3
            active_resolver.lifetime = 5

        answers = active_resolver.resolve(
            record_name,
            "TXT",
        )

        observed_values = [
            _read_txt_value(answer)
            for answer in answers
        ]

        verified = expected_value in observed_values

        return {
            "domain": safe_domain,
            "method": "DNS TXT",
            "verified": verified,
            "status": (
                "Verified"
                if verified
                else "Not Verified"
            ),
            "message": (
                "The WebShield verification token was found "
                "in the domain's DNS records."
                if verified
                else
                "The required WebShield verification token "
                "was not found in the DNS record."
            ),
            "record_name": record_name,
            "expected_value": expected_value,
        }

    except dns.exception.DNSException as error:
        return {
            "domain": safe_domain,
            "method": "DNS TXT",
            "verified": False,
            "status": "Not Verified",
            "message": (
                "The WebShield DNS verification record "
                "could not be found or read."
            ),
            "record_name": record_name,
            "expected_value": expected_value,
            "error_type": type(error).__name__,
        }


def verify_http_file_proof(
    domain: str,
    token: str,
    secret: str,
    now: datetime | None = None,
):
    payload = validate_verification_token(
        token,
        domain,
        secret,
        now=now,
    )

    safe_domain = payload["domain"]
    verification_url = (
        f"https://{safe_domain}/.well-known/"
        f"webshield-verification.txt"
    )
    expected_value = (
        f"{VERIFICATION_PREFIX}{token}"
    )

    try:
        response = safe_get(
            verification_url,
            timeout=10,
            max_bytes=4096,
        )

        final_url = response.url
        final_location = urlparse(final_url)

        same_domain = (
            final_location.hostname is not None
            and final_location.hostname.lower()
            == safe_domain
        )

        secure_response = (
            final_location.scheme.lower() == "https"
        )

        exact_content = (
            response.text.strip() == expected_value
        )

        verified = (
            response.status_code == 200
            and same_domain
            and secure_response
            and exact_content
            and not getattr(
                response,
                "webshield_content_truncated",
                False,
            )
        )

        return {
            "domain": safe_domain,
            "method": "Verification File",
            "verified": verified,
            "status": (
                "Verified"
                if verified
                else "Not Verified"
            ),
            "message": (
                "The WebShield verification file was found "
                "and contained the correct token."
                if verified
                else
                "The verification file was missing, "
                "redirected outside the domain, or did not "
                "contain the exact expected token."
            ),
            "requested_url": verification_url,
            "final_url": final_url,
            "status_code": response.status_code,
        }

    except requests.RequestException as error:
        return {
            "domain": safe_domain,
            "method": "Verification File",
            "verified": False,
            "status": "Not Verified",
            "message": (
                "The WebShield verification file could not "
                "be found or downloaded."
            ),
            "requested_url": verification_url,
            "final_url": None,
            "status_code": None,
            "error_type": type(error).__name__,
        } 

def create_authorization_receipt(
    domain: str,
    verification_method: str,
    secret: str,
    now: datetime | None = None,
    ttl_seconds: int = 86400,
):
    _validate_secret(secret)

    if ttl_seconds < 300 or ttl_seconds > 604800:
        raise VerificationError(
            "Authorization receipts must last between "
            "five minutes and seven days."
        )

    safe_domain = clean_domain(domain)
    issued_at = _timestamp(now)
    expires_at = issued_at + ttl_seconds

    payload = {
        "purpose": "deep_scan_authorization",
        "domain": safe_domain,
        "scope": [safe_domain],
        "verification_method": verification_method,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": secrets.token_urlsafe(16),
    }

    payload_bytes = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    encoded_payload = _encode_base64(payload_bytes)

    signature = hmac.new(
        secret.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()

    receipt = (
        f"{AUTHORIZATION_VERSION}."
        f"{encoded_payload}."
        f"{_encode_base64(signature)}"
    )

    return {
        "domain": safe_domain,
        "receipt": receipt,
        "scope": [safe_domain],
        "verification_method": verification_method,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "expires_in_seconds": ttl_seconds,
    }


def validate_authorization_receipt(
    receipt: str,
    expected_domain: str,
    secret: str,
    now: datetime | None = None,
):
    _validate_secret(secret)

    try:
        version, encoded_payload, encoded_signature = (
            receipt.split(".")
        )
    except ValueError as error:
        raise VerificationError(
            "The authorization receipt is malformed."
        ) from error

    if version != AUTHORIZATION_VERSION:
        raise VerificationError(
            "The authorization receipt version "
            "is unsupported."
        )

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()

    supplied_signature = _decode_base64(
        encoded_signature
    )

    if not hmac.compare_digest(
        expected_signature,
        supplied_signature,
    ):
        raise VerificationError(
            "The authorization receipt signature "
            "is invalid."
        )

    try:
        payload = json.loads(
            _decode_base64(encoded_payload).decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise VerificationError(
            "The authorization receipt payload "
            "is invalid."
        ) from error

    if payload.get("purpose") != (
        "deep_scan_authorization"
    ):
        raise VerificationError(
            "The receipt does not authorize deep scanning."
        )

    safe_domain = clean_domain(expected_domain)

    if payload.get("domain") != safe_domain:
        raise VerificationError(
            "This authorization receipt belongs "
            "to a different domain."
        )

    scope = payload.get("scope")

    if scope != [safe_domain]:
        raise VerificationError(
            "The authorization receipt has an "
            "invalid scan scope."
        )

    try:
        issued_at = int(payload["issued_at"])
        expires_at = int(payload["expires_at"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise VerificationError(
            "The authorization receipt is incomplete."
        ) from error

    current_time = _timestamp(now)

    if current_time > expires_at:
        raise VerificationError(
            "The deep-scan authorization has expired."
        )

    if issued_at > current_time + 60:
        raise VerificationError(
            "The authorization receipt has an "
            "invalid issue time."
        )

    return payload           