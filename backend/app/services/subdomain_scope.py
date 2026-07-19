import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from app.utils.domain import (
    DomainValidationError,
    clean_domain,
)


DEFAULT_MAX_SELECTED_HOSTS = 10
SCOPED_AUTHORIZATION_VERSION = "wss1"


class SubdomainScopeError(ValueError):
    pass


def is_child_subdomain(
    hostname: str,
    parent_domain: str,
) -> bool:
    safe_hostname = clean_domain(hostname)
    safe_parent = clean_domain(parent_domain)

    return (
        safe_hostname != safe_parent
        and safe_hostname.endswith(
            f".{safe_parent}"
        )
    )


def _build_discovery_map(
    parent_domain: str,
    discovery_checks: list,
) -> dict:
    discovery_map = {}

    for check in discovery_checks:
        if not isinstance(check, dict):
            continue

        hostname = check.get(
            "hostname",
            check.get("name", ""),
        )

        try:
            safe_hostname = clean_domain(
                str(hostname)
            )
        except DomainValidationError:
            continue

        if not is_child_subdomain(
            safe_hostname,
            parent_domain,
        ):
            continue

        discovery_map[safe_hostname] = check

    return discovery_map


def build_authorized_subdomain_scope(
    parent_domain: str,
    selected_domains: list,
    discovery_checks: list,
    authority_attested: bool,
    max_selected_hosts: int = (
        DEFAULT_MAX_SELECTED_HOSTS
    ),
) -> dict:
    safe_parent = clean_domain(parent_domain)

    if authority_attested is not True:
        raise SubdomainScopeError(
            "You must confirm that you are authorized "
            "to assess every selected subdomain."
        )

    if not isinstance(selected_domains, list):
        raise SubdomainScopeError(
            "Selected subdomains must be provided "
            "as a list."
        )

    if not selected_domains:
        raise SubdomainScopeError(
            "Select at least one subdomain."
        )

    if not 1 <= max_selected_hosts <= 25:
        raise SubdomainScopeError(
            "The selected-host limit must be between "
            "1 and 25."
        )

    normalized_selection = set()

    for hostname in selected_domains:
        try:
            safe_hostname = clean_domain(
                str(hostname)
            )
        except DomainValidationError as error:
            raise SubdomainScopeError(
                "A selected subdomain is invalid."
            ) from error

        if not is_child_subdomain(
            safe_hostname,
            safe_parent,
        ):
            raise SubdomainScopeError(
                f"{safe_hostname} is not a subdomain "
                f"of {safe_parent}."
            )

        normalized_selection.add(
            safe_hostname
        )

    if (
        len(normalized_selection)
        > max_selected_hosts
    ):
        raise SubdomainScopeError(
            "Too many subdomains were selected. "
            f"The current limit is {max_selected_hosts}."
        )

    discovery_map = _build_discovery_map(
        safe_parent,
        discovery_checks,
    )

    approved_hosts = []

    for hostname in sorted(
        normalized_selection
    ):
        discovery = discovery_map.get(hostname)

        if discovery is None:
            raise SubdomainScopeError(
                f"{hostname} was not present in the "
                "validated discovery results."
            )

        if discovery.get("status") != (
            "DNS Confirmed"
        ):
            raise SubdomainScopeError(
                f"{hostname} is historical or inactive. "
                "Its DNS is not currently confirmed."
            )

        if discovery.get("wildcard_match"):
            raise SubdomainScopeError(
                f"{hostname} matches wildcard DNS and "
                "cannot be automatically approved."
            )

        if not discovery.get("dns_records"):
            raise SubdomainScopeError(
                f"{hostname} has no confirmed DNS "
                "records."
            )

        approved_hosts.append(hostname)

    return {
        "name": "Authorized Subdomain Scope",
        "parent_domain": safe_parent,
        "selected_hosts": approved_hosts,
        "selected_count": len(
            approved_hosts
        ),
        "scope": [
            safe_parent,
            *approved_hosts,
        ],
        "authority_attested": True,
        "status": "Scope Validated",
        "message": (
            f"{len(approved_hosts)} active subdomain(s) "
            "passed WebShield's scope validation."
        ),
        "important_note": (
            "Scope validation records the user's "
            "authorization statement. It does not prove "
            "ownership of third-party infrastructure "
            "behind a CDN or hosted service."
        ),
        "constraints": {
            "dns_confirmation_required": True,
            "wildcard_matches_allowed": False,
            "historical_names_allowed": False,
            "maximum_selected_hosts": (
                max_selected_hosts
            ),
            "scanning_started": False,
        },
    }

def _encode_receipt_value(
    value: bytes,
) -> str:
    return (
        base64.urlsafe_b64encode(value)
        .decode("ascii")
        .rstrip("=")
    )


def _decode_receipt_value(
    value: str,
) -> bytes:
    padding = "=" * (-len(value) % 4)

    try:
        decoded = base64.urlsafe_b64decode(
            value + padding
        )
    except Exception as error:
        raise SubdomainScopeError(
            "The scoped authorization receipt "
            "is malformed."
        ) from error

    if _encode_receipt_value(decoded) != value:
        raise SubdomainScopeError(
            "The scoped authorization receipt uses "
            "invalid encoding."
        )

    return decoded


def _scope_timestamp(
    value: datetime | None = None,
) -> int:
    active_time = value or datetime.now(
        timezone.utc
    )

    if active_time.tzinfo is None:
        active_time = active_time.replace(
            tzinfo=timezone.utc
        )

    return int(active_time.timestamp())


def _validate_scope_secret(secret: str):
    if (
        not isinstance(secret, str)
        or len(secret) < 32
    ):
        raise SubdomainScopeError(
            "The authorization secret must contain "
            "at least 32 characters."
        )


def _validate_scope_structure(
    parent_domain: str,
    scope: list,
) -> list:
    safe_parent = clean_domain(parent_domain)

    if not isinstance(scope, list):
        raise SubdomainScopeError(
            "The authorization scope must be a list."
        )

    if not 2 <= len(scope) <= 26:
        raise SubdomainScopeError(
            "The authorization scope must contain the "
            "parent and between 1 and 25 subdomains."
        )

    try:
        normalized_scope = [
            clean_domain(str(hostname))
            for hostname in scope
        ]
    except DomainValidationError as error:
        raise SubdomainScopeError(
            "The authorization scope contains an "
            "invalid hostname."
        ) from error

    selected_hosts = normalized_scope[1:]

    expected_scope = [
        safe_parent,
        *sorted(set(selected_hosts)),
    ]

    if normalized_scope != expected_scope:
        raise SubdomainScopeError(
            "The authorization scope is not normalized "
            "or contains duplicate hostnames."
        )

    for hostname in selected_hosts:
        if not is_child_subdomain(
            hostname,
            safe_parent,
        ):
            raise SubdomainScopeError(
                f"{hostname} is outside the verified "
                "parent domain."
            )

    return expected_scope


def create_scoped_authorization_receipt(
    validated_scope: dict,
    verification_method: str,
    secret: str,
    now: datetime | None = None,
    ttl_seconds: int = 86400,
) -> dict:
    _validate_scope_secret(secret)

    if not 300 <= ttl_seconds <= 604800:
        raise SubdomainScopeError(
            "Scoped authorization must last between "
            "five minutes and seven days."
        )

    if (
        not isinstance(validated_scope, dict)
        or validated_scope.get("status")
        != "Scope Validated"
        or validated_scope.get(
            "authority_attested"
        )
        is not True
    ):
        raise SubdomainScopeError(
            "A validated and authorized subdomain "
            "scope is required."
        )

    safe_parent = clean_domain(
        validated_scope.get(
            "parent_domain",
            "",
        )
    )

    safe_scope = _validate_scope_structure(
        safe_parent,
        validated_scope.get("scope"),
    )

    clean_method = str(
        verification_method
    ).strip()

    if not clean_method:
        raise SubdomainScopeError(
            "The verification method is required."
        )

    issued_at = _scope_timestamp(now)
    expires_at = issued_at + ttl_seconds

    payload = {
        "purpose": (
            "subdomain_deep_scan_authorization"
        ),
        "parent_domain": safe_parent,
        "scope": safe_scope,
        "verification_method": clean_method,
        "authority_attested": True,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": secrets.token_urlsafe(16),
    }

    payload_bytes = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    encoded_payload = _encode_receipt_value(
        payload_bytes
    )

    signature = hmac.new(
        secret.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()

    receipt = (
        f"{SCOPED_AUTHORIZATION_VERSION}."
        f"{encoded_payload}."
        f"{_encode_receipt_value(signature)}"
    )

    return {
        "receipt": receipt,
        "parent_domain": safe_parent,
        "scope": safe_scope,
        "selected_hosts": safe_scope[1:],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "expires_in_seconds": ttl_seconds,
    }


def validate_scoped_authorization_receipt(
    receipt: str,
    expected_target: str,
    secret: str,
    now: datetime | None = None,
) -> dict:
    _validate_scope_secret(secret)

    try:
        version, encoded_payload, encoded_signature = (
            receipt.split(".")
        )
    except ValueError as error:
        raise SubdomainScopeError(
            "The scoped authorization receipt "
            "is malformed."
        ) from error

    if version != SCOPED_AUTHORIZATION_VERSION:
        raise SubdomainScopeError(
            "The scoped authorization receipt "
            "version is unsupported."
        )

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()

    supplied_signature = _decode_receipt_value(
        encoded_signature
    )

    if not hmac.compare_digest(
        expected_signature,
        supplied_signature,
    ):
        raise SubdomainScopeError(
            "The scoped authorization receipt "
            "signature is invalid."
        )

    try:
        payload = json.loads(
            _decode_receipt_value(
                encoded_payload
            ).decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise SubdomainScopeError(
            "The scoped authorization payload "
            "is invalid."
        ) from error

    if payload.get("purpose") != (
        "subdomain_deep_scan_authorization"
    ):
        raise SubdomainScopeError(
            "This receipt does not authorize "
            "subdomain deep scanning."
        )

    safe_parent = clean_domain(
        payload.get("parent_domain", "")
    )

    safe_scope = _validate_scope_structure(
        safe_parent,
        payload.get("scope"),
    )

    safe_target = clean_domain(
        expected_target
    )

    if safe_target not in safe_scope:
        raise SubdomainScopeError(
            "This hostname is not included in the "
            "authorized subdomain scope."
        )

    if payload.get("authority_attested") is not True:
        raise SubdomainScopeError(
            "The authorization statement is missing."
        )

    try:
        issued_at = int(payload["issued_at"])
        expires_at = int(payload["expires_at"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise SubdomainScopeError(
            "The scoped authorization receipt "
            "is incomplete."
        ) from error

    current_time = _scope_timestamp(now)

    if current_time > expires_at:
        raise SubdomainScopeError(
            "The scoped authorization has expired."
        )

    if issued_at > current_time + 60:
        raise SubdomainScopeError(
            "The scoped authorization has an "
            "invalid issue time."
        )

    return {
        **payload,
        "scope": safe_scope,
        "authorized_target": safe_target,
    }
