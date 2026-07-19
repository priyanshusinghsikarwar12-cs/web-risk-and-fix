import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from threading import Lock
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken

from app.utils.domain import clean_domain


MIN_TTL_SECONDS = 300
MAX_TTL_SECONDS = 14400
_records = {}
_vault_lock = Lock()


class CredentialVaultError(ValueError):
    pass


def _timestamp(now=None):
    value = now or datetime.now(timezone.utc)
    return int(value.timestamp())


def _fernet(secret: str) -> Fernet:
    if not isinstance(secret, str) or len(secret) < 32:
        raise CredentialVaultError(
            "The credential-vault secret must contain at least 32 characters."
        )
    key = base64.urlsafe_b64encode(
        hashlib.sha256(secret.encode("utf-8")).digest()
    )
    return Fernet(key)


def _validate_engagement(payload: dict, now=None):
    if not isinstance(payload, dict) or payload.get("purpose") != "verified_engagement":
        raise CredentialVaultError(
            "A signed Engagement Profile is required for test credentials."
        )
    current_time = _timestamp(now)
    try:
        expires_at = int(payload["expires_at"])
        engagement_id = str(payload["engagement_id"])
        domain = clean_domain(payload["domain"])
    except (KeyError, TypeError, ValueError) as error:
        raise CredentialVaultError("The Engagement Profile is incomplete.") from error
    if current_time > expires_at:
        raise CredentialVaultError("The Engagement Profile has expired.")
    return engagement_id, domain, expires_at


def _validate_login_url(login_url: str, engagement_payload: dict) -> str:
    cleaned = str(login_url or "").strip()
    try:
        parsed = urlsplit(cleaned)
        hostname = clean_domain(parsed.hostname or "")
    except (TypeError, ValueError) as error:
        raise CredentialVaultError("The login URL is invalid.") from error

    if parsed.scheme.lower() != "https":
        raise CredentialVaultError("Test-account login must use HTTPS.")
    if parsed.username or parsed.password:
        raise CredentialVaultError("The login URL must not contain credentials.")
    if parsed.port not in (None, 443):
        raise CredentialVaultError("The login URL must use the standard HTTPS port.")

    scope = engagement_payload.get("scope", [])
    normalized_scope = {clean_domain(item) for item in scope}
    if hostname not in normalized_scope:
        raise CredentialVaultError(
            "The login URL is outside the signed engagement scope."
        )
    return cleaned


def _clean_credential(value, field_name, minimum, maximum):
    if not isinstance(value, str):
        raise CredentialVaultError(f"{field_name} must be text.")
    if "\x00" in value or not minimum <= len(value) <= maximum:
        raise CredentialVaultError(
            f"{field_name} must contain between {minimum} and {maximum} characters."
        )
    return value


def purge_expired_test_accounts(now=None) -> int:
    current_time = _timestamp(now)
    with _vault_lock:
        expired_ids = [
            credential_id
            for credential_id, record in _records.items()
            if current_time > record["expires_at"]
        ]
        for credential_id in expired_ids:
            del _records[credential_id]
    return len(expired_ids)


def store_test_account(
    engagement_payload: dict,
    login_url: str,
    username: str,
    password: str,
    secret: str,
    ttl_seconds: int = 3600,
    now=None,
) -> dict:
    engagement_id, domain, engagement_expires_at = _validate_engagement(
        engagement_payload, now
    )
    current_time = _timestamp(now)
    try:
        ttl_seconds = int(ttl_seconds)
    except (TypeError, ValueError) as error:
        raise CredentialVaultError("Credential lifetime must be a whole number.") from error
    if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise CredentialVaultError(
            "Test credentials must expire between 5 minutes and 4 hours."
        )

    safe_login_url = _validate_login_url(login_url, engagement_payload)
    safe_username = _clean_credential(username, "Username", 1, 254)
    safe_password = _clean_credential(password, "Password", 8, 512)
    expires_at = min(current_time + ttl_seconds, engagement_expires_at)
    if expires_at <= current_time:
        raise CredentialVaultError("The Engagement Profile expires too soon.")

    plaintext = json.dumps(
        {"username": safe_username, "password": safe_password},
        separators=(",", ":"),
    ).encode("utf-8")
    encrypted = _fernet(secret).encrypt(plaintext)
    credential_id = secrets.token_urlsafe(18)
    record = {
        "credential_id": credential_id,
        "engagement_id": engagement_id,
        "domain": domain,
        "login_url": safe_login_url,
        "created_at": current_time,
        "expires_at": expires_at,
        "encrypted_credentials": encrypted,
    }

    purge_expired_test_accounts(now)
    with _vault_lock:
        _records[credential_id] = record

    return {
        "credential_id": credential_id,
        "domain": domain,
        "login_url": safe_login_url,
        "created_at": current_time,
        "expires_at": expires_at,
        "status": "Stored Encrypted",
        "password_returned": False,
        "storage": "Volatile server memory",
    }


def open_test_account(
    credential_id: str,
    engagement_payload: dict,
    secret: str,
    now=None,
) -> dict:
    engagement_id, domain, _ = _validate_engagement(engagement_payload, now)
    purge_expired_test_accounts(now)
    with _vault_lock:
        record = _records.get(str(credential_id))
    if not record:
        raise CredentialVaultError("The test credential was not found or has expired.")
    if record["engagement_id"] != engagement_id or record["domain"] != domain:
        raise CredentialVaultError(
            "This test credential belongs to a different engagement."
        )

    try:
        decrypted = _fernet(secret).decrypt(record["encrypted_credentials"])
        credentials = json.loads(decrypted.decode("utf-8"))
    except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CredentialVaultError("The test credential could not be decrypted.") from error

    return {
        "credential_id": record["credential_id"],
        "domain": domain,
        "login_url": record["login_url"],
        "username": credentials["username"],
        "password": credentials["password"],
        "expires_at": record["expires_at"],
    }


def delete_test_account(
    credential_id: str,
    engagement_payload: dict,
    now=None,
) -> dict:
    engagement_id, domain, _ = _validate_engagement(engagement_payload, now)
    with _vault_lock:
        record = _records.get(str(credential_id))
        if not record:
            raise CredentialVaultError("The test credential was not found or has expired.")
        if record["engagement_id"] != engagement_id or record["domain"] != domain:
            raise CredentialVaultError(
                "This test credential belongs to a different engagement."
            )
        del _records[str(credential_id)]
    return {"credential_id": str(credential_id), "deleted": True}


def clear_test_vault():
    """Test helper. Production code should delete individual records."""
    with _vault_lock:
        _records.clear()
