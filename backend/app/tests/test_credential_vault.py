from datetime import datetime, timedelta, timezone

import pytest

from app.services.credential_vault import (
    CredentialVaultError,
    clear_test_vault,
    delete_test_account,
    open_test_account,
    purge_expired_test_accounts,
    store_test_account,
)


SECRET = "credential-vault-test-secret-that-is-long-enough"
NOW = datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc)


def engagement(**overrides):
    payload = {
        "purpose": "verified_engagement",
        "engagement_id": "engagement-one",
        "domain": "example.com",
        "scope": ["example.com"],
        "expires_at": int((NOW + timedelta(hours=2)).timestamp()),
    }
    payload.update(overrides)
    return payload


@pytest.fixture(autouse=True)
def empty_vault():
    clear_test_vault()
    yield
    clear_test_vault()


def test_credentials_are_encrypted_and_not_returned():
    result = store_test_account(
        engagement(),
        "https://example.com/login",
        "test-user@example.com",
        "very-secret-password",
        SECRET,
        now=NOW,
    )

    assert result["status"] == "Stored Encrypted"
    assert result["password_returned"] is False
    assert "password" not in result
    assert "username" not in result

    opened = open_test_account(
        result["credential_id"], engagement(), SECRET, now=NOW
    )
    assert opened["username"] == "test-user@example.com"
    assert opened["password"] == "very-secret-password"


def test_wrong_encryption_secret_cannot_open_credentials():
    result = store_test_account(
        engagement(),
        "https://example.com/login",
        "tester",
        "very-secret-password",
        SECRET,
        now=NOW,
    )

    with pytest.raises(CredentialVaultError, match="decrypt"):
        open_test_account(
            result["credential_id"],
            engagement(),
            "different-secret-that-is-also-long-enough",
            now=NOW,
        )


def test_credentials_cannot_cross_engagements():
    result = store_test_account(
        engagement(),
        "https://example.com/login",
        "tester",
        "very-secret-password",
        SECRET,
        now=NOW,
    )

    with pytest.raises(CredentialVaultError, match="different engagement"):
        open_test_account(
            result["credential_id"],
            engagement(engagement_id="engagement-two"),
            SECRET,
            now=NOW,
        )


def test_login_url_must_use_https():
    with pytest.raises(CredentialVaultError, match="HTTPS"):
        store_test_account(
            engagement(),
            "http://example.com/login",
            "tester",
            "very-secret-password",
            SECRET,
            now=NOW,
        )


def test_login_url_must_be_inside_signed_scope():
    with pytest.raises(CredentialVaultError, match="outside"):
        store_test_account(
            engagement(),
            "https://accounts.example.com/login",
            "tester",
            "very-secret-password",
            SECRET,
            now=NOW,
        )


def test_expired_credentials_are_purged():
    result = store_test_account(
        engagement(),
        "https://example.com/login",
        "tester",
        "very-secret-password",
        SECRET,
        ttl_seconds=300,
        now=NOW,
    )

    assert purge_expired_test_accounts(NOW + timedelta(minutes=6)) == 1
    with pytest.raises(CredentialVaultError, match="not found"):
        open_test_account(
            result["credential_id"],
            engagement(),
            SECRET,
            now=NOW + timedelta(minutes=6),
        )


def test_credentials_can_be_deleted_immediately():
    result = store_test_account(
        engagement(),
        "https://example.com/login",
        "tester",
        "very-secret-password",
        SECRET,
        now=NOW,
    )

    deleted = delete_test_account(
        result["credential_id"], engagement(), now=NOW
    )
    assert deleted["deleted"] is True
    with pytest.raises(CredentialVaultError, match="not found"):
        open_test_account(
            result["credential_id"], engagement(), SECRET, now=NOW
        )


def test_vault_rejects_short_passwords():
    with pytest.raises(CredentialVaultError, match="Password"):
        store_test_account(
            engagement(),
            "https://example.com/login",
            "tester",
            "short",
            SECRET,
            now=NOW,
        )


def test_vault_rejects_excessive_lifetime():
    with pytest.raises(CredentialVaultError, match="4 hours"):
        store_test_account(
            engagement(),
            "https://example.com/login",
            "tester",
            "very-secret-password",
            SECRET,
            ttl_seconds=14401,
            now=NOW,
        )


def test_vault_requires_engagement_profile():
    with pytest.raises(CredentialVaultError, match="Engagement Profile"):
        store_test_account(
            {"domain": "example.com"},
            "https://example.com/login",
            "tester",
            "very-secret-password",
            SECRET,
            now=NOW,
        )
