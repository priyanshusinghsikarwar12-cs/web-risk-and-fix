import pytest

from app.services.development_access import (
    DevelopmentAccessError,
    read_allowed_domains,
    validate_development_admin_access,
)


ADMIN_TOKEN = (
    "development-admin-token-with-more-than-32-characters"
)


def development_environment():
    return {
        "WEBSHIELD_ENV": "development",
        "WEBSHIELD_DEV_ADMIN_TOKEN": ADMIN_TOKEN,
        "WEBSHIELD_DEV_SCAN_ALLOWLIST": (
            "example.com,test.example.org"
        ),
    }


def test_allowlist_parses_domains():
    result = read_allowed_domains(
        "example.com, test.example.org"
    )

    assert result == {
        "example.com",
        "test.example.org",
    }


def test_valid_local_admin_is_accepted():
    result = validate_development_admin_access(
        "example.com",
        ADMIN_TOKEN,
        "127.0.0.1",
        environment=development_environment(),
    )

    assert result["authorized"] is True
    assert result["domain"] == "example.com"
    assert result["development_bypass"] is True


def test_access_requires_development_mode():
    environment = development_environment()
    environment["WEBSHIELD_ENV"] = "production"

    with pytest.raises(
        DevelopmentAccessError
    ):
        validate_development_admin_access(
            "example.com",
            ADMIN_TOKEN,
            "127.0.0.1",
            environment=environment,
        )


def test_access_requires_local_request():
    with pytest.raises(
        DevelopmentAccessError
    ):
        validate_development_admin_access(
            "example.com",
            ADMIN_TOKEN,
            "203.0.113.10",
            environment=development_environment(),
        )


def test_wrong_token_is_rejected():
    with pytest.raises(
        DevelopmentAccessError
    ):
        validate_development_admin_access(
            "example.com",
            "incorrect-token",
            "127.0.0.1",
            environment=development_environment(),
        )


def test_unlisted_domain_is_rejected():
    with pytest.raises(
        DevelopmentAccessError
    ):
        validate_development_admin_access(
            "unlisted.example.net",
            ADMIN_TOKEN,
            "127.0.0.1",
            environment=development_environment(),
        )