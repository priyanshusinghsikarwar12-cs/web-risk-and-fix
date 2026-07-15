import pytest

from app.utils.domain import (
    DomainValidationError,
    clean_domain,
    ensure_public_addresses,
)


def test_normal_domain_is_cleaned():
    assert clean_domain(
        "https://Example.com/"
    ) == "example.com"


def test_localhost_is_rejected():
    with pytest.raises(DomainValidationError):
        clean_domain("localhost")


def test_private_ip_is_rejected():
    with pytest.raises(DomainValidationError):
        clean_domain("192.168.1.1")


def test_credentials_are_rejected():
    with pytest.raises(DomainValidationError):
        clean_domain(
            "https://user:password@example.com"
        )


def test_private_resolved_address_is_rejected():
    with pytest.raises(DomainValidationError):
        ensure_public_addresses(["127.0.0.1"])


def test_public_resolved_address_is_allowed():
    ensure_public_addresses(["93.184.216.34"])