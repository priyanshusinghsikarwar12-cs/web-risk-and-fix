from datetime import datetime, timedelta, timezone

import pytest

from app.services.domain_verification import (
    VerificationError,
    create_authorization_receipt,
    create_verification_challenge,
    validate_authorization_receipt,
    validate_verification_token,
    verify_dns_proof,
    verify_http_file_proof,
)

SECRET = "test-secret-that-is-longer-than-32-characters"
NOW = datetime(
    2026,
    7,
    17,
    12,
    0,
    tzinfo=timezone.utc,
)


def test_creates_domain_bound_challenge():
    challenge = create_verification_challenge(
        "https://Example.com/",
        SECRET,
        now=NOW,
    )

    assert challenge["domain"] == "example.com"
    assert challenge["dns_record_name"] == (
        "_webshield-verification.example.com"
    )
    assert challenge["file_url"] == (
        "https://example.com/.well-known/"
        "webshield-verification.txt"
    )


def test_valid_token_is_accepted():
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    payload = validate_verification_token(
        challenge["token"],
        "example.com",
        SECRET,
        now=NOW + timedelta(minutes=5),
    )

    assert payload["domain"] == "example.com"


def test_modified_token_is_rejected():
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    version, payload, signature = (
        challenge["token"].split(".")
    )

    replacement = (
        "A" if payload[-1] != "A" else "B"
    )

    modified_payload = (
        payload[:-1] + replacement
    )

    modified_token = (
        f"{version}.{modified_payload}.{signature}"
    )

    with pytest.raises(
        VerificationError,
        match="signature",
    ):
        validate_verification_token(
            modified_token,
            "example.com",
            SECRET,
            now=NOW,
        )

def test_token_cannot_verify_different_domain():
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    with pytest.raises(
        VerificationError,
        match="different domain",
    ):
        validate_verification_token(
            challenge["token"],
            "example.org",
            SECRET,
            now=NOW,
        )


def test_expired_token_is_rejected():
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
        ttl_seconds=60,
    )

    with pytest.raises(
        VerificationError,
        match="expired",
    ):
        validate_verification_token(
            challenge["token"],
            "example.com",
            SECRET,
            now=NOW + timedelta(seconds=61),
        )


def test_short_secret_is_rejected():
    with pytest.raises(
        VerificationError,
        match="at least 32",
    ):
        create_verification_challenge(
            "example.com",
            "too-short",
            now=NOW,
        )


def test_invalid_challenge_lifetime_is_rejected():
    with pytest.raises(
        VerificationError,
        match="between",
    ):
        create_verification_challenge(
            "example.com",
            SECRET,
            now=NOW,
            ttl_seconds=10,
        )

class FakeTxtRecord:
    def __init__(self, value):
        self.strings = [value.encode("utf-8")]


class FakeResolver:
    def __init__(self, values):
        self.values = values

    def resolve(self, record_name, record_type):
        assert record_name == (
            "_webshield-verification.example.com"
        )
        assert record_type == "TXT"

        return [
            FakeTxtRecord(value)
            for value in self.values
        ]


class FakeResponse:
    def __init__(
        self,
        url,
        text,
        status_code=200,
        truncated=False,
    ):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.webshield_content_truncated = truncated


def test_dns_proof_verifies_correct_value():
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    resolver = FakeResolver([
        challenge["dns_record_value"],
    ])

    result = verify_dns_proof(
        "example.com",
        challenge["token"],
        SECRET,
        resolver=resolver,
        now=NOW,
    )

    assert result["verified"] is True
    assert result["status"] == "Verified"


def test_dns_proof_rejects_wrong_value():
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    resolver = FakeResolver([
        "webshield-verification=wrong-token",
    ])

    result = verify_dns_proof(
        "example.com",
        challenge["token"],
        SECRET,
        resolver=resolver,
        now=NOW,
    )

    assert result["verified"] is False


def test_http_file_verifies_exact_value(
    monkeypatch,
):
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    monkeypatch.setattr(
        "app.services.domain_verification.safe_get",
        lambda url, timeout, max_bytes: FakeResponse(
            url,
            challenge["file_content"],
        ),
    )

    result = verify_http_file_proof(
        "example.com",
        challenge["token"],
        SECRET,
        now=NOW,
    )

    assert result["verified"] is True
    assert result["status"] == "Verified"


def test_http_file_rejects_wrong_content(
    monkeypatch,
):
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    monkeypatch.setattr(
        "app.services.domain_verification.safe_get",
        lambda url, timeout, max_bytes: FakeResponse(
            url,
            "incorrect-token",
        ),
    )

    result = verify_http_file_proof(
        "example.com",
        challenge["token"],
        SECRET,
        now=NOW,
    )

    assert result["verified"] is False


def test_http_file_rejects_external_redirect(
    monkeypatch,
):
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    monkeypatch.setattr(
        "app.services.domain_verification.safe_get",
        lambda url, timeout, max_bytes: FakeResponse(
            "https://attacker.example.net/"
            "webshield-verification.txt",
            challenge["file_content"],
        ),
    )

    result = verify_http_file_proof(
        "example.com",
        challenge["token"],
        SECRET,
        now=NOW,
    )

    assert result["verified"] is False


def test_http_file_rejects_truncated_content(
    monkeypatch,
):
    challenge = create_verification_challenge(
        "example.com",
        SECRET,
        now=NOW,
    )

    monkeypatch.setattr(
        "app.services.domain_verification.safe_get",
        lambda url, timeout, max_bytes: FakeResponse(
            url,
            challenge["file_content"],
            truncated=True,
        ),
    )

    result = verify_http_file_proof(
        "example.com",
        challenge["token"],
        SECRET,
        now=NOW,
    )

    assert result["verified"] is False        

def test_authorization_receipt_is_valid():
    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        SECRET,
        now=NOW,
    )

    payload = validate_authorization_receipt(
        authorization["receipt"],
        "example.com",
        SECRET,
        now=NOW + timedelta(hours=1),
    )

    assert payload["domain"] == "example.com"
    assert payload["scope"] == ["example.com"]
    assert payload["purpose"] == (
        "deep_scan_authorization"
    )


def test_authorization_rejects_other_domain():
    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        SECRET,
        now=NOW,
    )

    with pytest.raises(
        VerificationError,
        match="different domain",
    ):
        validate_authorization_receipt(
            authorization["receipt"],
            "example.org",
            SECRET,
            now=NOW,
        )


def test_expired_authorization_is_rejected():
    authorization = create_authorization_receipt(
        "example.com",
        "Verification File",
        SECRET,
        now=NOW,
        ttl_seconds=300,
    )

    with pytest.raises(
        VerificationError,
        match="expired",
    ):
        validate_authorization_receipt(
            authorization["receipt"],
            "example.com",
            SECRET,
            now=NOW + timedelta(seconds=301),
        )


def test_modified_authorization_is_rejected():
    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        SECRET,
        now=NOW,
    )

    version, payload, signature = (
        authorization["receipt"].split(".")
    )

    replacement = (
        "A" if payload[-1] != "A" else "B"
    )

    modified_receipt = (
        f"{version}.{payload[:-1]}"
        f"{replacement}.{signature}"
    )

    with pytest.raises(
        VerificationError,
        match="signature",
    ):
        validate_authorization_receipt(
            modified_receipt,
            "example.com",
            SECRET,
            now=NOW,
        )    