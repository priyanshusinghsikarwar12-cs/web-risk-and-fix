import pytest

from app.scanners.dkim import (
    DKIMSelectorError,
    analyze_dkim_records,
    build_dkim_record_name,
    check_dkim,
    clean_selector,
)


VALID_KEY = "cHVibGljLWtleQ=="


def test_selector_is_required():
    result = check_dkim("example.com")

    assert result["status"] == "Selector Required"
    assert result["confidence"] == "Not Tested"


def test_valid_selector_is_cleaned():
    result = clean_selector("  Selector1  ")

    assert result == "selector1"


def test_invalid_selector_is_rejected():
    with pytest.raises(DKIMSelectorError):
        clean_selector("../invalid selector")


def test_builds_dkim_record_name():
    result = build_dkim_record_name(
        "example.com",
        "selector1",
    )

    assert result == (
        "selector1._domainkey.example.com"
    )


def test_valid_dkim_record_is_configured():
    result = analyze_dkim_records(
        [
            (
                "v=DKIM1; k=rsa; "
                f"p={VALID_KEY}"
            )
        ],
        "example.com",
        "selector1",
    )

    assert result["status"] == "Configured"
    assert result["public_key_present"] is True
    assert result["key_type"] == "rsa"
    assert result["confidence"] == "Medium"


def test_empty_public_key_is_revoked():
    result = analyze_dkim_records(
        ["v=DKIM1; p="],
        "example.com",
        "selector1",
    )

    assert result["status"] == "Revoked"
    assert result["public_key_present"] is False


def test_missing_public_key_is_invalid():
    result = analyze_dkim_records(
        ["v=DKIM1; k=rsa"],
        "example.com",
        "selector1",
    )

    assert result["status"] == "Invalid"
    assert result["error"] == "public_key_missing"


def test_invalid_base64_key_is_rejected():
    result = analyze_dkim_records(
        ["v=DKIM1; p=not!base64"],
        "example.com",
        "selector1",
    )

    assert result["status"] == "Invalid"
    assert result["error"] == "invalid_public_key"


def test_no_record_does_not_claim_dkim_is_missing():
    result = analyze_dkim_records(
        [],
        "example.com",
        "selector1",
        lookup_error="no_answer",
    )

    assert result["status"] == "Not Found"
    assert "different selector" in result["message"]


def test_multiple_records_are_invalid():
    result = analyze_dkim_records(
        [
            f"v=DKIM1; p={VALID_KEY}",
            f"v=DKIM1; p={VALID_KEY}",
        ],
        "example.com",
        "selector1",
    )

    assert result["status"] == "Invalid"
    assert result["error"] == "multiple_records"


def test_version_must_appear_first():
    result = analyze_dkim_records(
        [
            (
                f"k=rsa; v=DKIM1; "
                f"p={VALID_KEY}"
            )
        ],
        "example.com",
        "selector1",
    )

    assert result["status"] == "Invalid"
    assert result["error"] == "version_not_first"