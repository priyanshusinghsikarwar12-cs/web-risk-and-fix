from app.scanners.dns import (
    analyze_mx_records,
    find_policy,
)


def test_null_mx_means_email_disabled():
    result = analyze_mx_records(["0 ."])

    assert result["valid"] is True
    assert result["accepts_email"] is False
    assert result["type"] == "null_mx"


def test_normal_mx_means_mail_server_configured():
    result = analyze_mx_records(
        ["10 mail.example.com."]
    )

    assert result["valid"] is True
    assert result["accepts_email"] is True


def test_null_and_normal_mx_is_invalid():
    result = analyze_mx_records(
        [
            "0 .",
            "10 mail.example.com.",
        ]
    )

    assert result["valid"] is False
    assert result["type"] == "invalid_mixed_mx"


def test_spf_policy_is_found():
    values = [
        "google-site-verification=123",
        "v=spf1 include:example.com -all",
    ]

    result = find_policy(values, "v=spf1")

    assert result == "v=spf1 include:example.com -all"


def test_unrelated_txt_is_not_spf():
    values = [
        "google-site-verification=123",
    ]

    result = find_policy(values, "v=spf1")

    assert result is None 