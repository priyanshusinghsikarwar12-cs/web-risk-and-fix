from app.scanners.headers import (
    validate_content_type_options,
    validate_csp,
    validate_hsts,
    validate_click_protection,
)


def test_missing_hsts_needs_attention():
    result = validate_hsts({})

    assert result["status"] == "Needs Attention"
    assert result["present"] is False


def test_weak_hsts_needs_attention():
    headers = {
        "Strict-Transport-Security": "max-age=100"
    }

    result = validate_hsts(headers)

    assert result["status"] == "Needs Attention"


def test_strong_hsts_is_protected():
    headers = {
        "Strict-Transport-Security": (
            "max-age=31536000; includeSubDomains"
        )
    }

    result = validate_hsts(headers)

    assert result["status"] == "Protected"


def test_nosniff_is_protected():
    headers = {
        "X-Content-Type-Options": "nosniff"
    }

    result = validate_content_type_options(headers)

    assert result["status"] == "Protected"


def test_invalid_frame_option_needs_attention():
    headers = {
        "X-Frame-Options": "ALLOW-ALL"
    }

    result = validate_click_protection(headers)

    assert result["status"] == "Needs Attention"


def test_csp_report_only_is_not_protected():
    headers = {
        "Content-Security-Policy-Report-Only": (
            "default-src 'self'"
        )
    }

    result = validate_csp(headers)

    assert result["status"] == "Needs Attention"