from app.scanners.cookies import (
    analyze_set_cookie_headers,
)


def test_secure_cookie_is_protected():
    checks = analyze_set_cookie_headers([
        (
            "session=secret; Secure; HttpOnly; "
            "SameSite=Lax; Path=/"
        )
    ])

    assert len(checks) == 1
    assert checks[0]["status"] == "Protected"
    assert checks[0]["flags"]["secure"] is True
    assert checks[0]["flags"]["http_only"] is True
    assert checks[0]["flags"]["same_site"] == "Lax"


def test_cookie_without_secure_needs_attention():
    checks = analyze_set_cookie_headers([
        "session=secret; HttpOnly; SameSite=Lax"
    ])

    assert checks[0]["status"] == "Needs Attention"
    assert checks[0]["flags"]["secure"] is False


def test_cookie_without_http_only_requires_review():
    checks = analyze_set_cookie_headers([
        "preferences=dark; Secure; SameSite=Lax"
    ])

    assert checks[0]["status"] == "Review"
    assert checks[0]["flags"]["http_only"] is False


def test_same_site_none_requires_secure():
    checks = analyze_set_cookie_headers([
        "session=secret; HttpOnly; SameSite=None"
    ])

    assert checks[0]["status"] == "Needs Attention"
    assert any(
        "SameSite=None requires"
        in warning
        for warning in checks[0]["warnings"]
    )


def test_invalid_host_prefix_needs_attention():
    checks = analyze_set_cookie_headers([
        (
            "__Host-session=secret; Secure; HttpOnly; "
            "SameSite=Lax; Domain=example.com; Path=/account"
        )
    ])

    assert checks[0]["status"] == "Needs Attention"
    assert len(checks[0]["warnings"]) >= 2


def test_cookie_values_are_not_stored():
    checks = analyze_set_cookie_headers([
        (
            "session=very-sensitive-value; Secure; "
            "HttpOnly; SameSite=Strict"
        )
    ])

    assert "very-sensitive-value" not in str(checks)