from app.deep_scanners.page_security import (
    analyze_page_security,
    summarize_page_security,
)


PROTECTED_HEADERS = {
    "Content-Type": "text/html",
    "Strict-Transport-Security": (
        "max-age=31536000; includeSubDomains"
    ),
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": (
        "strict-origin-when-cross-origin"
    ),
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=()"
    ),
}


class FakeResponse:
    def __init__(
        self,
        url="https://example.com/",
        text="<html></html>",
        headers=None,
        truncated=False,
    ):
        self.url = url
        self.text = text
        self.headers = headers or {}
        self.webshield_content_truncated = truncated
        self.raw = None


def test_protected_page_is_protected():
    response = FakeResponse(
        headers=PROTECTED_HEADERS,
    )

    result = analyze_page_security(response)

    assert result["status"] == "Protected"


def test_missing_headers_need_attention():
    response = FakeResponse(
        headers={"Content-Type": "text/html"},
    )

    result = analyze_page_security(response)

    assert result["status"] == "Needs Attention"


def test_insecure_cookie_is_detected():
    headers = {
        **PROTECTED_HEADERS,
        "Set-Cookie": (
            "session=test; Path=/; SameSite=Lax"
        ),
    }

    result = analyze_page_security(
        FakeResponse(headers=headers)
    )

    assert any(
        check["status"] == "Needs Attention"
        for check in result["cookie_checks"]
    )


def test_mixed_content_is_detected():
    response = FakeResponse(
        headers=PROTECTED_HEADERS,
        text=(
            '<script src="http://example.com/app.js">'
            "</script>"
        ),
    )

    result = analyze_page_security(response)

    assert result["mixed_content"]["status"] == (
        "Needs Attention"
    )


def test_summary_counts_affected_pages():
    protected_page = analyze_page_security(
        FakeResponse(
            url="https://example.com/",
            headers=PROTECTED_HEADERS,
        )
    )

    weak_page = analyze_page_security(
        FakeResponse(
            url="https://example.com/login",
            headers={"Content-Type": "text/html"},
        )
    )

    result = summarize_page_security([
        protected_page,
        weak_page,
    ])

    assert result["pages_analyzed"] == 2
    assert result["status"] == "Needs Attention"

    assert any(
        item["attention_pages"] == 1
        for item in result["header_coverage"]
    )


def test_no_cookie_is_not_a_cookie_failure():
    page = analyze_page_security(
        FakeResponse(
            headers=PROTECTED_HEADERS,
        )
    )

    result = summarize_page_security([page])

    assert result["cookie_finding_count"] == 0


def test_no_pages_are_not_applicable():
    result = summarize_page_security([])

    assert result["status"] == "Not Applicable"