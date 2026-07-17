from app.scanners.error_leakage import (
    analyze_error_response,
)


REQUESTED_URL = (
    "https://example.com/"
    ".well-known/webshield-missing-page-check"
)


def analyze(body="", headers=None, final_url=None):
    return analyze_error_response(
        status_code=404,
        headers=headers or {},
        body=body,
        requested_url=REQUESTED_URL,
        final_url=final_url or REQUESTED_URL,
        content_truncated=False,
    )


def test_python_stack_trace_needs_attention():
    result = analyze(
        "Traceback (most recent call last):"
    )

    assert result["status"] == "Needs Attention"
    assert result["checks"][0]["name"] == (
        "Python Stack Trace"
    )


def test_php_error_needs_attention():
    result = analyze(
        "Fatal error: failure in "
        "/var/www/app.php on line 42"
    )

    assert result["status"] == "Needs Attention"


def test_database_error_needs_attention():
    result = analyze(
        "SQLSTATE[HY000]: database connection failed"
    )

    assert result["status"] == "Needs Attention"


def test_detailed_server_version_requires_review():
    result = analyze(
        headers={
            "Server": "nginx/1.24.0",
        }
    )

    assert result["status"] == "Review"
    assert result["checks"][0]["name"] == (
        "Detailed Server Version"
    )


def test_powered_by_header_requires_review():
    result = analyze(
        headers={
            "X-Powered-By": "PHP/8.2",
        }
    )

    assert result["status"] == "Review"


def test_clean_error_page_is_not_observed():
    result = analyze(
        "Sorry, the requested page could not be found."
    )

    assert result["status"] == "Not Observed"
    assert result["checks"] == []


def test_redirected_error_page_is_inconclusive():
    result = analyze(
        body="Homepage",
        final_url="https://example.com/",
    )

    assert result["status"] == "Inconclusive"
    assert result["redirected"] is True


def test_truncated_error_page_requires_review():
    result = analyze_error_response(
        status_code=404,
        headers={},
        body="No obvious error",
        requested_url=REQUESTED_URL,
        final_url=REQUESTED_URL,
        content_truncated=True,
    )

    assert result["status"] == "Review"