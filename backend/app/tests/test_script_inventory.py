import requests

from app.scanners.script_inventory import (
    analyze_script_inventory,
    check_script_inventory,
    classify_script_host,
)

class FakeHtmlResponse:
    url = "https://example.com/"
    status_code = 200
    headers = {
        "Content-Type": "text/html",
    }
    text = """
    <script
      src="/js/jquery.min.js?ver=3.7.1">
    </script>
    """
    webshield_content_truncated = False


def test_success_result_contains_library_count():
    result = check_script_inventory(
        "example.com",
        response=FakeHtmlResponse(),
    )

    assert result["detected_library_count"] == 1


def test_non_html_result_has_zero_library_count():
    response = FakeHtmlResponse()
    response.headers = {
        "Content-Type": "application/json",
    }

    result = check_script_inventory(
        "example.com",
        response=response,
    )

    assert result["detected_library_count"] == 0


def test_failed_inventory_has_zero_library_count(
    monkeypatch,
):
    def failed_request(url, timeout):
        raise requests.ConnectionError(
            "Connection failed"
        )

    monkeypatch.setattr(
        "app.scanners.script_inventory.safe_get",
        failed_request,
    )

    result = check_script_inventory("example.com")

    assert result["status"] == "Unavailable"
    assert result["detected_library_count"] == 0


def test_same_host_classification():
    result = classify_script_host(
        "example.com",
        "example.com",
    )

    assert result == "Same Host"


def test_related_subdomain_classification():
    result = classify_script_host(
        "example.com",
        "cdn.example.com",
    )

    assert result == "Related Host"


def test_external_host_classification():
    result = classify_script_host(
        "example.com",
        "analytics.example.org",
    )

    assert result == "External Host"


def test_external_script_is_observed():
    html = """
    <script src="https://analytics.example.org/app.js">
    </script>
    """

    result = analyze_script_inventory(
        html,
        "https://example.com/",
    )

    assert result["status"] == "Observed"
    assert result["external_script_count"] == 1
    assert result["insecure_script_count"] == 0


def test_insecure_script_needs_attention():
    html = """
    <script src="http://cdn.example.com/app.js">
    </script>
    """

    result = analyze_script_inventory(
        html,
        "https://example.com/",
    )

    assert result["status"] == "Needs Attention"
    assert result["insecure_script_count"] == 1


def test_inline_and_duplicate_scripts_are_counted_safely():
    html = """
    <script>console.log("inline")</script>
    <script src="/app.js"></script>
    <script src="/app.js"></script>
    """

    result = analyze_script_inventory(
        html,
        "https://example.com/",
    )

    assert result["inline_script_count"] == 1
    assert result["total_script_files"] == 1


def test_truncated_inventory_requires_review():
    html = """
    <script src="https://example.com/app.js"></script>
    """

    result = analyze_script_inventory(
        html,
        "https://example.com/",
        content_truncated=True,
    )

    assert result["status"] == "Review"