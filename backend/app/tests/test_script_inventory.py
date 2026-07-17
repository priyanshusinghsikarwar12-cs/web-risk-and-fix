from app.scanners.script_inventory import (
    analyze_script_inventory,
    classify_script_host,
)


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