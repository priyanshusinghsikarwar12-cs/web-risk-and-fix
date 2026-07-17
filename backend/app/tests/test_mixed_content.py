from app.scanners.mixed_content import (
    analyze_mixed_content,
)


def test_detects_insecure_script():
    html = """
    <html>
      <script src="http://example.org/app.js"></script>
    </html>
    """

    result = analyze_mixed_content(html)

    assert result["status"] == "Needs Attention"
    assert result["total_found"] == 1
    assert result["checks"][0]["tag"] == "script"


def test_secure_resources_are_not_reported():
    html = """
    <html>
      <script src="https://example.org/app.js"></script>
      <img src="/images/logo.png">
      <img src="//example.org/image.png">
    </html>
    """

    result = analyze_mixed_content(html)

    assert result["status"] == "Protected"
    assert result["total_found"] == 0


def test_detects_insecure_srcset_resource():
    html = """
    <img
      srcset="
        https://example.org/small.png 1x,
        http://example.org/large.png 2x
      "
    >
    """

    result = analyze_mixed_content(html)

    assert result["total_found"] == 1
    assert result["checks"][0]["attribute"] == "srcset"


def test_canonical_link_is_not_mixed_content():
    html = """
    <link
      rel="canonical"
      href="http://example.org/page"
    >
    """

    result = analyze_mixed_content(html)

    assert result["status"] == "Protected"
    assert result["total_found"] == 0


def test_insecure_stylesheet_is_detected():
    html = """
    <link
      rel="stylesheet"
      href="http://example.org/style.css"
    >
    """

    result = analyze_mixed_content(html)

    assert result["status"] == "Needs Attention"
    assert result["total_found"] == 1


def test_duplicate_resources_are_reported_once():
    html = """
    <script src="http://example.org/app.js"></script>
    <script src="http://example.org/app.js"></script>
    """

    result = analyze_mixed_content(html)

    assert result["total_found"] == 1


def test_truncated_clean_response_requires_review():
    html = """
    <script src="https://example.org/app.js"></script>
    """

    result = analyze_mixed_content(
        html,
        content_truncated=True,
    )

    assert result["status"] == "Review"
    assert result["total_found"] == 0