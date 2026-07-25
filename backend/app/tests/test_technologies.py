from app.scanners.technologies import (
    detect_technologies,
    detect_technologies_from_evidence,
)


def test_cloudflare_cf_ray_is_high_confidence():
    results = detect_technologies_from_evidence(
        {"Cf-Ray": "123456-DEL"},
        "<html></html>",
    )

    assert results[0]["value"] == "Cloudflare"
    assert results[0]["confidence"] == "High"


def test_wordpress_multiple_signals_are_high_confidence():
    html = """
        <link href="/wp-content/theme.css">
        <script src="/wp-includes/script.js"></script>
    """

    results = detect_technologies_from_evidence({}, html)

    assert results[0]["value"] == "WordPress"
    assert results[0]["confidence"] == "High"


def test_one_wordpress_signal_is_medium_confidence():
    results = detect_technologies_from_evidence(
        {},
        '<link href="/wp-content/theme.css">',
    )

    assert results[0]["value"] == "WordPress"
    assert results[0]["confidence"] == "Medium"


def test_server_header_is_low_confidence():
    results = detect_technologies_from_evidence(
        {"Server": "nginx"},
        "<html></html>",
    )

    assert results[0]["value"] == "nginx"
    assert results[0]["confidence"] == "Low"


def test_no_evidence_returns_not_detected():
    results = detect_technologies_from_evidence(
        {},
        "<html><body>Hello</body></html>",
    )

    assert results[0]["status"] == "Not Detected"
    assert results[0]["confidence"] == "None"


def test_existing_homepage_response_is_reused(monkeypatch):
    class Response:
        url = "https://example.com/"
        headers = {"Server": "nginx"}
        text = "<html></html>"

    def unexpected_fetch(*args, **kwargs):
        raise AssertionError(
            "Technology detection fetched the homepage twice."
        )

    monkeypatch.setattr(
        "app.scanners.technologies.safe_get",
        unexpected_fetch,
    )

    result = detect_technologies(
        "example.com",
        response=Response(),
    )

    assert result["checks"][0]["value"] == "nginx"


def test_frontend_libraries_are_detected_from_html():
    results = detect_technologies_from_evidence(
        {},
        """
        <link href="/css/bootstrap.min.css" rel="stylesheet">
        <script src="/js/jquery.min.js"></script>
        <script src="/js/bootstrap.min.js"></script>
        """,
    )

    values = {result["value"] for result in results}
    assert "jQuery" in values
    assert "Bootstrap" in values
