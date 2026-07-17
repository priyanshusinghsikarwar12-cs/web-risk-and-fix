from app.scanners.public_files import (
    analyze_robots,
    analyze_security_txt,
    analyze_sitemap,
    label_security_txt_location,
)


def test_valid_robots_file_is_found():
    content = """
    User-agent: *
    Disallow: /search
    Sitemap: https://example.com/sitemap.xml
    """

    result = analyze_robots(
        200,
        content,
        "https://example.com/robots.txt",
    )

    assert result["status"] == "Found"
    assert result["disallowed_path_count"] == 1
    assert result["sitemap_reference_count"] == 1


def test_sensitive_looking_robots_path_requires_review():
    content = """
    User-agent: *
    Disallow: /private-backup/
    """

    result = analyze_robots(
        200,
        content,
        "https://example.com/robots.txt",
    )

    assert result["status"] == "Review"
    assert result["review_paths"] == [
        "/private-backup/"
    ]


def test_html_is_not_accepted_as_robots_file():
    result = analyze_robots(
        200,
        "<!doctype html><html></html>",
        "https://example.com/robots.txt",
    )

    assert result["status"] == "Review"


def test_valid_sitemap_is_found():
    content = """
    <urlset>
      <url>
        <loc>https://example.com/</loc>
      </url>
    </urlset>
    """

    result = analyze_sitemap(
        200,
        content,
        "https://example.com/sitemap.xml",
    )

    assert result["status"] == "Found"
    assert result["url_count"] == 1


def test_invalid_sitemap_requires_review():
    result = analyze_sitemap(
        200,
        "<html>Not a sitemap</html>",
        "https://example.com/sitemap.xml",
    )

    assert result["status"] == "Review"


def test_insecure_sitemap_url_requires_review():
    content = """
    <urlset>
      <url>
        <loc>http://example.com/page</loc>
      </url>
    </urlset>
    """

    result = analyze_sitemap(
        200,
        content,
        "https://example.com/sitemap.xml",
    )

    assert result["status"] == "Review"
    assert result["insecure_url_count"] == 1


def test_valid_security_txt_is_configured():
    content = """
    Contact: mailto:security@example.com
    Expires: 2099-12-31T23:59:59Z
    """

    result = analyze_security_txt(
        200,
        content,
        "https://example.com/.well-known/security.txt",
    )

    assert result["status"] == "Configured"
    assert result["contact_count"] == 1


def test_missing_security_contact_needs_attention():
    content = """
    Expires: 2099-12-31T23:59:59Z
    """

    result = analyze_security_txt(
        200,
        content,
        "https://example.com/.well-known/security.txt",
    )

    assert result["status"] == "Needs Attention"
    assert "Contact is missing" in result["message"]


def test_expired_security_txt_needs_attention():
    content = """
    Contact: mailto:security@example.com
    Expires: 2020-01-01T00:00:00Z
    """

    result = analyze_security_txt(
        200,
        content,
        "https://example.com/.well-known/security.txt",
    )

    assert result["status"] == "Needs Attention"
    assert "expired" in result["message"].lower()

def test_legacy_security_txt_requires_review():
    result = {
        "name": "security.txt",
        "status": "Configured",
        "message": "Valid file.",
    }

    labelled = label_security_txt_location(
        result,
        preferred_location=False,
    )

    assert labelled["status"] == "Review"
    assert labelled["location"] == "Legacy"    