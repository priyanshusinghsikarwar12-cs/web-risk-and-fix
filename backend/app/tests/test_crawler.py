from app.deep_scanners.crawler import (
    analyze_crawl_page,
    crawl_verified_site,
    inspect_candidate_url,
)


DOMAIN = "example.com"
PAGE_URL = "https://example.com/"


class FakeResponse:
    def __init__(
        self,
        url,
        text,
        status_code=200,
    ):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = {
            "Content-Type": "text/html",
        }
        self.webshield_content_truncated = False


def test_relative_link_becomes_internal_url():
    result = inspect_candidate_url(
        PAGE_URL,
        "/about",
        DOMAIN,
    )

    assert result["internal"] is True
    assert result["crawlable"] is True
    assert result["crawl_url"] == (
        "https://example.com/about"
    )


def test_external_link_is_not_crawlable():
    result = inspect_candidate_url(
        PAGE_URL,
        "https://external.example.org/page",
        DOMAIN,
    )

    assert result["internal"] is False
    assert result["crawlable"] is False


def test_query_parameter_names_are_inventoried():
    result = inspect_candidate_url(
        PAGE_URL,
        "/search?q=test&page=2",
        DOMAIN,
    )

    assert result["parameter_names"] == [
        "page",
        "q",
    ]


def test_risky_logout_path_is_not_crawled():
    result = inspect_candidate_url(
        PAGE_URL,
        "/account/logout",
        DOMAIN,
    )

    assert result["risky_path"] is True
    assert result["crawlable"] is False


def test_password_form_is_detected():
    html = """
    <form action="/login" method="post">
      <input name="email" type="email">
      <input name="password" type="password">
      <button type="submit">Sign in</button>
    </form>
    """

    result = analyze_crawl_page(
        html,
        PAGE_URL,
        DOMAIN,
    )

    assert len(result["forms"]) == 1
    assert result["forms"][0][
        "has_password_field"
    ] is True
    assert len(result["login_surfaces"]) == 1


def test_login_link_is_detected():
    html = """
    <a href="/login">Customer login</a>
    """

    result = analyze_crawl_page(
        html,
        PAGE_URL,
        DOMAIN,
    )

    assert len(result["login_surfaces"]) == 1


def test_http_link_is_not_crawled():
    result = inspect_candidate_url(
        PAGE_URL,
        "http://example.com/account",
        DOMAIN,
    )

    assert result["internal"] is True
    assert result["secure"] is False
    assert result["crawlable"] is False


def test_crawler_visits_discovered_pages(
    monkeypatch,
):
    responses = {
        "https://example.com/": FakeResponse(
            "https://example.com/",
            """
            <html>
              <title>Home</title>
              <a href="/login">Login</a>
              <a href="/about">About</a>
            </html>
            """,
        ),
        "https://example.com/login": FakeResponse(
            "https://example.com/login",
            """
            <form method="post">
              <input name="username">
              <input
                name="password"
                type="password"
              >
            </form>
            """,
        ),
        "https://example.com/about": FakeResponse(
            "https://example.com/about",
            "<title>About</title>",
        ),
    }

    monkeypatch.setattr(
        "app.deep_scanners.crawler.safe_get",
        lambda url, timeout, max_bytes, **kwargs: responses[url],
    )

    result = crawl_verified_site(
        "example.com",
        max_pages=10,
        max_depth=2,
        delay_seconds=0,
    )

    assert result["status"] == "Completed"
    assert result["pages_scanned"] == 3
    assert result["form_count"] == 1
    assert result["login_surface_count"] >= 1
    assert "password" in result["parameter_names"]
    assert result["safety"]["forms_submitted"] is False
