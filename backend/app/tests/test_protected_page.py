import pytest

from app.services.protected_page import (
    ProtectedPageError,
    verify_protected_page,
)


LOGIN_HTML = b'<form method="post"><input type="password" name="password"></form>'
DASHBOARD_HTML = b"<html><h1>Account dashboard</h1></html>"


class FakeResponse:
    def __init__(self, url, status_code, content):
        self.url = url
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8")


def engagement():
    return {
        "purpose": "verified_engagement",
        "engagement_id": "engagement-one",
        "domain": "example.com",
        "scope": ["example.com"],
    }


@pytest.fixture(autouse=True)
def fake_stored_session(monkeypatch):
    monkeypatch.setattr(
        "app.services.protected_page.get_login_session",
        lambda session_id, payload: object(),
    )


def response_fetcher(anonymous, authenticated):
    def fetch(url, session=None, **kwargs):
        return authenticated if session is not None else anonymous
    return fetch


def test_login_page_to_dashboard_is_verified():
    result = verify_protected_page(
        "session-one",
        "https://example.com/dashboard",
        engagement(),
        fetcher=response_fetcher(
            FakeResponse("https://example.com/login", 200, LOGIN_HTML),
            FakeResponse("https://example.com/dashboard", 200, DASHBOARD_HTML),
        ),
    )
    assert result["status"] == "Verified"
    assert result["confidence"] == "High"


def test_denied_to_allowed_is_verified():
    result = verify_protected_page(
        "session-one",
        "https://example.com/dashboard",
        engagement(),
        fetcher=response_fetcher(
            FakeResponse("https://example.com/dashboard", 403, b"Forbidden"),
            FakeResponse("https://example.com/dashboard", 200, DASHBOARD_HTML),
        ),
    )
    assert result["status"] == "Verified"


def test_dynamic_difference_is_only_medium_confidence():
    result = verify_protected_page(
        "session-one",
        "https://example.com/dashboard",
        engagement(),
        fetcher=response_fetcher(
            FakeResponse("https://example.com/dashboard", 200, b"anonymous"),
            FakeResponse("https://example.com/dashboard", 200, DASHBOARD_HTML),
        ),
    )
    assert result["status"] == "Likely Authenticated"
    assert result["confidence"] == "Medium"


def test_identical_pages_are_not_verified():
    page = FakeResponse("https://example.com/dashboard", 200, DASHBOARD_HTML)
    result = verify_protected_page(
        "session-one",
        "https://example.com/dashboard",
        engagement(),
        fetcher=response_fetcher(page, page),
    )
    assert result["status"] == "Not Verified"


def test_login_form_remaining_is_not_verified():
    result = verify_protected_page(
        "session-one",
        "https://example.com/dashboard",
        engagement(),
        fetcher=response_fetcher(
            FakeResponse("https://example.com/login", 200, LOGIN_HTML),
            FakeResponse("https://example.com/login", 200, LOGIN_HTML),
        ),
    )
    assert result["status"] == "Not Verified"


def test_protected_page_requires_https():
    with pytest.raises(ProtectedPageError, match="HTTPS"):
        verify_protected_page(
            "session-one",
            "http://example.com/dashboard",
            engagement(),
        )


def test_protected_page_must_be_in_scope():
    with pytest.raises(ProtectedPageError, match="outside"):
        verify_protected_page(
            "session-one",
            "https://admin.example.com/dashboard",
            engagement(),
        )


def test_response_does_not_return_content_or_cookies():
    result = verify_protected_page(
        "session-one",
        "https://example.com/dashboard",
        engagement(),
        fetcher=response_fetcher(
            FakeResponse("https://example.com/login", 200, LOGIN_HTML),
            FakeResponse("https://example.com/dashboard", 200, DASHBOARD_HTML),
        ),
    )
    assert result["page_content_returned"] is False
    assert result["cookie_values_returned"] is False
    assert "fingerprint" not in result["authenticated"]
    assert "content" not in result["authenticated"]
