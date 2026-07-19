import pytest

from app.services.authenticated_crawl import (
    AuthenticatedCrawlError,
    run_authenticated_crawl,
)


def engagement():
    return {
        "purpose": "verified_engagement",
        "engagement_id": "engagement-one",
        "domain": "example.com",
        "scope": ["example.com"],
    }


def verification(status="Verified"):
    return {
        "status": status,
        "confidence": "High" if status == "Verified" else "Medium",
    }


def test_verified_session_runs_read_only_crawler(monkeypatch):
    stored_session = object()
    monkeypatch.setattr(
        "app.services.authenticated_crawl.get_login_session",
        lambda session_id, payload: stored_session,
    )
    received = {}

    def fake_crawler(domain, **kwargs):
        received.update(kwargs)
        return {"domain": domain, "status": "Completed", "pages_scanned": 3}

    result = run_authenticated_crawl(
        "session-one",
        "https://example.com/dashboard",
        engagement(),
        verifier=lambda *args: verification(),
        crawler=fake_crawler,
    )

    assert result["name"] == "Read-Only Authenticated Crawler"
    assert result["forms_submitted"] == 0
    assert result["state_changing_requests_sent"] == 0
    assert received["session"] is stored_session
    assert received["start_url"] == "https://example.com/dashboard"
    assert received["authenticated"] is True


def test_unverified_session_stops_before_crawling(monkeypatch):
    called = False

    def fake_crawler(*args, **kwargs):
        nonlocal called
        called = True

    with pytest.raises(AuthenticatedCrawlError, match="stopped"):
        run_authenticated_crawl(
            "session-one",
            "https://example.com/dashboard",
            engagement(),
            verifier=lambda *args: verification("Not Verified"),
            crawler=fake_crawler,
        )
    assert called is False


def test_medium_confidence_requires_explicit_acceptance():
    with pytest.raises(AuthenticatedCrawlError, match="stopped"):
        run_authenticated_crawl(
            "session-one",
            "https://example.com/dashboard",
            engagement(),
            verifier=lambda *args: verification("Likely Authenticated"),
        )


def test_medium_confidence_can_be_explicitly_accepted(monkeypatch):
    monkeypatch.setattr(
        "app.services.authenticated_crawl.get_login_session",
        lambda *args: object(),
    )
    result = run_authenticated_crawl(
        "session-one",
        "https://example.com/dashboard",
        engagement(),
        accept_medium_confidence=True,
        verifier=lambda *args: verification("Likely Authenticated"),
        crawler=lambda domain, **kwargs: {"domain": domain},
    )
    assert result["authentication_verification"]["status"] == "Likely Authenticated"


def test_authenticated_page_limit_is_bounded():
    with pytest.raises(AuthenticatedCrawlError, match="1 and 25"):
        run_authenticated_crawl(
            "session-one",
            "https://example.com/dashboard",
            engagement(),
            max_pages=26,
        )


def test_authenticated_depth_is_bounded():
    with pytest.raises(AuthenticatedCrawlError, match="depth"):
        run_authenticated_crawl(
            "session-one",
            "https://example.com/dashboard",
            engagement(),
            max_depth=3,
        )
