import pytest

from app.services.authenticated_crawl import (
    AuthenticatedCrawlError,
    run_authenticated_crawl,
)
from app.services.authenticated_security import AuthenticatedSecurityError


def engagement():
    return {
        "purpose": "verified_engagement",
        "engagement_id": "engagement-one",
        "domain": "example.com",
        "scope": ["example.com"],
    }


def bug_bounty_engagement(**overrides):
    payload = {
        **engagement(),
        "assessment_mode": "bug_bounty",
        "authenticated_testing_approved": True,
        "researcher_owned_accounts_only": True,
        "request_delay_seconds": 0.5,
    }
    payload.update(overrides)
    return payload


def verification(status="Verified"):
    return {
        "status": status,
        "confidence": "High" if status == "Verified" else "Medium",
    }


def clean_authenticated_security(*args, **kwargs):
    return {
        "status": "Protected",
        "cors": {"status": "Protected", "checks": []},
        "data_transport": {"status": "Protected", "checks": []},
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
        security_scanner=clean_authenticated_security,
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
        security_scanner=clean_authenticated_security,
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


def test_bug_bounty_authenticated_crawl_uses_signed_safe_limits(monkeypatch):
    monkeypatch.setattr(
        "app.services.authenticated_crawl.get_login_session",
        lambda *args: object(),
    )
    received = {}

    result = run_authenticated_crawl(
        "session-one",
        "https://example.com/account",
        bug_bounty_engagement(),
        max_pages=5,
        max_depth=1,
        verifier=lambda *args: verification("Verified"),
        crawler=lambda domain, **kwargs: (
            received.update(kwargs) or {"domain": domain}
        ),
        security_scanner=clean_authenticated_security,
    )

    assert received["delay_seconds"] == 0.5
    assert received["max_pages"] == 5
    assert received["max_depth"] == 1
    assert result["assessment_mode"] == "bug_bounty"


def test_bug_bounty_authenticated_crawl_rejects_excess_pages():
    with pytest.raises(AuthenticatedCrawlError, match="1 and 5"):
        run_authenticated_crawl(
            "session-one",
            "https://example.com/account",
            bug_bounty_engagement(),
            max_pages=6,
            max_depth=1,
        )


def test_bug_bounty_medium_confidence_requires_manual_boundary_confirmation():
    with pytest.raises(AuthenticatedCrawlError, match="private browser window"):
        run_authenticated_crawl(
            "session-one",
            "https://example.com/account",
            bug_bounty_engagement(),
            max_pages=5,
            max_depth=1,
            accept_medium_confidence=True,
        )


def test_bug_bounty_medium_confidence_accepts_confirmed_anonymous_denial(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.authenticated_crawl.get_login_session",
        lambda *args: object(),
    )
    result = run_authenticated_crawl(
        "session-one",
        "https://example.com/account",
        bug_bounty_engagement(),
        max_pages=5,
        max_depth=1,
        accept_medium_confidence=True,
        anonymous_access_denial_confirmed=True,
        verifier=lambda *args: verification("Likely Authenticated"),
        crawler=lambda domain, **kwargs: {"domain": domain},
        security_scanner=clean_authenticated_security,
    )

    assert result["authentication_verification"]["confidence"] == "Medium"
    assert result["anonymous_access_denial_confirmed"] is True


def test_bug_bounty_authenticated_crawl_requires_signed_approval():
    with pytest.raises(AuthenticatedCrawlError, match="not approved"):
        run_authenticated_crawl(
            "session-one",
            "https://example.com/account",
            bug_bounty_engagement(authenticated_testing_approved=False),
            max_pages=5,
            max_depth=1,
        )


def test_authenticated_security_finding_enters_prioritized_report(monkeypatch):
    monkeypatch.setattr(
        "app.services.authenticated_crawl.get_login_session",
        lambda *args: object(),
    )
    security = {
        "status": "Needs Attention",
        "cors": {
            "status": "Needs Attention",
            "checks": [{
                "name": "Authenticated Response Trusts an Unrelated Origin",
                "message": "Credentialed origin reflection was observed.",
                "severity": "High",
                "confidence": "High",
                "category": "Broken Access Control",
            }],
        },
        "data_transport": {"status": "Protected", "checks": []},
    }
    result = run_authenticated_crawl(
        "session-one",
        "https://example.com/account",
        engagement(),
        verifier=lambda *args: verification("Verified"),
        crawler=lambda domain, **kwargs: {"domain": domain},
        security_scanner=lambda *args: security,
    )

    report = result["vulnerability_report"]
    assert report["summary"]["high"] == 1
    assert report["findings"][0]["category"] == "Broken Access Control"


def test_authenticated_security_failure_does_not_discard_completed_crawl(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.authenticated_crawl.get_login_session",
        lambda *args: object(),
    )

    def unavailable_security(*args):
        raise AuthenticatedSecurityError("The bounded check timed out.")

    result = run_authenticated_crawl(
        "session-one",
        "https://example.com/account",
        engagement(),
        verifier=lambda *args: verification("Verified"),
        crawler=lambda domain, **kwargs: {
            "domain": domain,
            "pages_scanned": 2,
        },
        security_scanner=unavailable_security,
    )

    assert result["pages_scanned"] == 2
    assert result["authenticated_security"]["status"] == "Unavailable"
    assert result["vulnerability_report"]["summary"]["total"] == 0
