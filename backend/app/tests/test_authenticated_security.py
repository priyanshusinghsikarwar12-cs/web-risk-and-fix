import requests
import pytest

from app.services.authenticated_security import (
    AuthenticatedSecurityError,
    run_authenticated_security_checks,
)


class FakeResponse:
    def __init__(self, url="https://example.com/account", headers=None, text=""):
        self.url = url
        self.headers = headers or {}
        self.text = text
        self.status_code = 200


def engagement():
    return {
        "purpose": "verified_engagement",
        "engagement_id": "engagement-one",
        "domain": "example.com",
        "scope": ["example.com"],
        "assessment_mode": "bug_bounty",
        "request_delay_seconds": 0.5,
    }


def run_with(response, monkeypatch, **kwargs):
    stored_session = object()
    monkeypatch.setattr(
        "app.services.authenticated_security.get_login_session",
        lambda *args: stored_session,
    )
    received = {}

    def fetcher(url, **request_options):
        received["url"] = url
        received.update(request_options)
        return response

    result = run_authenticated_security_checks(
        "session-one",
        kwargs.pop("protected_url", "https://example.com/account"),
        engagement(),
        fetcher=fetcher,
        sleeper=lambda delay: received.setdefault("delay", delay),
    )
    return result, received


def test_protected_response_without_cors_or_shared_cache_passes(monkeypatch):
    result, received = run_with(
        FakeResponse(headers={"Cache-Control": "private, no-store"}),
        monkeypatch,
    )

    assert result["status"] == "Protected"
    assert result["cors"]["status"] == "Protected"
    assert result["data_transport"]["status"] == "Protected"
    assert result["requests_made"] == 1
    assert received["session"] is not None
    assert received["headers"]["Origin"] == "https://webshield.invalid"
    assert received["delay"] == 0.5


def test_credentialed_origin_reflection_is_high_severity(monkeypatch):
    result, _ = run_with(
        FakeResponse(headers={
            "Access-Control-Allow-Origin": "https://webshield.invalid",
            "Access-Control-Allow-Credentials": "true",
            "Cache-Control": "private",
        }),
        monkeypatch,
    )

    finding = result["cors"]["checks"][0]
    assert finding["severity"] == "High"
    assert finding["category"] == "Broken Access Control"
    assert finding["evidence"]["response_body_returned"] is False


def test_shared_cache_with_personal_indicator_requires_confirmation(monkeypatch):
    result, _ = run_with(
        FakeResponse(
            headers={"Cache-Control": "public, max-age=120"},
            text="Account email: owner@example.com",
        ),
        monkeypatch,
    )

    finding = result["data_transport"]["checks"][0]
    assert finding["severity"] == "Medium"
    assert finding["validation"] == "Requires Confirmation"
    assert "owner@example.com" not in str(result)
    assert result["data_transport"]["sensitive_values_returned"] is False


def test_sensitive_query_name_is_reported_but_value_is_redacted(monkeypatch):
    result, _ = run_with(
        FakeResponse(
            url="https://example.com/account?token=secret-value&locale=en"
        ),
        monkeypatch,
    )

    finding = result["data_transport"]["checks"][0]
    assert finding["evidence"]["sensitive_parameter_names"] == ["token"]
    assert "secret-value" not in str(result)
    assert finding["evidence"]["parameter_values_returned"] is False


def test_collection_failure_stops_with_safe_error(monkeypatch):
    monkeypatch.setattr(
        "app.services.authenticated_security.get_login_session",
        lambda *args: object(),
    )

    def failing_fetcher(*args, **kwargs):
        raise requests.Timeout("timeout")

    with pytest.raises(AuthenticatedSecurityError, match="could not be collected"):
        run_authenticated_security_checks(
            "session-one",
            "https://example.com/account",
            engagement(),
            fetcher=failing_fetcher,
            sleeper=lambda delay: None,
        )
