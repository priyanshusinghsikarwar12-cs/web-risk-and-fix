import pytest

from app.services import object_access_control as module
from app.services.object_access_control import (
    ObjectAccessControlError,
    check_api_authentication_boundary,
    check_object_access_control,
)


class FakeResponse:
    def __init__(self, body, status=200, content_type="application/json"):
        self.content = body.encode("utf-8")
        self.status_code = status
        self.headers = {"Content-Type": content_type}


def engagement(**overrides):
    values = {
        "purpose": "verified_engagement",
        "engagement_id": "engagement-one",
        "domain": "example.com",
        "scope": ["example.com"],
        "assessment_mode": "owner_verified",
        "request_delay_seconds": 0.5,
    }
    values.update(overrides)
    return values


def run_with(responses, **overrides):
    sessions = {"a": object(), "b": object()}
    module.get_login_session = lambda session_id, payload: sessions[session_id]
    calls = []

    def fetcher(url, session, **kwargs):
        calls.append((url, session, kwargs))
        return responses.pop(0)

    result = check_object_access_control(
        "a",
        "b",
        "https://example.com/api/orders/{object_id}",
        "order-a",
        "order-b",
        engagement(),
        read_only_get_confirmed=True,
        test_accounts_own_objects_confirmed=True,
        fetcher=fetcher,
        sleeper=lambda delay: None,
        **overrides,
    )
    return result, calls


def test_exact_cross_account_match_is_high_confidence_candidate(monkeypatch):
    monkeypatch.setattr(
        module,
        "get_login_session",
        lambda session_id, payload: {"a": "session-a", "b": "session-b"}[session_id],
    )
    responses = [
        FakeResponse('{"owner":"a"}'),
        FakeResponse('{"owner":"b"}'),
        FakeResponse('{"owner":"b"}'),
        FakeResponse('{"owner":"a"}'),
    ]
    result, calls = run_with(responses)

    assert result["status"] == "Needs Attention"
    assert result["checks"][0]["severity"] == "High"
    assert result["checks"][0]["validation"] == "Requires Confirmation"
    assert result["requests_made"] == 4
    assert result["values_returned"] is False
    assert len(calls) == 4


def test_both_cross_requests_denied_is_protected():
    result, _calls = run_with([
        FakeResponse('{"owner":"a"}'),
        FakeResponse('{"owner":"b"}'),
        FakeResponse("denied", status=403),
        FakeResponse("missing", status=404),
    ])

    assert result["status"] == "Protected"
    assert result["finding_count"] == 0


def test_success_without_exact_match_is_inconclusive():
    result, _calls = run_with([
        FakeResponse('{"owner":"a"}'),
        FakeResponse('{"owner":"b"}'),
        FakeResponse('{"generic":true}'),
        FakeResponse('{"generic":true}'),
    ])

    assert result["status"] == "Inconclusive"
    assert result["finding_count"] == 0


def test_identical_owner_baselines_stop_before_cross_requests():
    result, calls = run_with([
        FakeResponse('{"same":true}'),
        FakeResponse('{"same":true}'),
    ])

    assert result["status"] == "Inconclusive"
    assert result["requests_made"] == 2
    assert len(calls) == 2


@pytest.mark.parametrize(
    "template",
    [
        "https://evil.example/api/{object_id}",
        "http://example.com/api/{object_id}",
        "https://example.com/api/delete/{object_id}",
        "https://example.com/api/{object_id}?token=secret",
        "https://example.com/api/no-placeholder",
    ],
)
def test_unsafe_endpoint_templates_are_rejected(monkeypatch, template):
    monkeypatch.setattr(module, "validate_request_url", lambda url: None)
    with pytest.raises(ObjectAccessControlError):
        check_object_access_control(
            "a",
            "b",
            template,
            "one",
            "two",
            engagement(),
            read_only_get_confirmed=True,
            test_accounts_own_objects_confirmed=True,
        )


def test_bug_bounty_profile_is_rejected():
    with pytest.raises(ObjectAccessControlError, match="owner-verified"):
        check_object_access_control(
            "a",
            "b",
            "https://example.com/api/{object_id}",
            "one",
            "two",
            engagement(assessment_mode="bug_bounty"),
            read_only_get_confirmed=True,
            test_accounts_own_objects_confirmed=True,
        )


def test_two_distinct_sessions_and_objects_are_required():
    with pytest.raises(ObjectAccessControlError, match="different test-account"):
        check_object_access_control(
            "same",
            "same",
            "https://example.com/api/{object_id}",
            "one",
            "two",
            engagement(),
            read_only_get_confirmed=True,
            test_accounts_own_objects_confirmed=True,
        )


class AnonymousSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def run_auth_boundary(responses):
    module.get_login_session = lambda session_id, payload: "authenticated-session"
    anonymous_session = AnonymousSession()

    def fetcher(url, session, **kwargs):
        return responses.pop(0)

    result = check_api_authentication_boundary(
        "account-session",
        "https://example.com/api/orders/{object_id}",
        "order-a",
        engagement(),
        read_only_get_confirmed=True,
        private_test_object_confirmed=True,
        fetcher=fetcher,
        sleeper=lambda delay: None,
        anonymous_session_factory=lambda: anonymous_session,
    )
    return result, anonymous_session


def test_exact_anonymous_private_match_is_high_candidate():
    result, anonymous_session = run_auth_boundary([
        FakeResponse('{"owner":"a","private":true}'),
        FakeResponse('{"owner":"a","private":true}'),
    ])

    assert result["status"] == "Needs Attention"
    assert result["checks"][0]["severity"] == "High"
    assert result["checks"][0]["validation"] == "Requires Confirmation"
    assert result["requests_made"] == 2
    assert result["values_returned"] is False
    assert anonymous_session.closed is True


def test_denied_anonymous_request_is_protected():
    result, _session = run_auth_boundary([
        FakeResponse('{"owner":"a"}'),
        FakeResponse("denied", status=401),
    ])

    assert result["status"] == "Protected"
    assert result["finding_count"] == 0


def test_nonmatching_anonymous_success_is_inconclusive():
    result, _session = run_auth_boundary([
        FakeResponse('{"owner":"a"}'),
        FakeResponse('{"public":true}'),
    ])

    assert result["status"] == "Inconclusive"
    assert result["finding_count"] == 0


def test_unusable_authenticated_baseline_stops_after_one_request():
    result, anonymous_session = run_auth_boundary([
        FakeResponse("login", content_type="text/html"),
    ])

    assert result["status"] == "Inconclusive"
    assert result["requests_made"] == 1
    assert anonymous_session.closed is False
