import pytest

import app.services.logout_invalidation as logout_service
from app.services.logout_invalidation import (
    LogoutInvalidationError,
    cancel_logout_invalidation_test,
    check_logout_invalidation_test,
    clear_logout_tests,
    prepare_logout_invalidation_test,
)


class FakeResponse:
    def __init__(self, text, status_code=200, url="https://example.com/account"):
        self.text = text
        self.content = text.encode("utf-8")
        self.status_code = status_code
        self.url = url


def engagement(identifier="engagement-one"):
    return {
        "purpose": "verified_engagement",
        "engagement_id": identifier,
        "domain": "example.com",
        "scope": ["example.com"],
        "assessment_mode": "bug_bounty",
        "request_delay_seconds": 0.5,
    }


def verified(*args):
    return {"status": "Likely Authenticated", "confidence": "Medium"}


@pytest.fixture(autouse=True)
def isolated_logout_tests(monkeypatch):
    deleted = []
    monkeypatch.setattr(
        logout_service,
        "delete_login_session",
        lambda session_id, payload: deleted.append(session_id),
    )
    monkeypatch.setattr(
        logout_service,
        "get_login_session",
        lambda *args: object(),
    )
    clear_logout_tests()
    yield deleted
    clear_logout_tests()


def prepare(baseline_text="Private owner@example.com account"):
    return prepare_logout_invalidation_test(
        "session-one",
        "https://example.com/account",
        engagement(),
        anonymous_access_denial_confirmed=True,
        verifier=verified,
        fetcher=lambda *args, **kwargs: FakeResponse(baseline_text),
        sleeper=lambda delay: None,
        now=1000,
    )


def test_prepare_stores_hashes_without_returning_values():
    result = prepare()

    assert result["status"] == "Waiting for Manual Logout"
    assert result["baseline_personal_indicator_count"] == 1
    assert result["personal_values_returned"] is False
    assert result["cookie_values_returned"] is False
    assert "owner@example.com" not in str(result)


def test_old_session_matching_anonymous_response_is_protected(
    isolated_logout_tests,
):
    prepared = prepare()
    responses = iter([
        FakeResponse("Please sign in"),
        FakeResponse("Please sign in"),
    ])
    result = check_logout_invalidation_test(
        prepared["test_id"],
        engagement(),
        True,
        fetcher=lambda *args, **kwargs: next(responses),
        sleeper=lambda delay: None,
        now=1001,
    )

    assert result["status"] == "Protected"
    assert result["finding"] is None
    assert result["old_session_deleted"] is True
    assert isolated_logout_tests == ["session-one"]


def test_private_indicator_persisting_after_logout_is_high_confidence():
    prepared = prepare()
    responses = iter([
        FakeResponse("Please sign in"),
        FakeResponse("Private owner@example.com account"),
    ])
    result = check_logout_invalidation_test(
        prepared["test_id"],
        engagement(),
        True,
        fetcher=lambda *args, **kwargs: next(responses),
        sleeper=lambda delay: None,
        now=1001,
    )

    assert result["status"] == "Needs Attention"
    assert result["finding"]["severity"] == "High"
    assert result["evidence"]["private_indicator_count"] == 1
    assert "owner@example.com" not in str(result)


def test_exact_baseline_without_private_indicator_requires_confirmation():
    prepared = prepare("Private account dashboard")
    responses = iter([
        FakeResponse("Please sign in"),
        FakeResponse("Private account dashboard"),
    ])
    result = check_logout_invalidation_test(
        prepared["test_id"],
        engagement(),
        True,
        fetcher=lambda *args, **kwargs: next(responses),
        sleeper=lambda delay: None,
        now=1001,
    )

    assert result["status"] == "Review"
    assert result["finding"]["severity"] == "Medium"
    assert result["finding"]["validation"] == "Requires Confirmation"


def test_check_requires_manual_logout_confirmation():
    prepared = prepare()
    with pytest.raises(LogoutInvalidationError, match="Confirm"):
        check_logout_invalidation_test(
            prepared["test_id"],
            engagement(),
            False,
            now=1001,
        )


def test_other_engagement_cannot_check_or_cancel_test():
    prepared = prepare()
    with pytest.raises(LogoutInvalidationError, match="different"):
        check_logout_invalidation_test(
            prepared["test_id"],
            engagement("engagement-two"),
            True,
            now=1001,
        )
    with pytest.raises(LogoutInvalidationError, match="different"):
        cancel_logout_invalidation_test(
            prepared["test_id"],
            engagement("engagement-two"),
        )


def test_cancel_deletes_old_session(isolated_logout_tests):
    prepared = prepare()
    result = cancel_logout_invalidation_test(
        prepared["test_id"],
        engagement(),
    )

    assert result["cancelled"] is True
    assert result["old_session_deleted"] is True
    assert isolated_logout_tests == ["session-one"]


def test_endpoint_mode_proves_anonymous_denial_and_uses_endpoint():
    calls = []
    responses = iter([
        FakeResponse(
            "Denied",
            status_code=401,
            url="https://example.com/api/me",
        ),
        FakeResponse(
            "Private account",
            url="https://example.com/api/me",
        ),
    ])

    result = prepare_logout_invalidation_test(
        "session-one",
        "https://example.com/account",
        engagement(),
        anonymous_access_denial_confirmed=True,
        verification_endpoint_url="https://example.com/api/me",
        verifier=verified,
        fetcher=lambda url, **kwargs: (
            calls.append(url) or next(responses)
        ),
        sleeper=lambda delay: None,
        now=1000,
    )

    assert result["verification_mode"] == "Read-only GET Account Endpoint"
    assert result["baseline_requests_made"] == 2
    assert calls == ["https://example.com/api/me"] * 2


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example/api/me",
        "https://example.com/api/me?access_token=secret",
        "https://example.com/api/me#private",
    ],
)
def test_endpoint_mode_rejects_unsafe_urls(url):
    with pytest.raises(LogoutInvalidationError):
        prepare_logout_invalidation_test(
            "session-one",
            "https://example.com/account",
            engagement(),
            anonymous_access_denial_confirmed=True,
            verification_endpoint_url=url,
            verifier=verified,
            fetcher=lambda *args, **kwargs: FakeResponse("Private"),
            sleeper=lambda delay: None,
            now=1000,
        )


def test_controlled_read_only_post_uses_small_json_body():
    calls = []
    responses = iter([
        FakeResponse(
            "Denied",
            status_code=401,
            url="https://example.com/api/getProfile",
        ),
        FakeResponse(
            "Private account",
            url="https://example.com/api/getProfile",
        ),
    ])

    result = prepare_logout_invalidation_test(
        "session-one",
        "https://example.com/account",
        engagement(),
        anonymous_access_denial_confirmed=True,
        verification_endpoint_url="https://example.com/api/getProfile",
        verification_method="POST",
        verification_json_body={
            "locale": "en-IN",
            "countryCode": "IN",
        },
        read_only_post_confirmed=True,
        verifier=verified,
        fetcher=lambda *args, **kwargs: pytest.fail("GET was used"),
        post_fetcher=lambda url, body, **kwargs: (
            calls.append((url, body, kwargs.get("session")))
            or next(responses)
        ),
        sleeper=lambda delay: None,
        now=1000,
    )

    assert result["verification_mode"] == "Read-only POST Account Endpoint"
    assert result["baseline_requests_made"] == 2
    assert [item[1] for item in calls] == [
        {"countryCode": "IN", "locale": "en-IN"}
    ] * 2
    assert "locale" not in str(result)


def test_controlled_post_replays_same_body_once_after_logout():
    calls = []
    responses = iter([
        FakeResponse("Denied", status_code=401),
        FakeResponse("Private account"),
        FakeResponse("Denied", status_code=401),
        FakeResponse("Denied", status_code=401),
    ])

    def post_fetcher(url, body, **kwargs):
        calls.append((url, body, kwargs.get("session")))
        return next(responses)

    prepared = prepare_logout_invalidation_test(
        "session-one",
        "https://example.com/account",
        engagement(),
        anonymous_access_denial_confirmed=True,
        verification_endpoint_url="https://example.com/api/getProfile",
        verification_method="POST",
        verification_json_body={"locale": "en-IN"},
        read_only_post_confirmed=True,
        verifier=verified,
        post_fetcher=post_fetcher,
        sleeper=lambda delay: None,
        now=1000,
    )
    result = check_logout_invalidation_test(
        prepared["test_id"],
        engagement(),
        True,
        post_fetcher=post_fetcher,
        sleeper=lambda delay: None,
        now=1001,
    )

    assert result["status"] == "Protected"
    assert result["verification_mode"] == "Read-only POST Account Endpoint"
    assert len(calls) == 4
    assert all(call[1] == {"locale": "en-IN"} for call in calls)


@pytest.mark.parametrize(
    ("url", "body", "confirmed", "message"),
    [
        (
            "https://example.com/api/getProfile",
            {},
            False,
            "Confirm",
        ),
        (
            "https://example.com/api/updateProfile",
            {},
            True,
            "recognizably read-only",
        ),
        (
            "https://example.com/api/getProfile",
            {"access_token": "secret"},
            True,
            "secret-like",
        ),
    ],
)
def test_controlled_post_rejects_unsafe_configuration(
    url,
    body,
    confirmed,
    message,
):
    with pytest.raises(LogoutInvalidationError, match=message):
        prepare_logout_invalidation_test(
            "session-one",
            "https://example.com/account",
            engagement(),
            anonymous_access_denial_confirmed=True,
            verification_endpoint_url=url,
            verification_method="POST",
            verification_json_body=body,
            read_only_post_confirmed=confirmed,
            verifier=verified,
            sleeper=lambda delay: None,
            now=1000,
        )
