import pytest

from app.services.login_session import (
    LoginSessionError,
    analyze_session_rotation,
    clear_login_sessions,
    create_browser_session,
    create_login_session,
    delete_login_session,
    get_login_session,
)


LOGIN_HTML = """
<html><body>
  <form action="/session" method="post">
    <input type="hidden" name="csrf" value="token-123">
    <input type="email" name="email">
    <input type="password" name="password">
  </form>
</body></html>
"""


class FakeCookie:
    def __init__(self, name, value="cookie-value"):
        self.name = name
        self.value = value


class FakeResponse:
    def __init__(self, text="", url="https://example.com/login", status_code=200):
        self.text = text
        self.url = url
        self.status_code = status_code


class FakeSession:
    def __init__(
        self,
        cookies=None,
        post_status=302,
        initial_cookies=None,
    ):
        post_cookies = (
            {"sessionid": "authenticated-session"}
            if cookies is None
            else cookies
        )
        initial_cookies = initial_cookies or {}
        self.cookies = [
            FakeCookie(name, value)
            for name, value in initial_cookies.items()
        ]
        self.post_cookies = (
            post_cookies
            if isinstance(post_cookies, dict)
            else {name: f"{name}-value" for name in post_cookies}
        )
        self.post_status = post_status
        self.post_calls = []
        self.closed = False

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        self.cookies = [
            FakeCookie(name, value)
            for name, value in self.post_cookies.items()
        ]
        return FakeResponse(url=url, status_code=self.post_status)

    def close(self):
        self.closed = True


def engagement(identifier="engagement-one"):
    return {
        "purpose": "verified_engagement",
        "engagement_id": identifier,
        "domain": "example.com",
        "scope": ["example.com"],
    }


def browser_engagement(**overrides):
    payload = {
        **engagement(),
        "assessment_mode": "bug_bounty",
        "authenticated_testing_approved": True,
        "researcher_owned_accounts_only": True,
    }
    payload.update(overrides)
    return payload


@pytest.fixture(autouse=True)
def isolated_sessions(monkeypatch):
    clear_login_sessions()
    monkeypatch.setattr(
        "app.services.login_session.open_test_account",
        lambda *args, **kwargs: {
            "credential_id": "credential-one",
            "domain": "example.com",
            "login_url": "https://example.com/login",
            "username": "test-user@example.com",
            "password": "temporary-password",
            "expires_at": 9999999999,
        },
    )
    monkeypatch.setattr(
        "app.services.login_session.validate_request_url",
        lambda url: None,
    )
    yield
    clear_login_sessions()


def set_login_page(monkeypatch, html=LOGIN_HTML, status_code=200):
    monkeypatch.setattr(
        "app.services.login_session.safe_get",
        lambda *args, **kwargs: FakeResponse(html, status_code=status_code),
    )


def test_one_login_attempt_preserves_hidden_field(monkeypatch):
    set_login_page(monkeypatch)
    session = FakeSession()

    result = create_login_session(
        "credential-one",
        engagement(),
        "vault-secret-that-is-long-enough-for-tests",
        session_factory=lambda: session,
    )

    assert result["status"] == "Session Cookie Observed"
    assert result["cookie_names"] == ["sessionid"]
    assert result["cookie_values_returned"] is False
    assert result["credential_values_returned"] is False
    assert len(session.post_calls) == 1
    submitted = session.post_calls[0][1]["data"]
    assert submitted["csrf"] == "token-123"
    assert submitted["email"] == "test-user@example.com"
    assert submitted["password"] == "temporary-password"
    assert result["session_fixation"]["status"] == "Protected"
    assert result["session_fixation"]["cookie_values_returned"] is False


def test_rotated_session_identifier_is_protected():
    result = analyze_session_rotation(
        {"sessionid": "anonymous-value"},
        {"sessionid": "authenticated-value"},
    )

    assert result["status"] == "Protected"
    assert result["rotated_cookie_count"] == 1
    assert result["checks"] == []


def test_unchanged_session_identifier_requires_confirmation():
    result = analyze_session_rotation(
        {"sessionid": "same-value"},
        {"sessionid": "same-value"},
    )

    assert result["status"] == "Needs Attention"
    assert result["finding_count"] == 1
    finding = result["checks"][0]
    assert finding["severity"] == "High"
    assert finding["confidence"] == "Medium"
    assert finding["validation"] == "Requires Confirmation"
    assert finding["evidence"]["cookie_values_returned"] is False


def test_unrelated_cookie_is_not_mislabeled_as_session_fixation():
    result = analyze_session_rotation(
        {"language": "en"},
        {"language": "en"},
    )

    assert result["status"] == "Not Observable"
    assert result["finding_count"] == 0


def test_standard_login_reports_unchanged_session_candidate(monkeypatch):
    set_login_page(monkeypatch)
    session = FakeSession(
        initial_cookies={"sessionid": "fixed-value"},
        cookies={"sessionid": "fixed-value"},
    )

    result = create_login_session(
        "credential-one",
        engagement(),
        "vault-secret-that-is-long-enough-for-tests",
        session_factory=lambda: session,
    )

    assert result["session_fixation"]["status"] == "Needs Attention"
    assert "fixed-value" not in str(result)


def test_get_login_form_is_rejected(monkeypatch):
    set_login_page(
        monkeypatch,
        LOGIN_HTML.replace('method="post"', 'method="get"'),
    )
    session = FakeSession()

    with pytest.raises(LoginSessionError, match="GET"):
        create_login_session(
            "credential-one", engagement(), "x" * 40,
            session_factory=lambda: session,
        )
    assert session.post_calls == []
    assert session.closed is True


def test_external_form_action_is_rejected(monkeypatch):
    set_login_page(
        monkeypatch,
        LOGIN_HTML.replace('/session', 'https://evil.example/session'),
    )
    session = FakeSession()

    with pytest.raises(LoginSessionError, match="outside"):
        create_login_session(
            "credential-one", engagement(), "x" * 40,
            session_factory=lambda: session,
        )
    assert session.post_calls == []


def test_ambiguous_login_forms_are_rejected(monkeypatch):
    set_login_page(monkeypatch, LOGIN_HTML + LOGIN_HTML)
    session = FakeSession()

    with pytest.raises(LoginSessionError, match="exactly one"):
        create_login_session(
            "credential-one", engagement(), "x" * 40,
            session_factory=lambda: session,
        )
    assert session.post_calls == []


def test_missing_session_cookie_is_not_called_success(monkeypatch):
    set_login_page(monkeypatch)
    session = FakeSession(cookies=[])

    with pytest.raises(LoginSessionError, match="No authenticated session cookie"):
        create_login_session(
            "credential-one", engagement(), "x" * 40,
            session_factory=lambda: session,
        )
    assert session.closed is True


def test_server_error_closes_session(monkeypatch):
    set_login_page(monkeypatch)
    session = FakeSession(post_status=500)

    with pytest.raises(LoginSessionError, match="server error"):
        create_login_session(
            "credential-one", engagement(), "x" * 40,
            session_factory=lambda: session,
        )
    assert session.closed is True


def test_session_deletion_is_engagement_bound(monkeypatch):
    set_login_page(monkeypatch)
    session = FakeSession()
    result = create_login_session(
        "credential-one", engagement(), "x" * 40,
        session_factory=lambda: session,
    )

    with pytest.raises(LoginSessionError, match="different engagement"):
        delete_login_session(result["session_id"], engagement("engagement-two"))

    deleted = delete_login_session(result["session_id"], engagement())
    assert deleted["deleted"] is True
    assert session.closed is True


def test_browser_session_is_volatile_and_does_not_return_cookie_secrets():
    result = create_browser_session(
        "sessionid=test-secret; preference=compact",
        browser_engagement(),
        ttl_seconds=900,
        now=1000,
    )

    assert result["status"] == "Browser Session Stored"
    assert result["cookie_count"] == 2
    assert result["cookie_names_returned"] is False
    assert result["cookie_values_returned"] is False
    assert "test-secret" not in str(result)

    session = get_login_session(
        result["session_id"],
        browser_engagement(),
        now=1001,
    )
    assert session.cookies.get(
        "sessionid", domain="example.com", path="/"
    ) == "test-secret"

    deleted = delete_login_session(
        result["session_id"],
        browser_engagement(),
    )
    assert deleted["deleted"] is True


@pytest.mark.parametrize(
    "cookie_header, message",
    [
        ("not-a-cookie", "name=value"),
        ("session=okay\r\nInjected: yes", "line breaks"),
        ("bad name=value", "name=value"),
        ("session=one; session=two", "repeats"),
    ],
)
def test_browser_session_rejects_unsafe_cookie_headers(cookie_header, message):
    with pytest.raises(LoginSessionError, match=message):
        create_browser_session(
            cookie_header,
            browser_engagement(),
            ttl_seconds=900,
        )


def test_browser_session_requires_researcher_owned_account():
    with pytest.raises(LoginSessionError, match="researcher-owned"):
        create_browser_session(
            "sessionid=test-secret",
            browser_engagement(researcher_owned_accounts_only=False),
            ttl_seconds=900,
        )
