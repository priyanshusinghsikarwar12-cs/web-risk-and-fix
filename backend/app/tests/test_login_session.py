import pytest

from app.services.login_session import (
    LoginSessionError,
    clear_login_sessions,
    create_login_session,
    delete_login_session,
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
    def __init__(self, name):
        self.name = name


class FakeResponse:
    def __init__(self, text="", url="https://example.com/login", status_code=200):
        self.text = text
        self.url = url
        self.status_code = status_code


class FakeSession:
    def __init__(self, cookies=None, post_status=302):
        cookie_names = ["sessionid"] if cookies is None else cookies
        self.cookies = [FakeCookie(name) for name in cookie_names]
        self.post_status = post_status
        self.post_calls = []
        self.closed = False

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
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
