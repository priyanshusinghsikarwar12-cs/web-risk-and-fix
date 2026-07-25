import pytest
import requests

from app.utils.safe_http import (
    UnsafeTargetError,
    safe_get,
    safe_post_json,
    safe_get_once,
)


class FakeResponse:
    def __init__(
        self,
        url,
        status_code=200,
        location=None,
        content=b"hello",
    ):
        self.url = url
        self.status_code = status_code
        self.headers = {}

        self.original_content = content
        self._content = content
        self._content_consumed = True

        if location:
            self.headers["Location"] = location

    @property
    def content(self):
        return self._content

    def iter_content(self, chunk_size):
        yield self.original_content

    def close(self):
        pass


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)

    def get(self, *args, **kwargs):
        return self.responses.pop(0)

    def post(self, *args, **kwargs):
        return self.responses.pop(0)


class RecordingSession(FakeSession):
    def __init__(self, responses):
        super().__init__(responses)
        self.get_options = []

    def get(self, *args, **kwargs):
        self.get_options.append(kwargs)
        return super().get(*args, **kwargs)


def allow_example_domains(url):
    if "127.0.0.1" in url:
        raise UnsafeTargetError("Unsafe private address")


def test_safe_response_is_returned(monkeypatch):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )

    session = FakeSession(
        [FakeResponse("https://example.com")]
    )

    response = safe_get(
        "https://example.com",
        session=session,
    )

    assert response.status_code == 200


def test_owner_controlled_request_can_preserve_invalid_tls_evidence(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )
    session = RecordingSession([
        FakeResponse("https://example.com")
    ])

    response = safe_get(
        "https://example.com",
        session=session,
        verify_tls=False,
    )

    assert session.get_options[0]["verify"] is False
    assert response.webshield_tls_verified is False


def test_private_redirect_is_blocked(monkeypatch):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )

    session = FakeSession(
        [
            FakeResponse(
                "https://example.com",
                status_code=302,
                location="http://127.0.0.1/admin",
            )
        ]
    )

    with pytest.raises(UnsafeTargetError):
        safe_get(
            "https://example.com",
            session=session,
        )


def test_public_redirect_is_followed(monkeypatch):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )

    session = FakeSession(
        [
            FakeResponse(
                "https://example.com",
                status_code=302,
                location="https://www.example.com",
            ),
            FakeResponse(
                "https://www.example.com",
                status_code=200,
            ),
        ]
    )

    response = safe_get(
        "https://example.com",
        session=session,
    )

    assert response.url == "https://www.example.com"


def test_approved_host_lock_blocks_public_third_party_redirect(monkeypatch):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )
    session = FakeSession([
        FakeResponse(
            "https://example.com",
            status_code=302,
            location="https://external.example.net/landing",
        )
    ])

    with pytest.raises(UnsafeTargetError, match="approved hostname"):
        safe_get(
            "https://example.com",
            session=session,
            allowed_redirect_host="example.com",
        )

    assert session.responses == []


def test_same_host_redirect_honors_request_pacing(monkeypatch):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )
    delays = []
    monkeypatch.setattr("app.utils.safe_http.time.sleep", delays.append)
    session = FakeSession([
        FakeResponse(
            "https://example.com",
            status_code=302,
            location="https://example.com/login",
        ),
        FakeResponse("https://example.com/login"),
    ])

    safe_get(
        "https://example.com",
        session=session,
        allowed_redirect_host="example.com",
        redirect_delay_seconds=0.5,
    )

    assert delays == [0.5]


def test_large_response_is_limited(monkeypatch):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )

    session = FakeSession(
        [
            FakeResponse(
                "https://example.com",
                content=b"a" * 100,
            )
        ]
    )

    response = safe_get(
        "https://example.com",
        max_bytes=10,
        session=session,
    )

    assert len(response.content) == 10
    assert response.webshield_content_truncated is True


def test_safe_json_post_is_bounded_and_does_not_follow_redirects(monkeypatch):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )
    response = safe_post_json(
        "https://example.com/api/getProfile",
        {"locale": "en-IN"},
        max_bytes=10,
        session=FakeSession([
            FakeResponse(
                "https://example.com/api/getProfile",
                content=b"a" * 100,
            )
        ]),
        allowed_host="example.com",
    )
    assert len(response.content) == 10
    assert response.webshield_content_truncated is True

    with pytest.raises(UnsafeTargetError, match="redirected"):
        safe_post_json(
            "https://example.com/api/getProfile",
            {},
            session=FakeSession([
                FakeResponse(
                    "https://example.com/api/getProfile",
                    status_code=302,
                    location="https://example.com/login",
                )
            ]),
            allowed_host="example.com",
        )


def test_safe_get_once_returns_redirect_without_following(monkeypatch):
    monkeypatch.setattr(
        "app.utils.safe_http.validate_request_url",
        allow_example_domains,
    )
    session = FakeSession([
        FakeResponse(
            "https://example.com/start",
            status_code=302,
            location="https://webshield.invalid/marker",
        )
    ])
    response = safe_get_once(
        "https://example.com/start",
        session=session,
        allowed_host="example.com",
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "https://webshield.invalid/marker"
    assert session.responses == []
