import pytest
import requests

from app.utils.safe_http import (
    UnsafeTargetError,
    safe_get,
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