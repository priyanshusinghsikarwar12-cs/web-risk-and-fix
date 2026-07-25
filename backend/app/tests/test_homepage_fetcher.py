import requests

from app.services.homepage_fetcher import (
    fetch_homepage,
)


class FakeResponse:
    status_code = 200
    url = "https://example.com/"


def test_successful_homepage_fetch(monkeypatch):
    response = FakeResponse()

    monkeypatch.setattr(
        "app.services.homepage_fetcher.safe_get",
        lambda url, timeout: response,
    )

    result = fetch_homepage("example.com")

    assert result["response"] is response
    assert result["response_time_ms"] >= 0
    assert result["error"] is None


def test_failed_homepage_fetch_is_controlled(
    monkeypatch,
):
    def failed_request(url, timeout):
        raise requests.ConnectionError(
            "Connection failed"
        )

    monkeypatch.setattr(
        "app.services.homepage_fetcher.safe_get",
        failed_request,
    )

    result = fetch_homepage("example.com")

    assert result["response"] is None
    assert result["response_time_ms"] is None
    assert result["error_type"] == "ConnectionError"


def test_homepage_fetch_uses_https(monkeypatch):
    captured = {}

    def capture_url(url, timeout):
        captured["url"] = url
        return FakeResponse()

    monkeypatch.setattr(
        "app.services.homepage_fetcher.safe_get",
        capture_url,
    )

    fetch_homepage("example.com")

    assert captured["url"] == "https://example.com"


def test_certificate_failure_retries_read_only_without_trust(
    monkeypatch,
):
    response = FakeResponse()
    calls = []

    def certificate_then_page(url, timeout, verify_tls=True):
        calls.append(verify_tls)
        if verify_tls:
            raise requests.exceptions.SSLError(
                "certificate has expired"
            )
        response.webshield_tls_verified = False
        return response

    monkeypatch.setattr(
        "app.services.homepage_fetcher.safe_get",
        certificate_then_page,
    )

    result = fetch_homepage("example.com")

    assert calls == [True, False]
    assert result["response"] is response
    assert result["tls_verified"] is False
    assert "expired" in result["tls_error"]
