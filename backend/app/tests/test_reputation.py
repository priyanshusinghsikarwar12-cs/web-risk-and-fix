from urllib.parse import parse_qs, urlparse

from app.scanners.reputation import (
    analyze_web_risk_response,
    build_web_risk_url,
    check_website_reputation,
)


class FakeResponse:
    def __init__(
        self,
        data,
        status_code=200,
        truncated=False,
    ):
        self.data = data
        self.status_code = status_code
        self.webshield_content_truncated = truncated

    def json(self):
        return self.data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("Request failed")


def test_missing_api_key_is_not_configured(
    monkeypatch,
):
    monkeypatch.delenv(
        "WEBRISK_API_KEY",
        raising=False,
    )

    result = check_website_reputation(
        "example.com"
    )

    assert result["status"] == "Not Configured"
    assert result["checks"] == []


def test_builds_web_risk_lookup_url():
    result = build_web_risk_url(
        "example.com",
        "test-key",
    )

    parsed_url = urlparse(result)
    query = parse_qs(parsed_url.query)

    assert parsed_url.netloc == (
        "webrisk.googleapis.com"
    )
    assert query["uri"] == [
        "https://example.com/"
    ]
    assert query["key"] == ["test-key"]
    assert len(query["threatTypes"]) == 3


def test_empty_response_means_no_known_threats():
    result = analyze_web_risk_response(
        {},
        "example.com",
    )

    assert result["status"] == "No Known Threats"
    assert result["threat_types"] == []
    assert "does not prove" in result["message"]


def test_malware_response_is_detected():
    result = analyze_web_risk_response(
        {
            "threat": {
                "threatTypes": ["MALWARE"],
                "expireTime": (
                    "2026-07-20T10:00:00Z"
                ),
            }
        },
        "example.com",
    )

    assert result["status"] == "Threat Detected"
    assert result["threat_types"] == ["MALWARE"]
    assert result["checks"][0]["name"] == "Malware"


def test_multiple_threat_types_are_preserved():
    result = analyze_web_risk_response(
        {
            "threat": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                ]
            }
        },
        "example.com",
    )

    assert result["status"] == "Threat Detected"
    assert len(result["checks"]) == 2


def test_live_lookup_uses_provider_response(
    monkeypatch,
):
    def fake_safe_get(
        url,
        timeout,
        max_bytes,
    ):
        return FakeResponse({})

    monkeypatch.setattr(
        "app.scanners.reputation.safe_get",
        fake_safe_get,
    )

    result = check_website_reputation(
        "example.com",
        api_key="test-key",
    )

    assert result["status"] == "No Known Threats"
    assert result["provider"] == "Google Web Risk"


def test_rejected_credentials_are_reported(
    monkeypatch,
):
    def fake_safe_get(
        url,
        timeout,
        max_bytes,
    ):
        return FakeResponse(
            {},
            status_code=403,
        )

    monkeypatch.setattr(
        "app.scanners.reputation.safe_get",
        fake_safe_get,
    )

    result = check_website_reputation(
        "example.com",
        api_key="bad-key",
    )

    assert result["status"] == (
        "Configuration Error"
    )