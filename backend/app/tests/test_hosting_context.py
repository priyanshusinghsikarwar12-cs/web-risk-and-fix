import socket

from app.scanners.hosting_context import (
    check_hosting_context,
    classify_shared_infrastructure,
    detect_managed_provider,
)


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


def fake_resolver(*args, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("203.0.113.10", 443),
        ),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            6,
            "",
            ("2001:db8::10", 443, 0, 0),
        ),
    ]


def public_resolver(*args, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("93.184.216.34", 443),
        )
    ]


def test_cloudflare_is_detected_from_headers():
    provider = detect_managed_provider(
        {"Cf-Ray": "abc", "Server": "cloudflare"}
    )

    assert provider["name"] == "Cloudflare"
    assert provider["category"] == "CDN / reverse proxy"
    assert provider["confidence"] == "High"


def test_github_pages_is_detected():
    provider = detect_managed_provider(
        {
            "X-GitHub-Request-Id": "request-id",
            "Server": "GitHub.com",
        }
    )

    assert provider["name"] == "GitHub Pages"
    assert provider["confidence"] == "High"


def test_unknown_provider_is_not_guessed():
    provider = detect_managed_provider(
        {"Server": "nginx"}
    )

    assert provider["name"] is None
    assert provider["confidence"] == "None"


def test_managed_hosting_is_likely_shared():
    result = classify_shared_infrastructure(
        {
            "category": "Managed static hosting",
            "confidence": "High",
        }
    )

    assert result["status"] == "Likely Shared"


def test_cdn_is_described_as_shared_edge():
    result = classify_shared_infrastructure(
        {
            "category": "CDN / reverse proxy",
            "confidence": "High",
        }
    )

    assert result["status"] == "Shared Edge Observed"
    assert "origin" in result["message"].lower()


def test_unknown_hosting_does_not_claim_dedicated_server():
    result = classify_shared_infrastructure(
        {
            "category": "Not identified",
            "confidence": "None",
        }
    )

    assert result["status"] == "Not Determined"


def test_complete_result_contains_attribution_warning():
    result = check_hosting_context(
        "example.com",
        FakeResponse(
            {"Cf-Ray": "abc", "Server": "cloudflare"}
        ),
        resolver=public_resolver,
        reverse_lookup=lambda address: (
            "edge.example.net",
            [],
            [address],
        ),
    )

    assert result["provider"]["name"] == "Cloudflare"
    assert result["address_count"] == 1
    assert result["addresses"][0]["reverse_dns"] == (
        "edge.example.net"
    )
    assert "provider" in result["attribution_note"].lower()
    assert result["score_eligible"] is False


def test_private_or_documentation_addresses_are_not_reported():
    result = check_hosting_context(
        "example.com",
        FakeResponse({}),
        resolver=fake_resolver,
        reverse_lookup=lambda address: (address, [], [address]),
    )

    assert result["addresses"] == []
    assert result["shared_infrastructure"]["status"] == (
        "Not Determined"
    )


def test_standalone_scan_fetches_homepage_provider_evidence():
    result = check_hosting_context(
        "example.com",
        resolver=public_resolver,
        reverse_lookup=lambda address: (
            "edge.example.net",
            [],
            [address],
        ),
        fetcher=lambda url, timeout: FakeResponse({
            "Cf-Ray": "abc",
            "Server": "cloudflare",
        }),
    )

    assert result["provider"]["name"] == "Cloudflare"
    assert result["homepage_evidence_available"] is True
