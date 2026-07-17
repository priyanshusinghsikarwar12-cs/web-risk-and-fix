from app.scanners.rdap import (
    analyze_rdap_domain,
    build_rdap_domain_url,
    check_domain_registration,
    find_rdap_server,
)

from datetime import datetime, timezone

from app.scanners.rdap import analyze_rdap_domain


TEST_NOW = datetime(
    2026,
    7,
    15,
    tzinfo=timezone.utc,
)


def make_rdap_data(expiration_date=None):
    events = [
        {
            "eventAction": "registration",
            "eventDate": "2020-01-10T10:00:00Z",
        },
        {
            "eventAction": "last changed",
            "eventDate": "2026-01-01T12:00:00Z",
        },
    ]

    if expiration_date:
        events.append({
            "eventAction": "expiration",
            "eventDate": expiration_date,
        })

    return {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "events": events,
    }


def test_domain_with_safe_expiry_is_healthy():
    result = analyze_rdap_domain(
        make_rdap_data("2027-07-15T00:00:00Z"),
        now=TEST_NOW,
    )

    assert result["status"] == "Healthy"
    assert result["days_left"] == 365
    assert result["confidence"] == "High"


def test_domain_expiring_within_90_days_requires_review():
    result = analyze_rdap_domain(
        make_rdap_data("2026-09-13T00:00:00Z"),
        now=TEST_NOW,
    )

    assert result["status"] == "Review"
    assert result["days_left"] == 60


def test_domain_expiring_within_30_days_needs_attention():
    result = analyze_rdap_domain(
        make_rdap_data("2026-07-25T00:00:00Z"),
        now=TEST_NOW,
    )

    assert result["status"] == "Needs Attention"
    assert result["days_left"] == 10


def test_expired_domain_is_reported():
    result = analyze_rdap_domain(
        make_rdap_data("2026-07-10T00:00:00Z"),
        now=TEST_NOW,
    )

    assert result["status"] == "Expired"
    assert result["days_left"] == -5


def test_missing_expiration_is_not_guessed():
    result = analyze_rdap_domain(
        make_rdap_data(),
        now=TEST_NOW,
    )

    assert result["status"] == "Unknown"
    assert result["days_left"] is None
    assert result["confidence"] == "Limited"


def test_invalid_expiration_date_is_not_guessed():
    result = analyze_rdap_domain(
        make_rdap_data("not-a-valid-date"),
        now=TEST_NOW,
    )

    assert result["status"] == "Unknown"
    assert result["expiration_date"] is None

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
            raise RuntimeError("HTTP request failed")


def test_finds_official_rdap_server():
    bootstrap_data = {
        "services": [
            [
                ["com", "net"],
                ["https://rdap.example.test/v1/"],
            ]
        ]
    }

    result = find_rdap_server(
        "example.com",
        bootstrap_data,
    )

    assert result == "https://rdap.example.test/v1/"


def test_unknown_extension_has_no_rdap_server():
    result = find_rdap_server(
        "example.unknown",
        {"services": []},
    )

    assert result is None


def test_builds_domain_lookup_url():
    result = build_rdap_domain_url(
        "https://rdap.example.test/v1/",
        "example.com",
    )

    assert result == (
        "https://rdap.example.test/v1/domain/example.com"
    )


def test_live_lookup_uses_bootstrap_server(monkeypatch):
    bootstrap_data = {
        "services": [
            [
                ["com"],
                ["https://rdap.example.test/v1/"],
            ]
        ]
    }

    rdap_data = make_rdap_data(
        "2027-07-15T00:00:00Z"
    )

    responses = iter([
        FakeResponse(bootstrap_data),
        FakeResponse(rdap_data),
    ])

    requested_urls = []

    def fake_safe_get(url, timeout):
        requested_urls.append(url)
        return next(responses)

    monkeypatch.setattr(
        "app.scanners.rdap.safe_get",
        fake_safe_get,
    )

    result = check_domain_registration("example.com")

    assert result["status"] == "Healthy"
    assert result["rdap_server"] == (
        "https://rdap.example.test/v1/"
    )

    assert requested_urls == [
        "https://data.iana.org/rdap/dns.json",
        (
            "https://rdap.example.test/"
            "v1/domain/example.com"
        ),
    ]


def test_missing_registry_server_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.rdap.safe_get",
        lambda url, timeout: FakeResponse({
            "services": [],
        }),
    )

    result = check_domain_registration(
        "example.unknown"
    )

    assert result["status"] == "Unavailable"
    assert result["days_left"] is None