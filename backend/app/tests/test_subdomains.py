import json

import dns.resolver

from app.deep_scanners.subdomains import (
    discover_subdomains,
    extract_certificate_names,
    resolve_dns_records,
)


class FakeDnsAnswer:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class FakeResolver:
    def __init__(self, records=None):
        self.records = records or {}

    def resolve(self, hostname, record_type):
        values = self.records.get(
            (hostname, record_type)
        )

        if not values:
            raise dns.resolver.NoAnswer()

        return [
            FakeDnsAnswer(value)
            for value in values
        ]


class FakeHttpResponse:
    def __init__(
        self,
        records,
        status_code=200,
    ):
        self.status_code = status_code
        self.content = json.dumps(
            records
        ).encode("utf-8")
        self.webshield_content_truncated = False


def test_extracts_multiline_certificate_names():
    records = [{
        "name_value": (
            "www.example.com\n"
            "api.example.com"
        ),
    }]

    result = extract_certificate_names(
        records,
        "example.com",
    )

    assert result == [
        "api.example.com",
        "www.example.com",
    ]


def test_removes_wildcard_prefix():
    records = [{
        "name_value": "*.shop.example.com",
    }]

    result = extract_certificate_names(
        records,
        "example.com",
    )

    assert result == [
        "shop.example.com"
    ]


def test_rejects_names_outside_parent():
    records = [{
        "name_value": (
            "example.net\n"
            "fakeexample.com"
        ),
    }]

    result = extract_certificate_names(
        records,
        "example.com",
    )

    assert result == []


def test_deduplicates_names():
    records = [
        {"name_value": "www.example.com"},
        {"common_name": "www.example.com"},
    ]

    result = extract_certificate_names(
        records,
        "example.com",
    )

    assert result == [
        "www.example.com"
    ]


def test_dns_records_are_confirmed():
    resolver = FakeResolver({
        ("www.example.com", "A"): [
            "203.0.113.10",
        ],
        ("www.example.com", "CNAME"): [
            "target.example.net.",
        ],
    })

    result = resolve_dns_records(
        "www.example.com",
        resolver,
    )

    assert result["A"] == [
        "203.0.113.10"
    ]
    assert result["CNAME"] == [
        "target.example.net"
    ]


def test_missing_dns_returns_empty_result():
    result = resolve_dns_records(
        "missing.example.com",
        FakeResolver(),
    )

    assert result == {}


def test_full_discovery_confirms_dns(
    monkeypatch,
):
    certificate_records = [{
        "name_value": (
            "www.example.com\n"
            "old.example.com"
        ),
    }]

    monkeypatch.setattr(
        "app.deep_scanners.subdomains.safe_get",
        lambda url, timeout, max_bytes: (
            FakeHttpResponse(
                certificate_records
            )
        ),
    )

    monkeypatch.setattr(
        "app.deep_scanners.subdomains."
        "secrets.token_hex",
        lambda length: "fixed",
    )

    resolver = FakeResolver({
        ("www.example.com", "A"): [
            "203.0.113.10",
        ],
    })

    result = discover_subdomains(
        "example.com",
        resolver=resolver,
    )

    assert result["status"] == "Completed"
    assert result["discovered_count"] == 2
    assert result["dns_confirmed_count"] == 1
    assert result["checks"][0]["hostname"] == (
        "old.example.com"
    )
    assert result["checks"][1]["status"] == (
        "DNS Confirmed"
    )


def test_invalid_provider_response_is_safe(
    monkeypatch,
):
    class InvalidResponse:
        status_code = 200
        content = b"not-json"
        webshield_content_truncated = False

    monkeypatch.setattr(
        "app.deep_scanners.subdomains.safe_get",
        lambda url, timeout, max_bytes: (
            InvalidResponse()
        ),
    )

    result = discover_subdomains(
        "example.com",
        resolver=FakeResolver(),
    )

    assert result["status"] == "Unavailable"
    assert result["checks"] == []