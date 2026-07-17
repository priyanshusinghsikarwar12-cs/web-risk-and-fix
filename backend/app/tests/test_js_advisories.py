import json

import requests

from app.deep_scanners.js_advisories import (
    extract_versioned_packages,
    match_javascript_advisories,
    normalize_package_name,
    query_osv_package,
)


def inventory_with_library(
    name,
    version,
    confidence="High",
):
    return {
        "checks": [{
            "url": (
                f"https://cdn.example.com/"
                f"{name}-{version}.js"
            ),
            "library": {
                "name": name,
                "version": version,
                "confidence": confidence,
                "evidence": "Test evidence",
            },
        }],
    }


def test_package_name_is_mapped():
    assert normalize_package_name(
        "Moment.js"
    ) == "moment"

    assert normalize_package_name(
        "React DOM"
    ) == "react-dom"


def test_high_confidence_version_is_eligible():
    result = extract_versioned_packages(
        inventory_with_library(
            "jQuery",
            "3.6.0",
        )
    )

    assert len(result["packages"]) == 1
    assert result["packages"][0][
        "package"
    ] == "jquery"


def test_low_confidence_version_is_skipped():
    result = extract_versioned_packages(
        inventory_with_library(
            "jQuery",
            "3.6.0",
            confidence="Low",
        )
    )

    assert result["packages"] == []
    assert result["skipped_count"] == 1


def test_missing_version_is_skipped():
    result = extract_versioned_packages({
        "checks": [{
            "url": "https://example.com/jquery.js",
            "library": {
                "name": "jQuery",
                "version": None,
                "confidence": "High",
            },
        }],
    })

    assert result["packages"] == []


def test_duplicate_package_is_queried_once():
    inventory = {
        "checks": [
            inventory_with_library(
                "jQuery",
                "3.6.0",
            )["checks"][0],
            inventory_with_library(
                "jQuery",
                "3.6.0",
            )["checks"][0],
        ],
    }

    result = extract_versioned_packages(
        inventory
    )

    assert len(result["packages"]) == 1


def test_vulnerability_match_is_reported():
    def fake_query(package, version):
        return [{
            "id": "GHSA-test-1234",
            "aliases": ["CVE-2026-0001"],
            "summary": "Test vulnerability",
            "references": [{
                "url": (
                    "https://example.org/advisory"
                ),
            }],
        }]

    result = match_javascript_advisories(
        inventory_with_library(
            "jQuery",
            "3.6.0",
        ),
        query_function=fake_query,
    )

    assert result["status"] == "Needs Attention"
    assert (
        result["vulnerability_match_count"]
        == 1
    )
    assert result["checks"][0][
        "vulnerability"
    ]["id"] == "GHSA-test-1234"


def test_no_match_is_not_observed():
    result = match_javascript_advisories(
        inventory_with_library(
            "Bootstrap",
            "5.3.0",
        ),
        query_function=lambda package, version: [],
    )

    assert result["status"] == "Not Observed"


def test_provider_error_becomes_partial():
    def failed_query(package, version):
        raise requests.RequestException(
            "Provider unavailable"
        )

    result = match_javascript_advisories(
        inventory_with_library(
            "Axios",
            "1.5.0",
        ),
        query_function=failed_query,
    )

    assert result["status"] == "Partial"
    assert result["provider_error_count"] == 1


class FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self.payload = json.dumps(
            payload
        ).encode("utf-8")
        self.closed = False

    def iter_content(self, chunk_size):
        yield self.payload

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, payload):
        self.response = FakeResponse(payload)
        self.request_json = None

    def post(self, url, **kwargs):
        self.request_json = kwargs["json"]
        return self.response


def test_osv_query_uses_exact_npm_version():
    session = FakeSession({
        "vulns": [{
            "id": "GHSA-test",
        }],
    })

    result = query_osv_package(
        "jquery",
        "3.6.0",
        session=session,
    )

    assert len(result) == 1
    assert session.request_json == {
        "package": {
            "name": "jquery",
            "ecosystem": "npm",
        },
        "version": "3.6.0",
    }
    assert session.response.closed is True