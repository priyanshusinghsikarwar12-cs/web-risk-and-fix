import requests

from app.source_scanners.dependency_advisories import (
    DependencyAdvisoryError,
    OsvClient,
    check_dependency_advisories,
)


PACKAGE = {
    "ecosystem": "PyPI",
    "name": "jinja2",
    "version": "2.4.1",
    "path": "requirements.txt",
    "direct": True,
    "scope": "runtime",
}


class FakeClient:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.received = None

    def query(self, packages):
        self.received = packages
        if self.error:
            raise self.error
        return self.result


class FakeResponse:
    def __init__(self, payload, status_code=200):
        import json

        self.content = json.dumps(payload).encode("utf-8")
        self.status_code = status_code
        self.headers = {"Content-Length": str(len(self.content))}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def iter_content(self, chunk_size=65_536):
        yield self.content

    def close(self):
        pass


class FakeSession:
    def __init__(self, batch_payload, detail_payload):
        self.batch_payload = batch_payload
        self.detail_payload = detail_payload
        self.post_kwargs = None

    def post(self, url, **kwargs):
        self.post_kwargs = {"url": url, **kwargs}
        return FakeResponse(self.batch_payload)

    def get(self, url, **kwargs):
        return FakeResponse(self.detail_payload)


def advisory_result():
    return {
        "matches": [(PACKAGE, "GHSA-test-1234")],
        "details": {
            "GHSA-test-1234": {
                "id": "GHSA-test-1234",
                "summary": "Template sandbox escape",
                "aliases": ["CVE-2026-1234"],
                "database_specific": {"severity": "HIGH"},
                "affected": [{
                    "package": {
                        "ecosystem": "PyPI",
                        "name": "jinja2",
                    },
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.4.2"},
                        ],
                    }],
                }],
                "references": [{
                    "type": "ADVISORY",
                    "url": "https://osv.dev/vulnerability/GHSA-test-1234",
                }],
            }
        },
        "detail_errors": [],
        "results_limited": False,
    }


def test_known_vulnerability_becomes_prioritized_finding():
    client = FakeClient(advisory_result())
    result = check_dependency_advisories([PACKAGE], client=client)

    assert result["status"] == "Completed"
    assert result["vulnerabilities_found"] == 1
    finding = result["findings"][0]
    assert finding["severity"] == "High"
    assert finding["confidence"] == "High"
    assert finding["advisory"]["fixed_versions"] == ["2.4.2"]
    assert finding["package"]["version"] == "2.4.1"
    assert "Template sandbox escape" in finding["title"]


def test_alias_records_are_merged_into_one_vulnerability_group():
    result_data = advisory_result()
    second_id = "PYSEC-2026-1234"
    result_data["matches"].append((PACKAGE, second_id))
    result_data["details"][second_id] = {
        **result_data["details"]["GHSA-test-1234"],
        "id": second_id,
        "aliases": ["GHSA-test-1234", "CVE-2026-1234"],
    }

    result = check_dependency_advisories(
        [PACKAGE], client=FakeClient(result_data)
    )

    assert result["vulnerabilities_found"] == 1
    assert result["advisory_records_matched"] == 2
    assert result["duplicate_records_merged"] == 1
    assert result["findings"][0]["advisory"]["ids"] == [
        "GHSA-test-1234",
        second_id,
    ]


def test_only_minimum_package_coordinates_are_shared():
    client = FakeClient(advisory_result())
    result = check_dependency_advisories([PACKAGE], client=client)

    assert result["data_shared"] == [
        "package ecosystem", "package name", "exact version"
    ]
    assert "content" not in str(client.received)


def test_service_failure_never_claims_clean_result():
    client = FakeClient(error=requests.Timeout("offline"))
    result = check_dependency_advisories([PACKAGE], client=client)

    assert result["status"] == "Unavailable"
    assert result["packages_checked"] == 0
    assert "No clean result" in result["message"]


def test_missing_advisory_severity_uses_disclosed_fallback():
    result_data = advisory_result()
    result_data["details"]["GHSA-test-1234"].pop("database_specific")
    client = FakeClient(result_data)

    result = check_dependency_advisories([PACKAGE], client=client)
    finding = result["findings"][0]

    assert finding["severity"] == "Medium"
    assert finding["advisory"]["severity_source"] == (
        "WebShield conservative fallback"
    )


def test_missing_detail_makes_scan_partial():
    result_data = advisory_result()
    result_data["details"] = {}
    client = FakeClient(result_data)

    result = check_dependency_advisories([PACKAGE], client=client)

    assert result["status"] == "Partial"
    assert result["vulnerabilities_found"] == 0
    assert result["unresolved_advisory_details"] == 1


def test_empty_inventory_is_not_applicable():
    result = check_dependency_advisories([])

    assert result["status"] == "Not Applicable"
    assert result["packages_checked"] == 0


def test_osv_client_sends_only_expected_query_fields():
    session = FakeSession(
        {"results": [{"vulns": [{"id": "GHSA-test-1234"}]}]},
        {"id": "GHSA-test-1234", "summary": "Test advisory"},
    )
    client = OsvClient(session=session)

    result = client.query([PACKAGE])

    query = session.post_kwargs["json"]["queries"][0]
    assert query == {
        "package": {"ecosystem": "PyPI", "name": "jinja2"},
        "version": "2.4.1",
    }
    assert result["details"]["GHSA-test-1234"]["id"] == (
        "GHSA-test-1234"
    )


def test_osv_client_rejects_misaligned_batch_response():
    session = FakeSession({"results": []}, {})
    client = OsvClient(session=session)

    import pytest

    with pytest.raises(DependencyAdvisoryError, match="did not match"):
        client.query([PACKAGE])
