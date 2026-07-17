from fastapi.testclient import TestClient
from app.main import app
from app.services.domain_verification import (
    create_authorization_receipt,
)


client = TestClient(app)


def test_home_endpoint_returns_success():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Welcome to WebShield"
    }


def test_scan_endpoint_returns_report(monkeypatch):
    def fake_scan(
        domain,
        dkim_selector=None,
    ):
        return {
            "domain": domain,
            "scan_status": "Complete",
            "overall_status": "Good",
            "score": 80,
        }

    monkeypatch.setattr(
        "app.main.run_full_scan",
        fake_scan,
    )

    response = client.get(
        "/scan",
        params={"domain": "example.com"},
    )

    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert response.json()["scan_status"] == "Complete"
    assert response.json()["score"] == 80


def test_scan_rejects_localhost():
    response = client.get(
        "/scan",
        params={"domain": "localhost"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Local or internal websites cannot be scanned."
    )


def test_scan_requires_domain():
    response = client.get("/scan")

    assert response.status_code == 422

def test_scan_passes_dkim_selector(monkeypatch):
    received_values = {}

    def fake_scan(
        domain,
        dkim_selector=None,
    ):
        received_values["domain"] = domain
        received_values["selector"] = dkim_selector

        return {
            "domain": domain,
            "scan_status": "Complete",
            "dkim": {
                "status": "Configured",
                "selector": dkim_selector,
            },
        }

    monkeypatch.setattr(
        "app.main.run_full_scan",
        fake_scan,
    )

    response = client.get(
        "/scan",
        params={
            "domain": "example.com",
            "dkim_selector": "Selector1",
        },
    )

    assert response.status_code == 200
    assert received_values["domain"] == "example.com"
    assert received_values["selector"] == "selector1"
    assert response.json()["dkim"]["status"] == (
        "Configured"
    )


def test_scan_rejects_invalid_dkim_selector():
    response = client.get(
        "/scan",
        params={
            "domain": "example.com",
            "dkim_selector": "../invalid selector",
        },
    )

    assert response.status_code == 400
    assert "selector" in response.json()["detail"].lower()  

TEST_VERIFICATION_SECRET = (
    "test-verification-secret-that-has-more-than-32-characters"
)


def test_verification_requires_server_secret(
    monkeypatch,
):
    monkeypatch.delenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        raising=False,
    )

    response = client.post(
        "/verification/challenge",
        json={"domain": "example.com"},
    )

    assert response.status_code == 503


def test_verification_challenge_is_created(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/verification/challenge",
        json={"domain": "example.com"},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["domain"] == "example.com"
    assert result["dns_record_type"] == "TXT"
    assert result["token"].startswith("ws1.")


def test_dns_verification_endpoint(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    monkeypatch.setattr(
        "app.main.verify_dns_proof",
        lambda domain, token, secret: {
            "domain": domain,
            "method": "DNS TXT",
            "verified": True,
            "status": "Verified",
        },
    )

    response = client.post(
        "/verification/check",
        json={
            "domain": "example.com",
            "token": "ws1.test.token",
            "method": "dns",
        },
    )

    assert response.status_code == 200
    assert response.json()["verified"] is True
    assert response.json()["method"] == "DNS TXT"


def test_invalid_verification_method_is_rejected(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/verification/check",
        json={
            "domain": "example.com",
            "token": "ws1.test.token",
            "method": "unsupported",
        },
    )

    assert response.status_code == 422   

def test_deep_scan_rejects_missing_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/access-check",
        json={"domain": "example.com"},
    )

    assert response.status_code == 401


def test_deep_scan_rejects_invalid_header(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/access-check",
        json={"domain": "example.com"},
        headers={
            "Authorization": "Invalid receipt",
        },
    )

    assert response.status_code == 401


def test_deep_scan_rejects_invalid_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/access-check",
        json={"domain": "example.com"},
        headers={
            "Authorization": "Bearer invalid-receipt",
        },
    )

    assert response.status_code == 403


def test_deep_scan_accepts_valid_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/access-check",
        json={"domain": "example.com"},
        headers={
            "Authorization": (
                f"Bearer {authorization['receipt']}"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["authorized"] is True
    assert response.json()["domain"] == "example.com"
    assert response.json()["scope"] == [
        "example.com"
    ]   

def test_crawler_endpoint_requires_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/crawl",
        json={
            "domain": "example.com",
            "max_pages": 10,
            "max_depth": 1,
        },
    )

    assert response.status_code == 401


def test_authorized_crawler_endpoint_runs(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    received = {}

    def fake_crawler(
        domain,
        max_pages,
        max_depth,
        delay_seconds,
    ):
        received["domain"] = domain
        received["max_pages"] = max_pages
        received["max_depth"] = max_depth
        received["delay_seconds"] = delay_seconds

        return {
            "name": "Verified Application Crawler",
            "domain": domain,
            "status": "Completed",
            "pages_scanned": 3,
        }

    monkeypatch.setattr(
        "app.main.crawl_verified_site",
        fake_crawler,
    )

    response = client.post(
        "/deep-scan/crawl",
        json={
            "domain": "example.com",
            "max_pages": 10,
            "max_depth": 1,
        },
        headers={
            "Authorization": (
                f"Bearer {authorization['receipt']}"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["pages_scanned"] == 3
    assert received["domain"] == "example.com"
    assert received["max_pages"] == 10
    assert received["max_depth"] == 1
    assert received["delay_seconds"] == 0.2


def test_crawler_rejects_excessive_limits():
    response = client.post(
        "/deep-scan/crawl",
        json={
            "domain": "example.com",
            "max_pages": 5000,
            "max_depth": 20,
        },
    )

    assert response.status_code == 422 

def test_exposure_endpoint_requires_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/exposures",
        json={"domain": "example.com"},
    )

    assert response.status_code == 401


def test_authorized_exposure_endpoint_runs(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    received = {}

    def fake_exposure_check(
        domain,
        delay_seconds,
    ):
        received["domain"] = domain
        received["delay_seconds"] = delay_seconds

        return {
            "name": "Sensitive Exposure Checks",
            "domain": domain,
            "status": "Not Observed",
            "finding_count": 0,
        }

    monkeypatch.setattr(
        "app.main.check_sensitive_exposures",
        fake_exposure_check,
    )

    response = client.post(
        "/deep-scan/exposures",
        json={"domain": "example.com"},
        headers={
            "Authorization": (
                f"Bearer {authorization['receipt']}"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["finding_count"] == 0
    assert received["domain"] == "example.com"
    assert received["delay_seconds"] == 0.15  

def test_subdomain_endpoint_requires_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/subdomains",
        json={"domain": "example.com"},
    )

    assert response.status_code == 401


def test_authorized_subdomain_endpoint_runs(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    monkeypatch.setattr(
        "app.main.discover_subdomains",
        lambda domain: {
            "name": "Subdomain Discovery",
            "domain": domain,
            "status": "Completed",
            "discovered_count": 2,
            "dns_confirmed_count": 1,
            "checks": [],
        },
    )

    response = client.post(
        "/deep-scan/subdomains",
        json={"domain": "example.com"},
        headers={
            "Authorization": (
                f"Bearer {authorization['receipt']}"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert response.json()["discovered_count"] == 2             

def test_port_endpoint_requires_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/ports",
        json={"domain": "example.com"},
    )

    assert response.status_code == 401


def test_authorized_port_endpoint_runs(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    received = {}

    def fake_port_scan(
        domain,
        timeout,
        max_workers,
    ):
        received["domain"] = domain
        received["timeout"] = timeout
        received["max_workers"] = max_workers

        return {
            "name": "Open Ports and Services",
            "domain": domain,
            "status": "Observed",
            "open_port_count": 2,
            "checks": [],
        }

    monkeypatch.setattr(
        "app.main.scan_open_ports",
        fake_port_scan,
    )

    response = client.post(
        "/deep-scan/ports",
        json={"domain": "example.com"},
        headers={
            "Authorization": (
                f"Bearer {authorization['receipt']}"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["open_port_count"] == 2
    assert received["domain"] == "example.com"
    assert received["timeout"] == 0.75
    assert received["max_workers"] == 20    

def test_js_advisory_endpoint_requires_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/js-advisories",
        json={"domain": "example.com"},
    )

    assert response.status_code == 401


def test_authorized_js_advisory_endpoint_runs(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    monkeypatch.setattr(
        "app.main.check_javascript_advisories",
        lambda domain: {
            "name": (
                "JavaScript Known Vulnerabilities"
            ),
            "domain": domain,
            "status": "Not Observed",
            "vulnerability_match_count": 0,
            "checks": [],
        },
    )

    response = client.post(
        "/deep-scan/js-advisories",
        json={"domain": "example.com"},
        headers={
            "Authorization": (
                f"Bearer {authorization['receipt']}"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert (
        response.json()[
            "vulnerability_match_count"
        ]
        == 0
    )

def test_zap_endpoint_requires_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/zap-baseline",
        json={
            "domain": "example.com",
            "spider_minutes": 1,
            "maximum_minutes": 5,
        },
    )

    assert response.status_code == 401


def test_authorized_zap_endpoint_runs(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    received = {}

    def fake_zap_scan(
        domain,
        spider_minutes,
        maximum_minutes,
    ):
        received["domain"] = domain
        received["spider_minutes"] = (
            spider_minutes
        )
        received["maximum_minutes"] = (
            maximum_minutes
        )

        return {
            "name": "OWASP ZAP Baseline",
            "domain": domain,
            "status": "Not Observed",
            "finding_count": 0,
            "checks": [],
            "active_attack_payloads": False,
        }

    monkeypatch.setattr(
        "app.main.run_zap_baseline",
        fake_zap_scan,
    )

    response = client.post(
        "/deep-scan/zap-baseline",
        json={
            "domain": "example.com",
            "spider_minutes": 1,
            "maximum_minutes": 5,
        },
        headers={
            "Authorization": (
                f"Bearer {authorization['receipt']}"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["domain"] == (
        "example.com"
    )
    assert response.json()["finding_count"] == 0
    assert (
        response.json()[
            "active_attack_payloads"
        ]
        is False
    )

    assert received["domain"] == "example.com"
    assert received["spider_minutes"] == 1
    assert received["maximum_minutes"] == 5


def test_zap_endpoint_rejects_excessive_limits():
    response = client.post(
        "/deep-scan/zap-baseline",
        json={
            "domain": "example.com",
            "spider_minutes": 30,
            "maximum_minutes": 60,
        },
    )

    assert response.status_code == 422    

def test_complete_deep_scan_requires_receipt(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/deep-scan/run",
        json={
            "domain": "example.com",
        },
    )

    assert response.status_code == 401


def test_authorized_complete_deep_scan_runs(
    monkeypatch,
):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    authorization = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    received = {}

    def fake_deep_scan(
        domain,
        max_pages,
        max_depth,
        include_zap,
        zap_spider_minutes,
        zap_maximum_minutes,
    ):
        received["domain"] = domain
        received["max_pages"] = max_pages
        received["max_depth"] = max_depth
        received["include_zap"] = include_zap
        received["zap_spider_minutes"] = (
            zap_spider_minutes
        )
        received["zap_maximum_minutes"] = (
            zap_maximum_minutes
        )

        return {
            "name": "WebShield Verified Deep Scan",
            "domain": domain,
            "scan_status": "Complete",
            "finding_summary": {
                "pages_crawled": 5,
                "sensitive_exposures": 0,
                "subdomains_discovered": 2,
                "open_ports": 2,
                "javascript_advisories": 0,
                "zap_findings": 0,
            },
        }

    monkeypatch.setattr(
        "app.main.run_verified_deep_scan",
        fake_deep_scan,
    )

    response = client.post(
        "/deep-scan/run",
        json={
            "domain": "example.com",
            "max_pages": 15,
            "max_depth": 2,
            "include_zap": False,
        },
        headers={
            "Authorization": (
                f"Bearer {authorization['receipt']}"
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["domain"] == (
        "example.com"
    )
    assert (
        response.json()["scan_status"]
        == "Complete"
    )

    assert received["domain"] == "example.com"
    assert received["max_pages"] == 15
    assert received["max_depth"] == 2
    assert received["include_zap"] is False
    assert received["zap_spider_minutes"] == 1
    assert received["zap_maximum_minutes"] == 5


def test_complete_deep_scan_rejects_bad_limits():
    response = client.post(
        "/deep-scan/run",
        json={
            "domain": "example.com",
            "max_pages": 1000,
            "max_depth": 50,
            "zap_spider_minutes": 20,
        },
    )

    assert response.status_code == 422    