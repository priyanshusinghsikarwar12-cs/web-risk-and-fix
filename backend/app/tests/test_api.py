from fastapi.testclient import TestClient
from app.main import app
from app.services.domain_verification import (
    create_authorization_receipt,
)
from app.services.engagement_profile import (
    create_engagement_profile,
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
        baseline_scanner=None,
        allow_invalid_tls=False,
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
        received["baseline_scanner"] = baseline_scanner
        received["allow_invalid_tls"] = allow_invalid_tls

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
    assert received["baseline_scanner"].__name__ == "run_full_scan"
    assert received["allow_invalid_tls"] is True


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


def test_local_admin_can_create_engagement_profile(monkeypatch):
    admin_token = "local-admin-token-that-is-at-least-32-characters"
    monkeypatch.setenv("WEBSHIELD_ENV", "development")
    monkeypatch.setenv("WEBSHIELD_DEV_ADMIN_TOKEN", admin_token)
    monkeypatch.setenv("WEBSHIELD_DEV_SCAN_ALLOWLIST", "example.com")
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/engagement/profile",
        headers={"X-WebShield-Admin-Token": admin_token},
        json={
            "domain": "example.com",
            "client_reference": "Local authorized test",
            "authorized_by": "WebShield developer",
            "environment": "development",
            "max_pages": 25,
            "max_depth": 2,
            "include_zap": False,
            "approved_scanners": [
                "crawler",
                "exposure_checks",
                "cors",
                "http_methods",
                "subdomains",
                "ports",
                "javascript_advisories",
            ],
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["receipt"].startswith("wse1.")
    assert response.json()["verification_method"] == "Development Admin"


def test_local_admin_engagement_respects_allowlist(monkeypatch):
    admin_token = "local-admin-token-that-is-at-least-32-characters"
    monkeypatch.setenv("WEBSHIELD_ENV", "development")
    monkeypatch.setenv("WEBSHIELD_DEV_ADMIN_TOKEN", admin_token)
    monkeypatch.setenv("WEBSHIELD_DEV_SCAN_ALLOWLIST", "example.org")

    response = client.post(
        "/engagement/profile",
        headers={"X-WebShield-Admin-Token": admin_token},
        json={
            "domain": "example.com",
            "client_reference": "Blocked local test",
            "authorized_by": "WebShield developer",
            "environment": "development",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 403
    assert "allowlist" in response.json()["detail"].lower()


def test_public_bug_bounty_profile_enforces_safe_scan(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    profile_response = client.post(
        "/engagement/bug-bounty-profile",
        json={
            "domain": "example.com",
            "program_name": "Example Program",
            "program_url": "https://hackerone.com/example",
            "researcher_handle": "researcher_one",
            "scope_reference": "example.com scope row",
            "policy_saved_date": "2026-07-21",
            "approved_scanners": [
                "crawler",
                "exposure_checks",
                "cors",
            ],
            "excluded_finding_types": [
                "missing_security_headers",
                "cookie_attribute_observations",
            ],
            "asset_in_scope_confirmed": True,
            "program_rules_confirmed": True,
            "safe_harbor_confirmed": True,
            "researcher_owned_accounts_only": True,
        },
    )

    assert profile_response.status_code == 200
    profile = profile_response.json()
    assert profile["assessment_mode"] == "bug_bounty"
    assert profile["max_pages"] == 5
    assert profile["max_concurrency"] == 1
    assert profile["approved_scanners"] == [
        "cors",
        "crawler",
        "exposure_checks",
    ]
    assert profile["excluded_finding_types"] == [
        "cookie_attribute_observations",
        "missing_security_headers",
    ]
    assert "ports" not in profile["approved_scanners"]

    received = {}

    def fake_deep_scan(domain, **kwargs):
        received["domain"] = domain
        received.update(kwargs)
        return {
            "name": "WebShield Verified Deep Scan",
            "domain": domain,
            "scan_status": "Complete",
            "finding_summary": {},
        }

    monkeypatch.setattr(
        "app.main.run_verified_deep_scan",
        fake_deep_scan,
    )
    scan_response = client.post(
        "/deep-scan/run",
        headers={
            "Authorization": f"Bearer {profile['receipt']}"
        },
        json={
            "domain": "example.com",
            "max_pages": 50,
            "max_depth": 3,
            "include_zap": True,
        },
    )

    assert scan_response.status_code == 200
    assert received["max_pages"] == 5
    assert received["max_depth"] == 1
    assert received["include_zap"] is False
    assert received["request_delay_seconds"] == 0.5
    assert received["approved_scanners"] == [
        "cors",
        "crawler",
        "exposure_checks",
    ]
    assert received["excluded_finding_types"] == [
        "cookie_attribute_observations",
        "missing_security_headers",
    ]
    assert "ports" not in received["approved_scanners"]
    assert scan_response.json()["engagement"]["assessment_mode"] == (
        "bug_bounty"
    )

    authenticated_response = client.post(
        "/engagement/test-account",
        headers={
            "Authorization": f"Bearer {profile['receipt']}"
        },
        json={
            "domain": "example.com",
            "login_url": "https://example.com/login",
            "username": "researcher@example.com",
            "password": "temporary-test-password",
        },
    )
    assert authenticated_response.status_code == 403
    assert "not approved" in authenticated_response.json()["detail"]


def test_bug_bounty_profile_can_approve_own_account_testing(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    monkeypatch.setenv(
        "WEBSHIELD_CREDENTIAL_VAULT_SECRET",
        "api-vault-secret-that-is-at-least-32-characters",
    )
    profile_response = client.post(
        "/engagement/bug-bounty-profile",
        json={
            "domain": "example.com",
            "program_name": "Example Program",
            "program_url": "https://hackerone.com/example",
            "researcher_handle": "researcher_one",
            "scope_reference": "example.com login scope row",
            "policy_saved_date": "2026-07-21",
            "approved_scanners": ["crawler"],
            "asset_in_scope_confirmed": True,
            "program_rules_confirmed": True,
            "safe_harbor_confirmed": True,
            "researcher_owned_accounts_only": True,
            "authenticated_testing_approved": True,
        },
    )
    assert profile_response.status_code == 200
    profile = profile_response.json()
    assert profile["authenticated_testing_approved"] is True

    monkeypatch.setattr(
        "app.main.store_test_account",
        lambda *args, **kwargs: {
            "credential_id": "credential-identifier-123",
            "status": "Stored Encrypted",
        },
    )
    response = client.post(
        "/engagement/test-account",
        headers={"Authorization": f"Bearer {profile['receipt']}"},
        json={
            "domain": "example.com",
            "login_url": "https://example.com/login",
            "username": "researcher@example.com",
            "password": "temporary-test-password",
            "ttl_minutes": 30,
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "Stored Encrypted"


def test_approved_bug_bounty_profile_can_create_browser_session(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    profile_response = client.post(
        "/engagement/bug-bounty-profile",
        json={
            "domain": "example.com",
            "program_name": "Example Program",
            "program_url": "https://hackerone.com/example",
            "researcher_handle": "researcher_one",
            "scope_reference": "example.com login scope row",
            "policy_saved_date": "2026-07-21",
            "approved_scanners": ["crawler"],
            "asset_in_scope_confirmed": True,
            "program_rules_confirmed": True,
            "safe_harbor_confirmed": True,
            "researcher_owned_accounts_only": True,
            "authenticated_testing_approved": True,
        },
    )
    profile = profile_response.json()
    received = {}

    def fake_browser_session(cookie_header, payload, ttl_seconds):
        received["cookie_header"] = cookie_header
        received["mode"] = payload["assessment_mode"]
        received["ttl_seconds"] = ttl_seconds
        return {
            "session_id": "browser-session-identifier",
            "status": "Browser Session Stored",
            "cookie_values_returned": False,
        }

    monkeypatch.setattr(
        "app.main.create_browser_session",
        fake_browser_session,
    )
    response = client.post(
        "/engagement/browser-session",
        headers={"Authorization": f"Bearer {profile['receipt']}"},
        json={
            "domain": "example.com",
            "cookie_header": "sessionid=test-secret",
            "ttl_minutes": 15,
            "researcher_owned_account_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["cookie_values_returned"] is False
    assert "test-secret" not in str(response.json())
    assert received["mode"] == "bug_bounty"
    assert received["ttl_seconds"] == 900


def test_browser_session_requires_own_account_confirmation(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    profile_response = client.post(
        "/engagement/bug-bounty-profile",
        json={
            "domain": "example.com",
            "program_name": "Example Program",
            "program_url": "https://hackerone.com/example",
            "researcher_handle": "researcher_one",
            "scope_reference": "example.com login scope row",
            "policy_saved_date": "2026-07-21",
            "approved_scanners": ["crawler"],
            "asset_in_scope_confirmed": True,
            "program_rules_confirmed": True,
            "safe_harbor_confirmed": True,
            "researcher_owned_accounts_only": True,
            "authenticated_testing_approved": True,
        },
    )
    response = client.post(
        "/engagement/browser-session",
        headers={
            "Authorization": f"Bearer {profile_response.json()['receipt']}"
        },
        json={
            "domain": "example.com",
            "cookie_header": "sessionid=test-secret",
            "researcher_owned_account_confirmed": False,
        },
    )
    assert response.status_code == 400
    assert "own test account" in response.json()["detail"]


def test_owner_engagement_can_create_confirmed_browser_session(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    engagement = make_test_engagement_receipt()
    received = {}

    def fake_browser_session(cookie_header, payload, ttl_seconds):
        received["owner_confirmation"] = payload[
            "researcher_owned_accounts_only"
        ]
        return {
            "session_id": "owner-browser-session-123",
            "status": "Browser Session Stored",
            "cookie_values_returned": False,
        }

    monkeypatch.setattr(
        "app.main.create_browser_session",
        fake_browser_session,
    )
    response = client.post(
        "/engagement/browser-session",
        headers={
            "Authorization": f"Bearer {engagement['receipt']}"
        },
        json={
            "domain": "example.com",
            "cookie_header": "sessionid=owner-test-secret",
            "ttl_minutes": 15,
            "researcher_owned_account_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert received["owner_confirmation"] is True


def test_signed_bug_bounty_profile_controls_logout_test_endpoints(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    profile_response = client.post(
        "/engagement/bug-bounty-profile",
        json={
            "domain": "example.com",
            "program_name": "Example Program",
            "program_url": "https://hackerone.com/example",
            "researcher_handle": "researcher_one",
            "scope_reference": "example.com login scope row",
            "policy_saved_date": "2026-07-21",
            "approved_scanners": ["crawler"],
            "asset_in_scope_confirmed": True,
            "program_rules_confirmed": True,
            "safe_harbor_confirmed": True,
            "researcher_owned_accounts_only": True,
            "authenticated_testing_approved": True,
        },
    )
    profile = profile_response.json()
    headers = {"Authorization": f"Bearer {profile['receipt']}"}
    received = {}

    def fake_prepare(session_id, protected_url, payload, **kwargs):
        received["prepare"] = (session_id, protected_url, payload["domain"], kwargs)
        return {
            "test_id": "logout-test-identifier",
            "status": "Waiting for Manual Logout",
            "personal_values_returned": False,
        }

    def fake_check(test_id, payload, logout_completed_confirmed):
        received["check"] = (
            test_id,
            payload["domain"],
            logout_completed_confirmed,
        )
        return {
            "status": "Protected",
            "old_session_deleted": True,
            "cookie_values_returned": False,
        }

    def fake_cancel(test_id, payload):
        received["cancel"] = (test_id, payload["domain"])
        return {"test_id": test_id, "cancelled": True}

    monkeypatch.setattr("app.main.prepare_logout_invalidation_test", fake_prepare)
    monkeypatch.setattr("app.main.check_logout_invalidation_test", fake_check)
    monkeypatch.setattr("app.main.cancel_logout_invalidation_test", fake_cancel)

    prepared = client.post(
        "/engagement/logout-test/prepare",
        headers=headers,
        json={
            "domain": "example.com",
            "session_id": "browser-session-identifier",
            "protected_url": "https://example.com/account",
            "anonymous_access_denial_confirmed": True,
            "verification_endpoint_url": "https://example.com/api/getProfile",
            "verification_method": "POST",
            "verification_json_body": {"locale": "en-IN"},
            "read_only_post_confirmed": True,
        },
    )
    assert prepared.status_code == 200
    assert prepared.json()["personal_values_returned"] is False

    checked = client.post(
        "/engagement/logout-test/check",
        headers=headers,
        json={
            "domain": "example.com",
            "test_id": "logout-test-identifier",
            "logout_completed_confirmed": True,
        },
    )
    assert checked.status_code == 200
    assert checked.json()["status"] == "Protected"

    cancelled = client.delete(
        "/engagement/logout-test/logout-test-identifier",
        params={"domain": "example.com"},
        headers=headers,
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["cancelled"] is True
    assert received["prepare"][2] == "example.com"
    assert received["prepare"][3]["verification_endpoint_url"] == (
        "https://example.com/api/getProfile"
    )
    assert received["prepare"][3]["verification_method"] == "POST"
    assert received["prepare"][3]["verification_json_body"] == {
        "locale": "en-IN"
    }
    assert received["prepare"][3]["read_only_post_confirmed"] is True
    assert received["check"][2] is True


def test_public_bug_bounty_profile_rejects_unsafe_scanner(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/engagement/bug-bounty-profile",
        json={
            "domain": "example.com",
            "program_name": "Example Program",
            "program_url": "https://hackerone.com/example",
            "researcher_handle": "researcher_one",
            "scope_reference": "example.com scope row",
            "policy_saved_date": "2026-07-21",
            "approved_scanners": ["crawler", "ports"],
            "asset_in_scope_confirmed": True,
            "program_rules_confirmed": True,
            "safe_harbor_confirmed": True,
            "researcher_owned_accounts_only": True,
        },
    )

    assert response.status_code == 400
    assert "not allowed in safe mode" in response.json()["detail"]


def make_test_engagement_receipt():
    ownership = {
        "domain": "example.com",
        "scope": ["example.com"],
        "verification_method": "DNS TXT",
    }
    return create_engagement_profile(
        "example.com",
        ownership,
        {
            "client_reference": "Test engagement",
            "authorized_by": "Website owner",
            "environment": "production",
            "max_pages": 25,
            "max_depth": 2,
            "include_zap": False,
            "zap_spider_minutes": 1,
            "zap_maximum_minutes": 5,
            "approved_scanners": ["crawler"],
            "authorization_confirmed": True,
        },
        TEST_VERIFICATION_SECRET,
    )


def test_engagement_can_store_and_delete_test_account(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    monkeypatch.setenv(
        "WEBSHIELD_CREDENTIAL_VAULT_SECRET",
        "api-vault-secret-that-is-at-least-32-characters",
    )
    engagement = make_test_engagement_receipt()
    headers = {
        "Authorization": f"Bearer {engagement['receipt']}"
    }

    stored = client.post(
        "/engagement/test-account",
        headers=headers,
        json={
            "domain": "example.com",
            "login_url": "https://example.com/login",
            "username": "test-user@example.com",
            "password": "temporary-test-password",
            "ttl_minutes": 30,
        },
    )

    assert stored.status_code == 200
    body = stored.json()
    assert body["status"] == "Stored Encrypted"
    assert "password" not in body
    assert "username" not in body

    deleted = client.delete(
        f"/engagement/test-account/{body['credential_id']}",
        params={"domain": "example.com"},
        headers=headers,
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_ownership_receipt_cannot_store_test_account(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    ownership = create_authorization_receipt(
        "example.com",
        "DNS TXT",
        TEST_VERIFICATION_SECRET,
    )

    response = client.post(
        "/engagement/test-account",
        headers={
            "Authorization": f"Bearer {ownership['receipt']}"
        },
        json={
            "domain": "example.com",
            "login_url": "https://example.com/login",
            "username": "test-user@example.com",
            "password": "temporary-test-password",
        },
    )

    assert response.status_code == 403
    assert "Engagement Profile" in response.json()["detail"]


def test_engagement_can_create_login_session(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    monkeypatch.setenv(
        "WEBSHIELD_CREDENTIAL_VAULT_SECRET",
        "api-vault-secret-that-is-at-least-32-characters",
    )
    engagement = make_test_engagement_receipt()
    received = {}

    def fake_login_session(credential_id, payload, vault_secret):
        received["credential_id"] = credential_id
        received["engagement_id"] = payload["engagement_id"]
        return {
            "session_id": "authenticated-session-id",
            "status": "Session Cookie Observed",
            "credential_values_returned": False,
        }

    monkeypatch.setattr(
        "app.main.create_login_session",
        fake_login_session,
    )
    response = client.post(
        "/engagement/login-session",
        headers={
            "Authorization": f"Bearer {engagement['receipt']}"
        },
        json={
            "domain": "example.com",
            "credential_id": "credential-identifier-123",
        },
    )

    assert response.status_code == 200
    assert response.json()["credential_values_returned"] is False
    assert received["credential_id"] == "credential-identifier-123"


def test_ownership_receipt_cannot_create_login_session(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    ownership = create_authorization_receipt(
        "example.com", "DNS TXT", TEST_VERIFICATION_SECRET
    )

    response = client.post(
        "/engagement/login-session",
        headers={
            "Authorization": f"Bearer {ownership['receipt']}"
        },
        json={
            "domain": "example.com",
            "credential_id": "credential-identifier-123",
        },
    )

    assert response.status_code == 403


def test_engagement_can_verify_protected_page(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    engagement = make_test_engagement_receipt()
    monkeypatch.setattr(
        "app.main.verify_protected_page",
        lambda session_id, protected_url, payload: {
            "status": "Verified",
            "confidence": "High",
            "page_content_returned": False,
            "cookie_values_returned": False,
        },
    )

    response = client.post(
        "/engagement/protected-page/verify",
        headers={
            "Authorization": f"Bearer {engagement['receipt']}"
        },
        json={
            "domain": "example.com",
            "session_id": "authenticated-session-id",
            "protected_url": "https://example.com/dashboard",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "Verified"
    assert response.json()["page_content_returned"] is False


def test_engagement_can_run_authenticated_crawl(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    engagement = make_test_engagement_receipt()
    received = {}

    def fake_authenticated_crawl(session_id, protected_url, payload, **kwargs):
        received.update(kwargs)
        return {
            "name": "Read-Only Authenticated Crawler",
            "pages_scanned": 4,
            "forms_submitted": 0,
            "state_changing_requests_sent": 0,
        }

    monkeypatch.setattr(
        "app.main.run_authenticated_crawl",
        fake_authenticated_crawl,
    )
    response = client.post(
        "/engagement/authenticated-crawl",
        headers={
            "Authorization": f"Bearer {engagement['receipt']}"
        },
        json={
            "domain": "example.com",
            "session_id": "authenticated-session-id",
            "protected_url": "https://example.com/dashboard",
            "max_pages": 10,
            "max_depth": 1,
            "accept_medium_confidence": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["forms_submitted"] == 0
    assert received["max_pages"] == 10
    assert received["max_depth"] == 1


def test_owner_engagement_can_run_object_access_check(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    engagement = make_test_engagement_receipt()
    received = {}

    def fake_check(
        session_a_id,
        session_b_id,
        endpoint_template,
        object_a_id,
        object_b_id,
        payload,
        **kwargs,
    ):
        received.update({
            "sessions": [session_a_id, session_b_id],
            "template": endpoint_template,
            "objects": [object_a_id, object_b_id],
            "mode": payload["assessment_mode"],
            **kwargs,
        })
        return {
            "name": "Object Access Control",
            "status": "Protected",
            "checks": [],
            "requests_made": 4,
            "values_returned": False,
        }

    monkeypatch.setattr(
        "app.main.check_object_access_control",
        fake_check,
    )
    response = client.post(
        "/engagement/object-access/check",
        headers={
            "Authorization": f"Bearer {engagement['receipt']}"
        },
        json={
            "domain": "example.com",
            "session_a_id": "session-account-a-123",
            "session_b_id": "session-account-b-456",
            "endpoint_template": (
                "https://example.com/api/orders/{object_id}"
            ),
            "object_a_id": "order-a",
            "object_b_id": "order-b",
            "read_only_get_confirmed": True,
            "test_accounts_own_objects_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "Protected"
    assert response.json()["values_returned"] is False
    assert received["mode"] == "owner_verified"
    assert received["read_only_get_confirmed"] is True
    assert received["test_accounts_own_objects_confirmed"] is True


def test_object_access_check_requires_signed_engagement():
    response = client.post(
        "/engagement/object-access/check",
        json={
            "domain": "example.com",
            "session_a_id": "session-account-a-123",
            "session_b_id": "session-account-b-456",
            "endpoint_template": (
                "https://example.com/api/orders/{object_id}"
            ),
            "object_a_id": "order-a",
            "object_b_id": "order-b",
            "read_only_get_confirmed": True,
            "test_accounts_own_objects_confirmed": True,
        },
    )

    assert response.status_code == 401


def test_owner_engagement_can_run_api_authentication_boundary(monkeypatch):
    monkeypatch.setenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        TEST_VERIFICATION_SECRET,
    )
    engagement = make_test_engagement_receipt()
    received = {}

    def fake_check(session_id, template, object_id, payload, **kwargs):
        received.update({
            "session_id": session_id,
            "template": template,
            "object_id": object_id,
            "mode": payload["assessment_mode"],
            **kwargs,
        })
        return {
            "name": "API Authentication Boundary",
            "status": "Protected",
            "checks": [],
            "requests_made": 2,
            "values_returned": False,
        }

    monkeypatch.setattr(
        "app.main.check_api_authentication_boundary",
        fake_check,
    )
    response = client.post(
        "/engagement/api-auth-boundary/check",
        headers={
            "Authorization": f"Bearer {engagement['receipt']}"
        },
        json={
            "domain": "example.com",
            "session_id": "session-account-a-123",
            "endpoint_template": (
                "https://example.com/api/orders/{object_id}"
            ),
            "object_id": "order-a",
            "read_only_get_confirmed": True,
            "private_test_object_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "Protected"
    assert response.json()["values_returned"] is False
    assert received["mode"] == "owner_verified"
    assert received["private_test_object_confirmed"] is True
