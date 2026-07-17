from app.services.scan_engine import (
    bind_homepage_response,
    run_full_scan,
    run_scanner,
)

def test_homepage_response_is_bound_to_scanner():
    homepage_response = object()

    def scanner(domain, response=None):
        return {
            "domain": domain,
            "same_response": (
                response is homepage_response
            ),
        }

    bound_scanner = bind_homepage_response(
        scanner,
        homepage_response,
    )

    result = bound_scanner("example.com")

    assert result["same_response"] is True


def test_scanner_is_unchanged_without_response():
    def scanner(domain):
        return {"domain": domain}

    result = bind_homepage_response(
        scanner,
        None,
    )

    assert result is scanner


def test_successful_scanner_returns_result():
    def working_scanner(domain):
        return {
            "domain": domain,
            "status": "Completed",
        }

    result, failure = run_scanner(
        "Test Scanner",
        working_scanner,
        "example.com",
        {"status": "Unavailable"},
    )

    assert result["status"] == "Completed"
    assert failure is None


def test_failed_scanner_returns_fallback():
    def broken_scanner(domain):
        raise RuntimeError("Scanner failed")

    fallback = {
        "status": "Unavailable",
        "checks": [],
    }

    result, failure = run_scanner(
        "Test Scanner",
        broken_scanner,
        "example.com",
        fallback,
    )

    assert result == fallback
    assert failure["scanner"] == "Test Scanner"
    assert failure["error_type"] == "RuntimeError"


def test_invalid_scanner_result_returns_fallback():
    def invalid_scanner(domain):
        return None

    fallback = {
        "status": "Unavailable",
        "checks": [],
    }

    result, failure = run_scanner(
        "Test Scanner",
        invalid_scanner,
        "example.com",
        fallback,
    )

    assert result == fallback
    assert failure["error_type"] == "TypeError"


def test_full_scan_becomes_partial_when_scanner_fails(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.scan_engine.validate_public_domain",
        lambda domain: domain,
    )

    monkeypatch.setattr(
        "app.services.scan_engine.check_connectivity",
        lambda domain: {
            "domain": domain,
            "reachable": True,
            "status_code": 200,
        },
    )

    monkeypatch.setattr(
        "app.services.scan_engine.check_website_health",
        lambda domain: {
            "status": "Healthy",
            "message": "Website is responding.",
            "response_time_ms": 100,
        },
    )

    def broken_headers(domain):
        raise RuntimeError("Header scanner failed")

    monkeypatch.setattr(
        "app.services.scan_engine.check_security_headers",
        broken_headers,
    )

    monkeypatch.setattr(
        "app.services.scan_engine.check_ssl_certificate",
        lambda domain: {
            "status": "Protected",
            "message": "Certificate is valid.",
            "days_left": 90,
        },
    )

    monkeypatch.setattr(
        "app.services.scan_engine.check_tls_protocols",
        lambda domain: {
            "name": "TLS Protocol Security",
            "domain": domain,
            "status": "Protected",
            "message": (
                "Modern TLS protocols are supported."
            ),
            "confidence": "High",
            "checks": [],
            "score_eligible": False,
        },
    )

    monkeypatch.setattr(
        "app.services.scan_engine.check_mixed_content",
        lambda domain: {
            "name": "Mixed Content",
            "domain": domain,
            "url": f"https://{domain}",
            "status": "Protected",
            "message": (
                "No insecure HTTP resources were found."
            ),
            "checks": [],
            "total_found": 0,
            "results_limited": False,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
        },
    )  

    monkeypatch.setattr(
        "app.services.scan_engine.check_privacy_signals",
        lambda domain: {
            "name": "Privacy and Consent Signals",
            "domain": domain,
            "url": f"https://{domain}",
            "status": "Observed",
            "message": (
                "Privacy and consent signals were observed."
            ),
            "checks": [],
            "privacy_link_count": 1,
            "consent_signal_count": 1,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
        },
    )

    monkeypatch.setattr(
        "app.services.scan_engine.check_script_inventory",
        lambda domain: {
            "name": "Script Inventory",
            "domain": domain,
            "url": f"https://{domain}",
            "status": "No External Scripts",
            "message": (
                "No external scripts were observed."
            ),
            "checks": [],
            "total_script_files": 0,
            "external_script_count": 0,
            "inline_script_count": 0,
            "insecure_script_count": 0,
            "detected_library_count": 0,
            "results_limited": False,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
        },
    )    

    monkeypatch.setattr(
        "app.services.scan_engine.check_public_security_files",
        lambda domain: {
            "name": "Public Security Files",
            "domain": domain,
            "status": "Completed",
            "message": (
                "Public security files were inspected."
            ),
            "checks": [],
            "score_eligible": False,
        },
    ) 

    monkeypatch.setattr(
        "app.services.scan_engine.check_error_leakage",
        lambda domain: {
            "name": "Error Information Leakage",
            "status": "Not Observed",
            "message": (
                "No obvious detailed errors were observed."
            ),
            "requested_url": (
                f"https://{domain}/.well-known/"
                f"webshield-missing-page-check"
            ),
            "final_url": (
                f"https://{domain}/.well-known/"
                f"webshield-missing-page-check"
            ),
            "status_code": 404,
            "redirected": False,
            "content_truncated": False,
            "checks": [],
            "scope": "One intentionally missing page only",
            "score_eligible": False,
        },
    )

    monkeypatch.setattr(
        "app.services.scan_engine.check_dns_records",
        lambda domain: {
            "status": "Completed",
            "checks": [],
        },
    )

    monkeypatch.setattr(
        "app.services.scan_engine.detect_technologies",
        lambda domain: {
            "name": "Technology Detection",
            "checks": [],
        },
    )
    
    monkeypatch.setattr(
        "app.services.scan_engine.check_cookie_security",
        lambda domain: {
            "name": "Cookie Security",
            "status": "Not Observed",
            "checks": [],
        },
    )

    monkeypatch.setattr(
        "app.services.scan_engine.check_domain_registration",
        lambda domain: {
            "name": "Domain Registration",
            "domain": domain,
            "status": "Healthy",
            "message": (
                "The domain registration is active."
            ),
            "source": "RDAP registry data",
            "confidence": "High",
            "registration_date": (
                "2020-01-10T10:00:00+00:00"
            ),
            "expiration_date": (
                "2027-07-15T00:00:00+00:00"
            ),
            "last_changed_date": None,
            "days_left": 365,
        },
    )
    monkeypatch.setattr(
        "app.services.scan_engine.check_website_reputation",
        lambda domain: {
            "name": "Website Reputation",
            "domain": domain,
            "provider": "Google Web Risk",
            "checked_url": f"https://{domain}/",
            "scope": "Homepage URL only",
            "status": "No Known Threats",
            "message": (
                "No known threats were found."
            ),
            "confidence": "High",
            "threat_types": [],
            "checks": [],
            "cache_expires_at": None,
            "score_eligible": False,
        },
    )    

    report = run_full_scan("example.com")

    assert report["scan_status"] == "Partial"
    assert report["security_headers"]["checks"] == []
    assert len(report["scan_failures"]) == 1
    assert (
        report["scan_failures"][0]["scanner"]
        == "Security Headers"
    )  
    assert (
        report["cookie_security"]["status"]
        == "Not Observed"
    )
    assert (
        report["domain_registration"]["status"]
        == "Healthy"
    )
    assert (
        report["reputation"]["status"]
        == "No Known Threats"
    )    

    assert (
        report["error_leakage"]["status"]
        == "Not Observed"
    )

    assert report["privacy_signals"]["status"] == "Observed"