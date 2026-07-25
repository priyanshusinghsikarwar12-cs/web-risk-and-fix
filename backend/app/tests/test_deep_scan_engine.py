from app.services.deep_scan_engine import (
    run_deep_scanner,
    run_verified_deep_scan,
)


def test_successful_deep_scanner():
    result, failure = run_deep_scanner(
        "Test Scanner",
        lambda domain: {
            "domain": domain,
            "status": "Completed",
        },
        "example.com",
    )

    assert result["status"] == "Completed"
    assert failure is None


def test_failed_deep_scanner_uses_fallback():
    def broken_scanner(domain):
        raise RuntimeError("Test failure")

    result, failure = run_deep_scanner(
        "Test Scanner",
        broken_scanner,
        "example.com",
    )

    assert result["status"] == "Unavailable"
    assert failure["scanner"] == "Test Scanner"
    assert failure["error_type"] == "RuntimeError"


def successful_scanners():
    return {
        "crawler": lambda domain, **kwargs: {
            "name": "Crawler",
            "status": "Completed",
            "pages_scanned": 5,
        },
        "exposures": lambda domain, **kwargs: {
            "name": "Exposures",
            "status": "Not Observed",
            "finding_count": 0,   
        },
        "cors": lambda domain, **kwargs: {
            "name": "CORS Configuration",
            "status": "Not Observed",
            "finding_count": 0,
        },
        "http_methods": lambda domain, **kwargs: {
            "name": "HTTP Method Exposure",
            "status": "Protected",
            "finding_count": 0,
        },
        "subdomains": lambda domain, **kwargs: {
            "name": "Subdomains",
            "status": "Completed",
            "discovered_count": 3,
        },
        "ports": lambda domain, **kwargs: {
            "name": "Ports",
            "status": "Observed",
            "open_port_count": 2,
        },
        "hosting_context": lambda domain, **kwargs: {
            "name": "Hosting and Infrastructure Context",
            "status": "Hosting Provider Observed",
            "provider": {
                "name": "Cloudflare",
                "confidence": "High",
            },
            "shared_infrastructure": {
                "status": "Shared Edge Observed",
            },
        },
        "javascript_advisories": (
            lambda domain, **kwargs: {
                "name": "JavaScript Advisories",
                "status": "Not Observed",
                "vulnerability_match_count": 0,
            }
        ),
        "query_input_security": (
            lambda domain, crawler, **kwargs: {
                "name": "Application Input Security",
                "status": "Not Observed",
                "checks": [],
                "finding_count": 0,
            }
        ),
        "zap": lambda domain, **kwargs: {
            "name": "OWASP ZAP Baseline",
            "status": "Not Observed",
            "finding_count": 0,
        },
    }


def test_complete_deep_scan_summary():
    report = run_verified_deep_scan(
        "example.com",
        scanner_overrides=successful_scanners(),
    )

    assert report["scan_status"] == "Complete"
    assert report["finding_summary"] == {
        "vulnerabilities": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "pages_crawled": 5,
        "sensitive_exposures": 0,
        "cors_findings": 0,
        "http_method_findings": 0,
        "subdomains_discovered": 3,
        "open_ports": 2,
        "javascript_advisories": 0,
        "query_input_findings": 0,
        "zap_findings": 0,
    }
    assert report["zap_requested"] is False
    assert report["vulnerability_report"]["summary"][
        "total"
    ] == 0
    assert report["hosting_context"]["provider"]["name"] == (
        "Cloudflare"
    )
    assert (
        report["zap_baseline"]["status"]
        == "Not Requested"
    )


def test_zap_can_be_requested():
    report = run_verified_deep_scan(
        "example.com",
        include_zap=True,
        scanner_overrides=successful_scanners(),
    )

    assert report["scan_status"] == "Complete"
    assert report["zap_requested"] is True
    assert (
        report["zap_baseline"]["status"]
        == "Not Observed"
    )


def test_one_failure_makes_scan_partial():
    scanners = successful_scanners()

    def broken_ports(domain, **kwargs):
        raise RuntimeError("Port scanner failed")

    scanners["ports"] = broken_ports

    report = run_verified_deep_scan(
        "example.com",
        scanner_overrides=scanners,
    )

    assert report["scan_status"] == "Partial"
    assert (
        report["open_ports"]["status"]
        == "Unavailable"
    )
    assert len(report["scan_failures"]) == 1
    assert (
        report["scan_failures"][0]["scanner"]
        == "Open Ports and Services"
    )


def test_zero_crawled_pages_makes_assessment_incomplete():
    scanners = successful_scanners()
    scanners["crawler"] = lambda domain, **kwargs: {
        "name": "Crawler",
        "status": "Unavailable",
        "message": "Trusted HTTPS page access failed.",
        "pages_scanned": 0,
        "form_hygiene": {
            "status": "Not Applicable",
            "checks": [],
        },
        "page_security": {
            "status": "Not Applicable",
            "header_coverage": [],
            "cookie_findings": [],
            "cookie_diagnostics": [],
            "mixed_content_findings": [],
        },
    }

    report = run_verified_deep_scan(
        "example.com",
        scanner_overrides=scanners,
    )

    assert report["scan_status"] == "Incomplete"
    assert report["coverage"]["complete"] is False
    assert report["vulnerability_report"]["status"] == (
        "Assessment Incomplete"
    )
    assert report["vulnerability_report"]["summary"]["total"] == 0


def test_passive_baseline_finding_survives_zero_page_crawl():
    scanners = successful_scanners()
    scanners["crawler"] = lambda domain, **kwargs: {
        "name": "Crawler",
        "status": "Unavailable",
        "pages_scanned": 0,
        "page_security": {},
    }

    report = run_verified_deep_scan(
        "example.com",
        scanner_overrides=scanners,
        baseline_scanner=lambda domain: {
            "domain": domain,
            "ssl_certificate": {
                "status": "Needs Attention",
                "message": "Your website security certificate has expired.",
                "days_left": -1,
                "error_type": "certificate_expired",
            },
        },
    )

    assert report["scan_status"] == "Incomplete"
    assert report["finding_summary"]["high"] == 1
    assert report["finding_summary"]["vulnerabilities"] == 1
    assert report["vulnerability_report"]["findings"][0]["title"] == (
        "Website security certificate has expired"
    )


def test_owner_controlled_scan_passes_invalid_tls_permission_to_crawler():
    scanners = successful_scanners()
    observed = {}

    def crawler(domain, **kwargs):
        observed.update(kwargs)
        return {
            "name": "Crawler",
            "status": "Completed",
            "pages_scanned": 1,
        }

    scanners["crawler"] = crawler
    report = run_verified_deep_scan(
        "example.com",
        scanner_overrides=scanners,
        allow_invalid_tls=True,
    )

    assert observed["allow_invalid_tls"] is True
    assert report["coverage"]["tls_verification_bypassed"] is True


def test_safe_profile_runs_only_approved_scanners_with_pacing():
    scanners = successful_scanners()
    calls = []

    for name in list(scanners):
        original = scanners[name]

        def tracked(domain, _name=name, _scanner=original, **kwargs):
            calls.append(_name)
            return _scanner(domain, **kwargs)

        scanners[name] = tracked

    delays = []
    report = run_verified_deep_scan(
        "example.com",
        max_pages=5,
        max_depth=1,
        approved_scanners=["crawler", "cors"],
        request_delay_seconds=0.5,
        sleep_function=delays.append,
        scanner_overrides=scanners,
    )

    assert calls == ["crawler", "cors"]
    assert delays == [0.5, 0.5]
    assert report["approved_scanners"] == ["cors", "crawler"]
    assert report["open_ports"]["status"] == "Not Requested"
    assert report["subdomains"]["status"] == "Not Requested"
    assert report["request_delay_seconds"] == 0.5
    assert report["max_concurrency"] == 1


def test_query_input_scanner_runs_only_when_explicitly_approved():
    scanners = successful_scanners()
    report = run_verified_deep_scan(
        "example.com",
        approved_scanners=["query_input_security"],
        request_delay_seconds=0.5,
        sleep_function=lambda seconds: None,
        scanner_overrides=scanners,
    )

    assert report["query_input_security"]["status"] == "Not Observed"
    assert report["crawler"]["status"] == "Not Requested"
    assert report["approved_scanners"] == ["query_input_security"]


def test_scan_rejects_unsupported_scanner_permission():
    import pytest

    with pytest.raises(ValueError, match="unsupported scanner"):
        run_verified_deep_scan(
            "example.com",
            approved_scanners=["password_attack"],
            scanner_overrides=successful_scanners(),
        )


def test_safe_profile_applies_signed_finding_exclusions():
    scanners = successful_scanners()
    scanners["crawler"] = lambda domain, **kwargs: {
        "name": "Crawler",
        "status": "Completed",
        "pages_scanned": 1,
        "form_hygiene": {
            "status": "Protected",
            "checks": [],
        },
        "page_security": {
            "status": "Needs Attention",
            "header_coverage": [{
                "technical_name": "Content-Security-Policy",
                "name": "Script Attack Protection",
                "status": "Needs Attention",
                "attention_pages": 1,
                "affected_pages": ["https://example.com/"],
            }],
            "cookie_findings": [],
            "cookie_diagnostics": [],
            "mixed_content_findings": [],
        },
    }

    report = run_verified_deep_scan(
        "example.com",
        approved_scanners=["crawler"],
        excluded_finding_types=["missing_security_headers"],
        request_delay_seconds=0.5,
        sleep_function=lambda seconds: None,
        scanner_overrides=scanners,
    )

    assert report["finding_summary"]["vulnerabilities"] == 0
    assert report["vulnerability_report"]["summary"]["excluded"] == 1
