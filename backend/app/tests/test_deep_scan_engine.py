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
        "javascript_advisories": (
            lambda domain, **kwargs: {
                "name": "JavaScript Advisories",
                "status": "Not Observed",
                "vulnerability_match_count": 0,
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
        "pages_crawled": 5,
        "sensitive_exposures": 0,
        "subdomains_discovered": 3,
        "open_ports": 2,
        "javascript_advisories": 0,
        "zap_findings": 0,
    }
    assert report["zap_requested"] is False
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