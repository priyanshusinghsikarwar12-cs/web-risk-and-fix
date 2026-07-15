from app.services.scan_engine import (
    run_full_scan,
    run_scanner,
)


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

    report = run_full_scan("example.com")

    assert report["scan_status"] == "Partial"
    assert report["security_headers"]["checks"] == []
    assert len(report["scan_failures"]) == 1
    assert (
        report["scan_failures"][0]["scanner"]
        == "Security Headers"
    )  