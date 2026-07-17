from app.scanners.tls_protocols import (
    check_tls_protocols,
    evaluate_tls_results,
)


def make_check(
    name,
    supported,
    security,
):
    return {
        "name": name,
        "status": (
            "Supported"
            if supported is True
            else "Not Supported"
            if supported is False
            else "Inconclusive"
        ),
        "supported": supported,
        "security": security,
        "cipher": None,
        "message": "Test result",
    }


def test_obsolete_tls_requires_attention():
    checks = [
        make_check("TLS 1.0", True, "Obsolete"),
        make_check("TLS 1.1", False, "Obsolete"),
        make_check("TLS 1.2", True, "Modern"),
        make_check("TLS 1.3", True, "Modern"),
    ]

    result = evaluate_tls_results(checks)

    assert result["status"] == "Needs Attention"
    assert result["confidence"] == "High"


def test_modern_tls_is_protected():
    checks = [
        make_check("TLS 1.0", False, "Obsolete"),
        make_check("TLS 1.1", False, "Obsolete"),
        make_check("TLS 1.2", True, "Modern"),
        make_check("TLS 1.3", True, "Modern"),
    ]

    result = evaluate_tls_results(checks)

    assert result["status"] == "Protected"
    assert result["confidence"] == "High"


def test_uncertain_obsolete_protocol_requires_review():
    checks = [
        make_check("TLS 1.0", None, "Obsolete"),
        make_check("TLS 1.1", False, "Obsolete"),
        make_check("TLS 1.2", True, "Modern"),
        make_check("TLS 1.3", True, "Modern"),
    ]

    result = evaluate_tls_results(checks)

    assert result["status"] == "Review"
    assert result["confidence"] == "Medium"


def test_missing_modern_tls_requires_review():
    checks = [
        make_check("TLS 1.0", False, "Obsolete"),
        make_check("TLS 1.1", False, "Obsolete"),
        make_check("TLS 1.2", False, "Modern"),
        make_check("TLS 1.3", False, "Modern"),
    ]

    result = evaluate_tls_results(checks)

    assert result["status"] == "Review"


def test_full_scanner_returns_four_protocol_checks(
    monkeypatch,
):
    def fake_probe(
        domain,
        protocol_name,
        version,
        modern,
    ):
        return make_check(
            protocol_name,
            modern,
            "Modern" if modern else "Obsolete",
        )

    monkeypatch.setattr(
        "app.scanners.tls_protocols.probe_tls_protocol",
        fake_probe,
    )

    result = check_tls_protocols("example.com")

    assert result["status"] == "Protected"
    assert len(result["checks"]) == 4
    assert result["score_eligible"] is False