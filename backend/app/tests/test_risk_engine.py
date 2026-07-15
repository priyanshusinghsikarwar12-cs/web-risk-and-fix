from app.services.risk_engine import calculate_risk


def create_headers(protected_count):
    checks = []

    for index in range(6):
        checks.append(
            {
                "status": (
                    "Protected"
                    if index < protected_count
                    else "Needs Attention"
                )
            }
        )

    return {"checks": checks}


def create_dns(passed):
    return {
        "checks": [
            {
                "name": "Website Address",
                "score_eligible": True,
                "passed": passed,
            },
            {
                "name": "IPv6 Website Address",
                "score_eligible": False,
                "passed": None,
            },
            {
                "name": "Email Receiving",
                "score_eligible": False,
                "passed": True,
            },
        ]
    }


def test_fully_protected_site_scores_100():
    result = calculate_risk(
        {"reachable": True},
        create_headers(6),
        {"status": "Protected"},
        create_dns(True),
    )

    assert result["score"] == 100
    assert result["overall_status"] == "Excellent"


def test_failed_site_scores_zero():
    result = calculate_risk(
        {"reachable": False},
        create_headers(0),
        {"status": "Needs Attention"},
        create_dns(False),
    )

    assert result["score"] == 0
    assert result["overall_status"] == "Critical"


def test_optional_dns_checks_do_not_reduce_score():
    result = calculate_risk(
        {"reachable": True},
        create_headers(6),
        {"status": "Protected"},
        create_dns(True),
    )

    assert result["score"] == 100


def test_three_protected_headers_score_correctly():
    result = calculate_risk(
        {"reachable": True},
        create_headers(3),
        {"status": "Protected"},
        create_dns(True),
    )

    assert result["score"] == 80
    assert result["overall_status"] == "Good"