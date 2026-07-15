from app.services.recommendation_engine import (
    generate_recommendations,
)


def safe_ssl():
    return {
        "status": "Protected",
        "message": "Certificate is valid.",
    }


def test_optional_dns_checks_do_not_create_recommendations():
    dns_records = {
        "checks": [
            {
                "name": "IPv6 Website Address",
                "status": "Optional",
                "passed": None,
                "score_eligible": False,
                "message": "IPv6 is optional.",
            },
            {
                "name": "Email Setup",
                "status": "Not Configured",
                "passed": None,
                "score_eligible": False,
                "message": "Email is optional.",
            },
        ]
    }

    recommendations = generate_recommendations(
        {"checks": []},
        safe_ssl(),
        dns_records,
    )

    assert recommendations == []


def test_failed_required_dns_check_creates_recommendation():
    dns_records = {
        "checks": [
            {
                "name": "Website Address",
                "status": "Missing",
                "passed": False,
                "score_eligible": True,
                "message": "No website address was found.",
            }
        ]
    }

    recommendations = generate_recommendations(
        {"checks": []},
        safe_ssl(),
        dns_records,
    )

    assert len(recommendations) == 1
    assert recommendations[0]["title"] == "Fix Website Address"


def test_failed_security_header_creates_recommendation():
    security_headers = {
        "checks": [
            {
                "name": "HTTPS Protection",
                "status": "Needs Attention",
                "message": "HTTPS protection is missing.",
            }
        ]
    }

    recommendations = generate_recommendations(
        security_headers,
        safe_ssl(),
        {"checks": []},
    )

    assert len(recommendations) == 1
    assert recommendations[0]["title"] == "Enable HTTPS Protection"