import logging
from datetime import datetime

from app.scanners.connectivity import check_connectivity
from app.scanners.dns import check_dns_records
from app.scanners.headers import check_security_headers
from app.scanners.health import check_website_health
from app.scanners.ssl import check_ssl_certificate
from app.scanners.technologies import detect_technologies
from app.services.fix_guidance import add_fix_guidance
from app.services.recommendation_engine import (
    generate_recommendations,
)
from app.services.risk_engine import calculate_risk
from app.utils.domain import validate_public_domain


logger = logging.getLogger(__name__)


def run_scanner(
    scanner_name,
    scanner_function,
    domain,
    fallback,
):
    try:
        result = scanner_function(domain)

        if not isinstance(result, dict):
            raise TypeError(
                f"{scanner_name} returned an invalid result."
            )

        return result, None

    except Exception as error:
        logger.exception(
            "%s failed while scanning %s",
            scanner_name,
            domain,
        )

        failure = {
            "scanner": scanner_name,
            "message": (
                f"The {scanner_name} check could not be completed."
            ),
            "error_type": type(error).__name__,
        }

        return fallback, failure


def run_full_scan(domain: str):
    domain = validate_public_domain(domain)
    failures = []

    connectivity, failure = run_scanner(
        "Website Connectivity",
        check_connectivity,
        domain,
        {
            "domain": domain,
            "reachable": False,
        },
    )

    if failure:
        failures.append(failure)

    health, failure = run_scanner(
        "Website Health",
        check_website_health,
        domain,
        {
            "name": "Website Health",
            "status": "Unavailable",
            "message": (
                "The website health check could not be completed."
            ),
            "status_code": None,
            "response_category": "scan_failed",
            "response_time_ms": None,
            "performance": None,
            "final_url": None,
            "https": None,
        },
    )

    if failure:
        failures.append(failure)

    if not connectivity.get("reachable"):
        return {
            "domain": domain,
            "scan_status": (
                "Partial"
                if failures
                else "Complete"
            ),
            "scan_failures": failures,
            "overall_status": "Website not reachable",
            "score": 0,
            "summary": (
                "WebShield could not contact this website."
            ),
            "connectivity": connectivity,
            "health": health,
            "security_headers": None,
            "ssl_certificate": None,
            "dns_records": None,
            "technologies": None,
            "recommendations": [],
            "scan_time": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }

    security_headers, failure = run_scanner(
        "Security Headers",
        check_security_headers,
        domain,
        {
            "domain": domain,
            "url": f"https://{domain}",
            "status_code": None,
            "checks": [],
            "error": "scan_failed",
        },
    )

    if failure:
        failures.append(failure)

    ssl_certificate, failure = run_scanner(
        "Security Certificate",
        check_ssl_certificate,
        domain,
        {
            "name": "Security Certificate",
            "status": "Unavailable",
            "message": (
                "The certificate check could not be completed."
            ),
            "days_left": None,
            "urgency": "Check unavailable",
            "error_type": "scan_failed",
            "advanced": {},
        },
    )

    if failure:
        failures.append(failure)

    dns_records, failure = run_scanner(
        "Domain Setup",
        check_dns_records,
        domain,
        {
            "status": "Unavailable",
            "checks": [],
            "error": "scan_failed",
        },
    )

    if failure:
        failures.append(failure)

    technologies, failure = run_scanner(
        "Technology Detection",
        detect_technologies,
        domain,
        {
            "name": "Technology Detection",
            "url": f"https://{domain}",
            "checks": [],
            "error": "scan_failed",
        },
    )

    if failure:
        failures.append(failure)

    risk = calculate_risk(
        connectivity,
        security_headers,
        ssl_certificate,
        dns_records,
    )

    recommendations = generate_recommendations(
        security_headers,
        ssl_certificate,
        dns_records,
    )

    recommendations = add_fix_guidance(
        recommendations,
        technologies,
    )

    scan_status = "Partial" if failures else "Complete"

    if failures:
        summary = (
            f"WebShield completed a partial scan. "
            f"{len(failures)} check could not be completed."
        )
    else:
        summary = (
            f"Your website received a security health score "
            f"of {risk['score']}/100. WebShield found "
            f"{len(recommendations)} important recommendations."
        )

    return {
        "domain": domain,
        "scan_status": scan_status,
        "scan_failures": failures,
        "overall_status": risk["overall_status"],
        "score": risk["score"],
        "risk_breakdown": risk["breakdown"],
        "summary": summary,
        "connectivity": connectivity,
        "health": health,
        "security_headers": security_headers,
        "ssl_certificate": ssl_certificate,
        "dns_records": dns_records,
        "technologies": technologies,
        "recommendations": recommendations,
        "scan_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
    }