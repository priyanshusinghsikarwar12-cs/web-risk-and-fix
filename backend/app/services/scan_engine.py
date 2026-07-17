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
from app.scanners.cookies import check_cookie_security
from app.scanners.rdap import check_domain_registration
from app.scanners.dkim import check_dkim
from app.scanners.reputation import (
    check_website_reputation,
)
from app.scanners.tls_protocols import check_tls_protocols
from app.scanners.mixed_content import check_mixed_content
from app.scanners.public_files import (
    check_public_security_files,
)
from app.scanners.script_inventory import (
    check_script_inventory,
)


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

def bind_homepage_response(
    scanner_function,
    homepage_response,
):
    if homepage_response is None:
        return scanner_function

    return lambda current_domain: scanner_function(
        current_domain,
        homepage_response,
    )        


def run_full_scan(
    domain: str,
    dkim_selector=None,  
):
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

    homepage_response = connectivity.pop(
        "_homepage_response",
        None,
    )

    homepage_response_time_ms = connectivity.pop(
        "_response_time_ms",
        None,
    )  
    if homepage_response is not None:
        health_scanner = lambda current_domain: (
            check_website_health(
                current_domain,
                homepage_response,
                homepage_response_time_ms,
            )
        )
    else:
        health_scanner = check_website_health     

    health, failure = run_scanner(
        "Website Health",
        health_scanner,
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
            "cookie_security": None,
            "ssl_certificate": None,
            "tls_protocols": None,
            "dns_records": None,
            "dkim": None,
            "domain_registration": None,
            "technologies": None,
            "reputation": None,
            "mixed_content": None,
            "script_inventory": None,
            "public_security_files": None,
            "recommendations": [],
            "scan_time": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }
    if failure:
        failures.append(failure)
    security_headers, failure = run_scanner(
        "Security Headers",
        bind_homepage_response(
            check_security_headers,
            homepage_response,
        ),
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

    tls_protocols, failure = run_scanner(
        "TLS Protocol Security",
        check_tls_protocols,
        domain,
        {
            "name": "TLS Protocol Security",
            "domain": domain,
            "status": "Unavailable",
            "message": (
                "The TLS protocol check could not be completed."
            ),
            "confidence": "Unavailable",
            "checks": [],
            "score_eligible": False,
        },
    )

    if failure:
        failures.append(failure) 

    mixed_content, failure = run_scanner(
        "Mixed Content",
        bind_homepage_response(
            check_mixed_content,
            homepage_response,
        ),        
        domain,
        {
            "name": "Mixed Content",
            "domain": domain,
            "url": f"https://{domain}",
            "status": "Unavailable",
            "message": (
                "The mixed-content check could not be completed."
            ),
            "checks": [],
            "total_found": 0,
            "results_limited": False,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
        },
    )
    if failure:
        failures.append(failure)    

    script_inventory, failure = run_scanner(
        "Script Inventory",
        bind_homepage_response(
            check_script_inventory,
            homepage_response,
        ),
        domain,
        {
            "name": "Script Inventory",
            "domain": domain,
            "url": f"https://{domain}",
            "status": "Unavailable",
            "message": (
                "The script inventory could not be completed."
            ),
            "checks": [],
            "total_script_files": 0,
            "external_script_count": 0,
            "inline_script_count": 0,
            "insecure_script_count": 0,
            "results_limited": False,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
        },
    )
    if failure:
        failures.append(failure)
    public_security_files, failure = run_scanner(
        "Public Security Files",
        check_public_security_files,
        domain,
        {
            "name": "Public Security Files",
            "domain": domain,
            "status": "Unavailable",
            "message": (
                "The public security file checks could not "
                "be completed."
            ),
            "checks": [],
            "score_eligible": False,
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
        bind_homepage_response(
            detect_technologies,
            homepage_response,
        ),
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
    cookie_security, failure = run_scanner(
        "Cookie Security",
        bind_homepage_response(
            check_cookie_security,
            homepage_response,
        ),
        domain,
        {
            "name": "Cookie Security",
            "status": "Unavailable",
            "message": (
                "The cookie security check could not be completed."
            ),
            "url": f"https://{domain}",
            "checks": [],
            "error": "scan_failed",
        },
    )

    if failure:
        failures.append(failure)
    domain_registration, failure = run_scanner(
        "Domain Registration",
        check_domain_registration,
        domain,
        {
            "name": "Domain Registration",
            "domain": domain,
            "status": "Unavailable",
            "message": (
                "The domain registration check could not "
                "be completed."
            ),
            "source": "RDAP registry data",
            "confidence": "Unavailable",
            "registration_date": None,
            "expiration_date": None,
            "last_changed_date": None,
            "days_left": None,
        },
    )

    if failure:
        failures.append(failure)
    dkim, failure = run_scanner(
        "DKIM Email Signing",
        lambda current_domain: check_dkim(
            current_domain,
            dkim_selector,
        ),
        domain,
        {
            "name": "DKIM Email Signing",
            "domain": domain,
            "selector": dkim_selector,
            "record_name": None,
            "status": "Unavailable",
            "message": (
                "The DKIM check could not be completed."
            ),
            "confidence": "Unavailable",
            "source": "DNS TXT record",
            "score_eligible": False,
            "public_key_present": None,
            "key_type": None,
            "error": "scan_failed",
        },
    )

    if failure:
        failures.append(failure) 
    reputation, failure = run_scanner(
        "Website Reputation",
        check_website_reputation,
        domain,
        {
            "name": "Website Reputation",
            "domain": domain,
            "provider": "Google Web Risk",
            "checked_url": f"https://{domain}/",
            "scope": "Homepage URL only",
            "status": "Unavailable",
            "message": (
                "The website reputation check could not "
                "be completed."
            ),
            "confidence": "Unavailable",
            "threat_types": [],
            "checks": [],
            "cache_expires_at": None,
            "score_eligible": False,
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
        domain_registration,
        dkim,
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
        "cookie_security": cookie_security,
        "ssl_certificate": ssl_certificate,
        "tls_protocols": tls_protocols,
        "mixed_content": mixed_content,
        "dns_records": dns_records,
        "dkim": dkim,
        "domain_registration": domain_registration,
        "technologies": technologies,
        "recommendations": recommendations,
        "reputation": reputation,
        "script_inventory": script_inventory,
        "public_security_files": public_security_files,
        "scan_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
    }