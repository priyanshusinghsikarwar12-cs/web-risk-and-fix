from app.scanners.connectivity import check_connectivity
from app.scanners.headers import check_security_headers
from app.scanners.ssl import check_ssl_certificate
from app.services.risk_engine import calculate_risk
from app.services.recommendation_engine import generate_recommendations
from app.scanners.dns import check_dns_records
from app.scanners.technologies import detect_technologies
from datetime import datetime
from app.scanners.health import check_website_health

def run_full_scan(domain: str):
    connectivity = check_connectivity(domain)
    health = check_website_health(domain)

    if not connectivity.get("reachable"):
        return {
            "domain": domain,
            "overall_status": "Website not reachable",
            "score": 0,
            "summary": "WebShield could not contact this website.",
            "connectivity": connectivity,
            "security_headers": None,
            "ssl_certificate": None,
        }

    security_headers = check_security_headers(domain)
    ssl_certificate = check_ssl_certificate(domain)
    dns_records = check_dns_records(domain)
    technologies = detect_technologies(domain)

    risk = calculate_risk(connectivity, security_headers, ssl_certificate, dns_records)
    recommendations = generate_recommendations(
        security_headers,
        ssl_certificate,
        dns_records,
    )

    return {
        "domain": domain,
        "overall_status": risk["overall_status"],
        "score": risk["score"],
        "summary": (
            f"Your website received a security score of {risk['score']}/100. "
            f"WebShield found {len(recommendations)} important recommendations."
        ),
        "connectivity": connectivity,
        "security_headers": security_headers,
        "ssl_certificate": ssl_certificate,
        "recommendations": recommendations,
        "dns_records": dns_records,
        "technologies": technologies,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "health": health,
    }