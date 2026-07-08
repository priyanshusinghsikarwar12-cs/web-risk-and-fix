def calculate_risk(connectivity, security_headers, ssl_certificate, dns_records):
    score = 0

    if connectivity.get("reachable"):
        score += 20

    if ssl_certificate.get("status") == "Protected":
        score += 20

    header_checks = security_headers.get("checks", [])
    if header_checks:
        protected_headers = sum(
            1 for check in header_checks
            if check["status"] == "Protected"
        )
        score += int((protected_headers / len(header_checks)) * 40)

    dns_checks = dns_records.get("checks", [])
    if dns_checks:
        found_dns = sum(
            1 for check in dns_checks
            if check["status"] == "Found"
        )
        score += int((found_dns / len(dns_checks)) * 20)

    if score >= 90:
        overall_status = "Excellent"
    elif score >= 70:
        overall_status = "Good"
    elif score >= 50:
        overall_status = "Needs Attention"
    else:
        overall_status = "Critical"

    return {
        "score": score,
        "overall_status": overall_status,
    }