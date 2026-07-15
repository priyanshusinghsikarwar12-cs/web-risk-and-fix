WEIGHTS = {
    "connectivity": 20,
    "ssl_certificate": 20,
    "security_headers": 40,
    "dns": 20,
}


def calculate_risk(
    connectivity,
    security_headers,
    ssl_certificate,
    dns_records,
):
    score = 0

    breakdown = {
        "connectivity": {
            "earned": 0,
            "maximum": WEIGHTS["connectivity"],
        },
        "ssl_certificate": {
            "earned": 0,
            "maximum": WEIGHTS["ssl_certificate"],
        },
        "security_headers": {
            "earned": 0,
            "maximum": WEIGHTS["security_headers"],
        },
        "dns": {
            "earned": 0,
            "maximum": WEIGHTS["dns"],
        },
    }

    # Website connectivity: 20 points
    if connectivity.get("reachable") is True:
        connectivity_score = WEIGHTS["connectivity"]

        score += connectivity_score
        breakdown["connectivity"]["earned"] = connectivity_score

    # Valid and trusted SSL certificate: 20 points
    if ssl_certificate.get("status") == "Protected":
        ssl_score = WEIGHTS["ssl_certificate"]

        score += ssl_score
        breakdown["ssl_certificate"]["earned"] = ssl_score

    # Valid security headers: up to 40 points
    header_checks = security_headers.get("checks", [])

    if header_checks:
        protected_headers = sum(
            1
            for check in header_checks
            if check.get("status") == "Protected"
        )

        header_score = int(
            (
                protected_headers
                / len(header_checks)
            )
            * WEIGHTS["security_headers"]
        )

        score += header_score
        breakdown["security_headers"]["earned"] = header_score

    # Only score DNS checks explicitly marked as eligible.
    # Optional IPv6 and email settings do not reduce the score.
    dns_checks = dns_records.get("checks", [])

    eligible_dns_checks = [
        check
        for check in dns_checks
        if check.get("score_eligible") is True
    ]

    if eligible_dns_checks:
        passed_dns_checks = sum(
            1
            for check in eligible_dns_checks
            if check.get("passed") is True
        )

        dns_score = int(
            (
                passed_dns_checks
                / len(eligible_dns_checks)
            )
            * WEIGHTS["dns"]
        )

        score += dns_score
        breakdown["dns"]["earned"] = dns_score

    # Defensive protection against an invalid score.
    score = max(0, min(score, 100))

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
        "breakdown": breakdown,
    }