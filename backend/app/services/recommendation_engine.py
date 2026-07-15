def generate_recommendations(
    security_headers,
    ssl_certificate,
    dns_records,
):
    recommendations = []

    if ssl_certificate.get("status") == "Needs Attention":
        recommendations.append({
            "title": "Fix your website security certificate",
            "priority": "High",
            "difficulty": "Easy",
            "estimated_time": "10 minutes",
            "reason": ssl_certificate.get(
                "message",
                "The website certificate needs review.",
            ),
        })

    for check in security_headers.get("checks", []):
        if check.get("status") == "Needs Attention":
            recommendations.append({
                "title": f"Enable {check.get('name', 'security protection')}",
                "priority": "Medium",
                "difficulty": "Easy",
                "estimated_time": "5–15 minutes",
                "reason": check.get(
                    "message",
                    "This security setting needs review.",
                ),
            })

    for check in dns_records.get("checks", []):
        if (
            check.get("score_eligible") is True
            and check.get("passed") is False
        ):
            recommendations.append({
                "title": f"Fix {check.get('name', 'domain setup')}",
                "priority": "High",
                "difficulty": "Medium",
                "estimated_time": "10–20 minutes",
                "reason": check.get(
                    "message",
                    "This required domain setting needs review.",
                ),
            })

    return recommendations[:3]