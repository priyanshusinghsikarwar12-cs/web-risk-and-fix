def generate_recommendations(security_headers, ssl_certificate, dns_records):
    recommendations = []

    if ssl_certificate.get("status") != "Protected":
        recommendations.append({
            "title": "Fix your website security certificate",
            "priority": "High",
            "difficulty": "Easy",
            "estimated_time": "10 minutes",
            "reason": "Visitors may see security warnings if your certificate is invalid or expires soon.",
        })

    for check in security_headers.get("checks", []):
        if check["status"] != "Protected":
            recommendations.append({
                "title": f"Enable {check['name']}",
                "priority": "Medium",
                "difficulty": "Easy",
                "estimated_time": "5–15 minutes",
                "reason": check["message"],
            })

    for check in dns_records.get("checks", []):
        if check["status"] != "Found":
            recommendations.append({
                "title": f"Fix {check['name']}",
                "priority": "Medium",
                "difficulty": "Medium",
                "estimated_time": "10–20 minutes",
                "reason": check["message"],
            })

    return recommendations[:3]