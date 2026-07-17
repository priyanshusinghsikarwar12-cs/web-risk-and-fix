def generate_recommendations(
    security_headers,
    ssl_certificate,
    dns_records,
    domain_registration=None,
    dkim=None,
):
    recommendations = []

    domain_registration = domain_registration or {}
    dkim = dkim or {}

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

    registration_status = domain_registration.get(
        "status"
    )

    if registration_status in {
        "Expired",
        "Needs Attention",
    }:
        recommendations.append({
            "title": "Renew your domain registration",
            "priority": "High",
            "difficulty": "Easy",
            "estimated_time": "10-20 minutes",
            "reason": domain_registration.get(
                "message",
                "The domain registration needs attention.",
            ),
        })

    elif registration_status == "Review":
        recommendations.append({
            "title": "Review your domain renewal",
            "priority": "Medium",
            "difficulty": "Easy",
            "estimated_time": "5-10 minutes",
            "reason": domain_registration.get(
                "message",
                "Confirm that automatic renewal is enabled.",
            ),
        })

    dkim_status = dkim.get("status")

    if dkim_status in {
        "Invalid",
        "Revoked",
    }:
        recommendations.append({
            "title": "Fix your DKIM email signing",
            "priority": "High",
            "difficulty": "Medium",
            "estimated_time": "15-30 minutes",
            "reason": dkim.get(
                "message",
                "The tested DKIM selector needs attention.",
            ),
        })

    elif dkim_status == "Not Found":
        recommendations.append({
            "title": "Confirm your DKIM selector",
            "priority": "Medium",
            "difficulty": "Easy",
            "estimated_time": "5-10 minutes",
            "reason": dkim.get(
                "message",
                "No record was found for the tested selector.",
            ),
        })

    for check in security_headers.get("checks", []):
        if check.get("status") == "Needs Attention":
            recommendations.append({
                "title": (
                    f"Enable "
                    f"{check.get('name', 'security protection')}"
                ),
                "priority": "Medium",
                "difficulty": "Easy",
                "estimated_time": "5-15 minutes",
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
                "title": (
                    f"Fix "
                    f"{check.get('name', 'domain setup')}"
                ),
                "priority": "High",
                "difficulty": "Medium",
                "estimated_time": "10-20 minutes",
                "reason": check.get(
                    "message",
                    (
                        "This required domain setting "
                        "needs review."
                    ),
                ),
            })

    priority_order = {
        "High": 0,
        "Medium": 1,
        "Low": 2,
    }

    recommendations.sort(
        key=lambda item: priority_order.get(
            item.get("priority"),
            99,
        )
    )

    return recommendations[:3]