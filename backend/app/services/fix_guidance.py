FIX_GUIDANCE = {
    "Enable HTTPS Protection": {
        "why_it_matters": (
            "Your website may not always force visitors to use a secure "
            "HTTPS connection."
        ),
        "technical_name": "Strict-Transport-Security",
        "generic_fix": (
            "Enable the Strict-Transport-Security security header."
        ),
    },

    "Enable Click Protection": {
        "why_it_matters": (
            "Attackers may display your website inside a fake page and "
            "trick visitors into clicking something they did not intend."
        ),
        "technical_name": "X-Frame-Options",
        "generic_fix": (
            "Add the X-Frame-Options header or use the "
            "Content-Security-Policy frame-ancestors rule."
        ),
    },

    "Enable File Type Protection": {
        "why_it_matters": (
            "Browsers may incorrectly guess the type of files returned "
            "by your website."
        ),
        "technical_name": "X-Content-Type-Options",
        "generic_fix": (
            "Add the X-Content-Type-Options header with the value nosniff."
        ),
    },

    "Enable Script Attack Protection": {
        "why_it_matters": (
            "Your website has fewer browser restrictions against "
            "unexpected or harmful scripts."
        ),
        "technical_name": "Content-Security-Policy",
        "generic_fix": (
            "Create a Content-Security-Policy that only allows resources "
            "from trusted sources."
        ),
    },

    "Enable Privacy Protection": {
        "why_it_matters": (
            "Your website may share more visitor referral information "
            "than necessary."
        ),
        "technical_name": "Referrer-Policy",
        "generic_fix": (
            "Add a Referrer-Policy header such as "
            "strict-origin-when-cross-origin."
        ),
    },

    "Enable Browser Feature Protection": {
        "why_it_matters": (
            "Browser features such as camera, microphone, or location "
            "may not be clearly restricted."
        ),
        "technical_name": "Permissions-Policy",
        "generic_fix": (
            "Add a Permissions-Policy header and allow only the browser "
            "features your website needs."
        ),
    },

    "Fix your website security certificate": {
        "why_it_matters": (
            "Visitors may see security warnings when the website "
            "certificate cannot be verified."
        ),
        "technical_name": "TLS Certificate",
        "generic_fix": (
            "Check the certificate hostname, expiry date, and certificate "
            "chain with your hosting provider."
        ),
    },
}


TECHNOLOGY_FIXES = {
    "cloudflare": (
        "Your website appears to use Cloudflare. Review the relevant "
        "security header or SSL configuration in Cloudflare and apply "
        "the required setting at the edge or origin server."
    ),

    "nginx": (
        "Your website appears to use Nginx. Add the required header "
        "to the Nginx server configuration and reload Nginx after "
        "testing the configuration."
    ),

    "apache": (
        "Your website appears to use Apache. Configure the required "
        "header using the Apache headers module and reload the server."
    ),

    "wordpress": (
        "Your website appears to use WordPress. Review your hosting, "
        "security plugin, or web server configuration before changing "
        "security headers."
    ),
}


def get_detected_technology(technologies: dict):
    if not technologies:
        return None

    for check in technologies.get("checks", []):
        if check.get("confidence") not in {"High", "Medium"}:
            continue

        value = str(check.get("value", "")).lower()

        for technology in TECHNOLOGY_FIXES:
            if technology in value:
                return technology

    return None


def add_fix_guidance(
    recommendations: list,
    technologies: dict = None,
) -> list:
    guided_recommendations = []

    detected_technology = get_detected_technology(technologies)

    for recommendation in recommendations:
        item = recommendation.copy()

        guidance = FIX_GUIDANCE.get(item.get("title"))

        if guidance:
            guidance_data = guidance.copy()

            guidance_data["how_to_fix"] = guidance_data.pop(
                "generic_fix"
            )

            if detected_technology:
                guidance_data["platform"] = detected_technology

                guidance_data["platform_guidance"] = (
                    TECHNOLOGY_FIXES[detected_technology]
                )

            item["guidance"] = guidance_data

        guided_recommendations.append(item)

    return guided_recommendations