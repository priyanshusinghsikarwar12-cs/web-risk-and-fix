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
    "Renew your domain registration": {
        "why_it_matters": (
            "If the domain expires, the website and domain-based "
            "email may stop working. Another party may eventually "
            "be able to register the domain."
        ),
        "technical_name": "RDAP domain expiration",
        "generic_fix": (
            "Sign in to the domain registrar, renew the domain, "
            "confirm the payment method, and enable automatic renewal."
        ),
    },

    "Review your domain renewal": {
        "why_it_matters": (
            "The domain is approaching its published expiration "
            "date. A failed renewal could interrupt the website "
            "and email."
        ),
        "technical_name": "RDAP domain expiration",
        "generic_fix": (
            "Confirm that automatic renewal is enabled and that "
            "the registrar has a valid payment method."
        ),
    },

    "Fix your DKIM email signing": {
        "why_it_matters": (
            "A broken or revoked DKIM key may prevent email "
            "signatures from being verified and can reduce email "
            "trust or deliverability."
        ),
        "technical_name": "DKIM DNS TXT record",
        "generic_fix": (
            "Generate or obtain a new DKIM record from the email "
            "provider, publish it at the correct selector, wait "
            "for DNS changes, and test the selector again."
        ),
    },

    "Confirm your DKIM selector": {
        "why_it_matters": (
            "DKIM can only be validated using the selector that "
            "the email service uses to sign outgoing messages."
        ),
        "technical_name": "selector._domainkey",
        "generic_fix": (
            "Find the selector in the email provider settings or "
            "in the s= value of a DKIM-Signature email header, "
            "then run the check again."
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

TECHNOLOGY_AWARE_RECOMMENDATIONS = {
    "Enable HTTPS Protection",
    "Enable Click Protection",
    "Enable File Type Protection",
    "Enable Script Attack Protection",
    "Enable Privacy Protection",
    "Enable Browser Feature Protection",
    "Fix your website security certificate",
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

            if (
                detected_technology
                and item.get("title")
                in TECHNOLOGY_AWARE_RECOMMENDATIONS
            ):
                guidance_data["platform"] = detected_technology

                guidance_data["platform_guidance"] = (
                    TECHNOLOGY_FIXES[detected_technology]
                )

            item["guidance"] = guidance_data

        guided_recommendations.append(item)

    return guided_recommendations