import os
from urllib.parse import urlencode

import requests

from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get


WEB_RISK_ENDPOINT = (
    "https://webrisk.googleapis.com/v1/uris:search"
)

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
]

THREAT_LABELS = {
    "MALWARE": "Malware",
    "SOCIAL_ENGINEERING": "Phishing or deception",
    "UNWANTED_SOFTWARE": "Unwanted software",
}


def build_web_risk_url(domain, api_key):
    clean_name = clean_domain(domain)
    website_url = f"https://{clean_name}/"

    query = urlencode(
        {
            "uri": website_url,
            "threatTypes": THREAT_TYPES,
            "key": api_key,
        },
        doseq=True,
    )

    return f"{WEB_RISK_ENDPOINT}?{query}"


def base_result(domain):
    clean_name = clean_domain(domain)

    return {
        "name": "Website Reputation",
        "domain": clean_name,
        "provider": "Google Web Risk",
        "checked_url": f"https://{clean_name}/",
        "scope": "Homepage URL only",
        "score_eligible": False,
    }


def analyze_web_risk_response(data, domain):
    if not isinstance(data, dict):
        raise ValueError(
            "The reputation provider returned invalid data."
        )

    result = base_result(domain)
    threat = data.get("threat")

    if not threat:
        return {
            **result,
            "status": "No Known Threats",
            "message": (
                "No known threats were found for the "
                "checked homepage URL. This does not prove "
                "that every page on the website is safe."
            ),
            "confidence": "High",
            "threat_types": [],
            "checks": [],
            "cache_expires_at": None,
        }

    threat_types = threat.get("threatTypes", [])

    if not isinstance(threat_types, list):
        raise ValueError(
            "The provider returned invalid threat information."
        )

    recognized_threats = [
        threat_type
        for threat_type in threat_types
        if threat_type in THREAT_LABELS
    ]

    checks = [
        {
            "name": THREAT_LABELS[threat_type],
            "status": "Detected",
            "message": (
                f"Google Web Risk identified the checked "
                f"URL for {THREAT_LABELS[threat_type].lower()}."
            ),
            "threat_type": threat_type,
        }
        for threat_type in recognized_threats
    ]

    if not recognized_threats:
        return {
            **result,
            "status": "Review",
            "message": (
                "The provider returned a threat category "
                "that WebShield does not currently recognize."
            ),
            "confidence": "Limited",
            "threat_types": threat_types,
            "checks": [],
            "cache_expires_at": threat.get("expireTime"),
        }

    return {
        **result,
        "status": "Threat Detected",
        "message": (
            "The checked homepage URL appears on one or "
            "more Google Web Risk threat lists."
        ),
        "confidence": "High",
        "threat_types": recognized_threats,
        "checks": checks,
        "cache_expires_at": threat.get("expireTime"),
    }


def unavailable_result(domain, status, message):
    return {
        **base_result(domain),
        "status": status,
        "message": message,
        "confidence": "Unavailable",
        "threat_types": [],
        "checks": [],
        "cache_expires_at": None,
    }


def check_website_reputation(
    domain,
    api_key=None,
):
    clean_name = clean_domain(domain)

    web_risk_key = (
        api_key
        or os.getenv("WEBRISK_API_KEY", "").strip()
    )

    if not web_risk_key:
        return unavailable_result(
            clean_name,
            "Not Configured",
            (
                "Google Web Risk is not configured. "
                "Add a server-side API key to enable "
                "commercial reputation monitoring."
            ),
        )

    request_url = build_web_risk_url(
        clean_name,
        web_risk_key,
    )

    try:
        response = safe_get(
            request_url,
            timeout=10,
            max_bytes=200_000,
        )

        if response.status_code in {401, 403}:
            return unavailable_result(
                clean_name,
                "Configuration Error",
                (
                    "Google Web Risk rejected the configured "
                    "API credentials."
                ),
            )

        if response.status_code == 429:
            return unavailable_result(
                clean_name,
                "Rate Limited",
                (
                    "The reputation provider temporarily "
                    "rejected the request limit."
                ),
            )

        response.raise_for_status()

        if getattr(
            response,
            "webshield_content_truncated",
            False,
        ):
            return unavailable_result(
                clean_name,
                "Unavailable",
                (
                    "The reputation response exceeded "
                    "WebShield's safety limit."
                ),
            )

        return analyze_web_risk_response(
            response.json(),
            clean_name,
        )

    except (
        requests.RequestException,
        ValueError,
    ):
        return unavailable_result(
            clean_name,
            "Unavailable",
            (
                "The website reputation check could not "
                "be completed."
            ),
        )