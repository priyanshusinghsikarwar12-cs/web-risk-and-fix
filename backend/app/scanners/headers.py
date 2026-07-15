import re

import requests
from app.utils.safe_http import safe_get


def build_result(
    technical_name,
    name,
    status,
    message,
    value=None,
    warnings=None,
):
    return {
        "technical_name": technical_name,
        "name": name,
        "present": value is not None,
        "status": status,
        "message": message,
        "urgency": (
            "No action needed"
            if status == "Protected"
            else "Review this setting"
        ),
        "advanced": {
            "technical_name": technical_name,
            "value": value,
            "warnings": warnings or [],
        },
    }


def validate_hsts(headers):
    value = headers.get("Strict-Transport-Security")

    if not value:
        return build_result(
            "Strict-Transport-Security",
            "HTTPS Protection",
            "Needs Attention",
            "Your website does not tell browsers to always use HTTPS.",
        )

    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)

    if not match:
        return build_result(
            "Strict-Transport-Security",
            "HTTPS Protection",
            "Needs Attention",
            "HTTPS protection exists, but its duration is invalid.",
            value,
            ["The max-age directive is missing or invalid."],
        )

    max_age = int(match.group(1))

    if max_age < 31_536_000:
        return build_result(
            "Strict-Transport-Security",
            "HTTPS Protection",
            "Needs Attention",
            "HTTPS protection is enabled, but for less than one year.",
            value,
            ["OWASP testing guidance uses at least 31536000 seconds."],
        )

    warnings = []

    if "includesubdomains" not in value.lower():
        warnings.append(
            "Subdomains are not included in this HTTPS policy."
        )

    return build_result(
        "Strict-Transport-Security",
        "HTTPS Protection",
        "Protected",
        "Browsers are instructed to keep using HTTPS.",
        value,
        warnings,
    )


def validate_click_protection(headers):
    x_frame_options = headers.get("X-Frame-Options")
    csp = headers.get("Content-Security-Policy", "")

    if "frame-ancestors" in csp.lower():
        return build_result(
            "Content-Security-Policy: frame-ancestors",
            "Click Protection",
            "Protected",
            "Your website controls which pages may embed it.",
            csp,
        )

    if not x_frame_options:
        return build_result(
            "X-Frame-Options",
            "Click Protection",
            "Needs Attention",
            "Your website does not declare clickjacking protection.",
        )

    normalized_value = x_frame_options.strip().upper()

    if normalized_value not in {"DENY", "SAMEORIGIN"}:
        return build_result(
            "X-Frame-Options",
            "Click Protection",
            "Needs Attention",
            "Click protection exists, but its value is not recognized.",
            x_frame_options,
            ["Use DENY, SAMEORIGIN, or CSP frame-ancestors."],
        )

    return build_result(
        "X-Frame-Options",
        "Click Protection",
        "Protected",
        "Your website restricts being displayed inside other pages.",
        x_frame_options,
    )


def validate_content_type_options(headers):
    value = headers.get("X-Content-Type-Options")

    if not value:
        return build_result(
            "X-Content-Type-Options",
            "File Type Protection",
            "Needs Attention",
            "Browsers are not explicitly prevented from guessing file types.",
        )

    if value.strip().lower() != "nosniff":
        return build_result(
            "X-Content-Type-Options",
            "File Type Protection",
            "Needs Attention",
            "File type protection exists, but its value is invalid.",
            value,
            ["The supported secure value is nosniff."],
        )

    return build_result(
        "X-Content-Type-Options",
        "File Type Protection",
        "Protected",
        "Browsers are prevented from guessing unsafe file types.",
        value,
    )


def validate_csp(headers):
    value = headers.get("Content-Security-Policy")
    report_only = headers.get("Content-Security-Policy-Report-Only")

    if not value:
        warnings = []

        if report_only:
            warnings.append(
                "A Report-Only policy exists, but it does not enforce blocking."
            )

        return build_result(
            "Content-Security-Policy",
            "Script Attack Protection",
            "Needs Attention",
            "Your website does not enforce a Content Security Policy.",
            report_only,
            warnings,
        )

    normalized_value = value.lower()
    warnings = []

    if "default-src" not in normalized_value and "script-src" not in normalized_value:
        warnings.append(
            "The policy has neither default-src nor script-src."
        )

    if "'unsafe-eval'" in normalized_value:
        warnings.append(
            "The policy permits unsafe-eval for scripts."
        )

    if warnings:
        return build_result(
            "Content-Security-Policy",
            "Script Attack Protection",
            "Needs Attention",
            "A security policy exists, but it requires review.",
            value,
            warnings,
        )

    return build_result(
        "Content-Security-Policy",
        "Script Attack Protection",
        "Protected",
        "Your website enforces restrictions on browser content.",
        value,
    )


def validate_referrer_policy(headers):
    value = headers.get("Referrer-Policy")

    accepted_values = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }

    if not value:
        return build_result(
            "Referrer-Policy",
            "Privacy Protection",
            "Needs Attention",
            "Your website does not explicitly limit referral information.",
        )

    policies = {
        item.strip().lower()
        for item in value.split(",")
    }

    if not policies.intersection(accepted_values):
        return build_result(
            "Referrer-Policy",
            "Privacy Protection",
            "Needs Attention",
            "A referral policy exists, but it may expose more information.",
            value,
            ["Use a privacy-preserving referrer policy."],
        )

    return build_result(
        "Referrer-Policy",
        "Privacy Protection",
        "Protected",
        "Your website limits referral information.",
        value,
    )


def validate_permissions_policy(headers):
    value = headers.get("Permissions-Policy")

    if not value:
        return build_result(
            "Permissions-Policy",
            "Browser Feature Protection",
            "Needs Attention",
            "Your website does not explicitly restrict browser features.",
        )

    normalized_value = value.lower()
    restricted_features = [
        feature
        for feature in ("camera=()", "microphone=()", "geolocation=()")
        if feature in normalized_value.replace(" ", "")
    ]

    if not restricted_features:
        return build_result(
            "Permissions-Policy",
            "Browser Feature Protection",
            "Needs Attention",
            "A browser feature policy exists, but sensitive features are not clearly restricted.",
            value,
            [
                "Review camera, microphone, and geolocation permissions."
            ],
        )

    return build_result(
        "Permissions-Policy",
        "Browser Feature Protection",
        "Protected",
        "Your website restricts sensitive browser features.",
        value,
    )


def validate_security_headers(headers):
    return [
        validate_hsts(headers),
        validate_click_protection(headers),
        validate_content_type_options(headers),
        validate_csp(headers),
        validate_referrer_policy(headers),
        validate_permissions_policy(headers),
    ]


def check_security_headers(domain: str):
    url = f"https://{domain}"

    try:
        response = safe_get(
            url,
            timeout=10,
        )

        return {
            "domain": domain,
            "url": response.url,
            "status_code": response.status_code,
            "checks": validate_security_headers(response.headers),
        }

    except requests.RequestException as error:
        return {
            "domain": domain,
            "url": url,
            "status_code": None,
            "checks": [],
            "error": str(error),
        }