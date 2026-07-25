from urllib.parse import urlsplit
import time

import requests

from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get


TEST_ORIGINS = (
    "https://webshield.invalid",
    "https://security-check.invalid",
)


def _normalized_header(
    response,
    header_name: str,
) -> str:
    return str(
        response.headers.get(header_name, "")
    ).strip()


def _credentials_enabled(response) -> bool:
    value = _normalized_header(
        response,
        "Access-Control-Allow-Credentials",
    )

    return value.lower() == "true"


def _response_stays_in_scope(
    response,
    domain: str,
) -> bool:
    location = urlsplit(response.url)

    return (
        location.scheme.lower() == "https"
        and (location.hostname or "").lower() == domain
    )


def check_cors_configuration(
    domain: str,
    getter=safe_get,
    delay_seconds: float = 0,
    allow_invalid_tls: bool = False,
):
    safe_domain = clean_domain(domain)
    target_url = f"https://{safe_domain}/"

    if not 0 <= delay_seconds <= 5:
        raise ValueError(
            "The CORS request delay must be between 0 and 5 seconds."
        )

    observations = []
    errors = []

    for index, test_origin in enumerate(TEST_ORIGINS):
        if index and delay_seconds:
            time.sleep(delay_seconds)
        try:
            response = getter(
                target_url,
                timeout=10,
                max_bytes=1,
                headers={
                    "Origin": test_origin,
                    "Accept": "text/html,*/*",
                },
                allowed_redirect_host=safe_domain,
                redirect_delay_seconds=delay_seconds,
                verify_tls=not allow_invalid_tls,
            )

            if not _response_stays_in_scope(
                response,
                safe_domain,
            ):
                errors.append({
                    "origin": test_origin,
                    "message": (
                        "The response redirected outside "
                        "the verified HTTPS hostname."
                    ),
                })
                continue

            allowed_origin = _normalized_header(
                response,
                "Access-Control-Allow-Origin",
            )

            observations.append({
                "tested_origin": test_origin,
                "allowed_origin": (
                    allowed_origin or None
                ),
                "credentials_allowed": (
                    _credentials_enabled(response)
                ),
                "origin_reflected": (
                    allowed_origin == test_origin
                ),
                "wildcard_allowed": (
                    allowed_origin == "*"
                ),
                "status_code": response.status_code,
            })

        except requests.RequestException as error:
            errors.append({
                "origin": test_origin,
                "error_type": type(error).__name__,
                "message": (
                    "The CORS response could not be "
                    "collected."
                ),
            })

    reflected = [
        item
        for item in observations
        if item["origin_reflected"]
    ]

    reflected_with_credentials = [
        item
        for item in reflected
        if item["credentials_allowed"]
    ]

    wildcard = [
        item
        for item in observations
        if item["wildcard_allowed"]
    ]

    findings = []

    if reflected_with_credentials:
        findings.append({
            "name": (
                "Arbitrary Origin Trusted With Credentials"
            ),
            "status": "Needs Attention",
            "severity": "High",
            "message": (
                "The website reflected unrelated test "
                "origins while allowing browser "
                "credentials. This may permit an external "
                "website to read sensitive responses."
            ),
            "evidence": reflected_with_credentials,
        })

    elif len(reflected) == len(TEST_ORIGINS):
        findings.append({
            "name": "Arbitrary Origin Reflection",
            "status": "Review",
            "severity": "Medium",
            "message": (
                "The website reflected multiple unrelated "
                "origins. Confirm that these responses are "
                "intended to be readable by any website."
            ),
            "evidence": reflected,
        })

    if wildcard:
        findings.append({
            "name": "Wildcard Cross-Origin Access",
            "status": "Review",
            "severity": "Low",
            "message": (
                "The website allows cross-origin reading "
                "from any origin. This can be intentional "
                "for public resources, but sensitive "
                "responses should use a restricted policy."
            ),
            "evidence": wildcard,
        })

    if any(
        item["severity"] == "High"
        for item in findings
    ):
        status = "Needs Attention"
        message = (
            "WebShield observed a potentially dangerous "
            "cross-origin trust configuration."
        )

    elif findings:
        status = "Review"
        message = (
            "WebShield observed a broad CORS policy that "
            "requires manual confirmation."
        )

    elif observations and not any(
        item["allowed_origin"]
        for item in observations
    ):
        status = "Not Observed"
        message = (
            "The tested responses did not expose a CORS "
            "access policy."
        )

    elif observations:
        status = "Protected"
        message = (
            "The website did not trust WebShield's "
            "unrelated test origins."
        )

    else:
        status = "Unavailable"
        message = (
            "WebShield could not collect an in-scope CORS "
            "response."
        )

    return {
        "name": "CORS Configuration",
        "domain": safe_domain,
        "status": status,
        "message": message,
        "checks": findings,
        "finding_count": len(findings),
        "observations": observations,
        "errors": errors,
        "requests_made": len(observations) + len(errors),
        "scope": "Verified homepage response only",
        "score_eligible": False,
        "safety": {
            "http_methods": ["GET"],
            "test_origin_count": len(TEST_ORIGINS),
            "credentials_sent": False,
            "forms_submitted": False,
            "response_contents_returned": False,
            "same_verified_hostname_only": True,
        },
    }
