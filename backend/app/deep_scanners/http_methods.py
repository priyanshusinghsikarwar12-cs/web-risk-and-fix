from urllib.parse import urlsplit

import requests

from app.utils.domain import clean_domain
from app.utils.safe_http import validate_request_url


EXPECTED_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
    "POST",
}

REVIEW_METHODS = {
    "COPY",
    "DELETE",
    "LOCK",
    "MKCOL",
    "MOVE",
    "PROPFIND",
    "PROPPATCH",
    "PUT",
    "TRACE",
    "UNLOCK",
}

HIGH_RISK_METHODS = {
    "CONNECT",
}


def parse_methods(value: str) -> set:
    return {
        method.strip().upper()
        for method in str(value).split(",")
        if method.strip()
    }


def _response_stays_in_scope(
    response,
    domain: str,
) -> bool:
    location = urlsplit(response.url)

    return (
        location.scheme.lower() == "https"
        and (location.hostname or "").lower() == domain
    )


def check_http_method_exposure(
    domain: str,
    requester=requests.options,
    validator=validate_request_url,
    allow_invalid_tls: bool = False,
):
    safe_domain = clean_domain(domain)
    target_url = f"https://{safe_domain}/"

    validator(target_url)

    response = None

    try:
        response = requester(
            target_url,
            timeout=10,
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": (
                    "WebShield/0.1 authorized "
                    "website security assessment"
                ),
                "Accept": "*/*",
            },
            verify=not allow_invalid_tls,
        )

        if not _response_stays_in_scope(
            response,
            safe_domain,
        ):
            return {
                "name": "HTTP Method Exposure",
                "domain": safe_domain,
                "status": "Unavailable",
                "message": (
                    "The method check did not remain on "
                    "the exact verified HTTPS hostname."
                ),
                "checks": [],
                "advertised_methods": [],
                "finding_count": 0,
                "score_eligible": False,
            }

        allow_methods = parse_methods(
            response.headers.get("Allow", "")
        )

        cors_methods = parse_methods(
            response.headers.get(
                "Access-Control-Allow-Methods",
                "",
            )
        )

        advertised_methods = (
            allow_methods | cors_methods
        )

        review_methods = sorted(
            advertised_methods & REVIEW_METHODS
        )

        high_risk_methods = sorted(
            advertised_methods & HIGH_RISK_METHODS
        )

        checks = []

        for method in high_risk_methods:
            checks.append({
                "name": f"{method} Method Advertised",
                "method": method,
                "status": "Needs Attention",
                "severity": "High",
                "message": (
                    f"The server advertised {method}. "
                    "Confirm that this behavior is "
                    "intentional and restricted."
                ),
                "vulnerability_confirmed": False,
                "validation": "Requires Confirmation",
            })

        for method in review_methods:
            checks.append({
                "name": f"{method} Method Advertised",
                "method": method,
                "status": "Review",
                "severity": "Medium",
                "message": (
                    f"The server advertised {method}. "
                    "This can be legitimate, but it should "
                    "be enabled only where required and "
                    "protected by authorization."
                ),
                "vulnerability_confirmed": False,
                "validation": "Requires Confirmation",
            })

        if high_risk_methods:
            status = "Needs Attention"
            message = (
                "The server advertised a powerful HTTP "
                "method that requires immediate review."
            )

        elif review_methods:
            status = "Review"
            message = (
                "The server advertised one or more HTTP "
                "methods that require manual confirmation."
            )

        elif advertised_methods:
            status = "Protected"
            message = (
                "The server advertised only commonly "
                "expected HTTP methods."
            )

        else:
            status = "Not Observed"
            message = (
                "The server did not advertise supported "
                "HTTP methods in the tested response."
            )

        return {
            "name": "HTTP Method Exposure",
            "domain": safe_domain,
            "status": status,
            "message": message,
            "status_code": response.status_code,
            "checks": checks,
            "advertised_methods": sorted(
                advertised_methods
            ),
            "allow_header_methods": sorted(
                allow_methods
            ),
            "cors_header_methods": sorted(
                cors_methods
            ),
            "finding_count": len(checks),
            "scope": (
                "One OPTIONS request to the verified "
                "homepage only"
            ),
            "score_eligible": False,
            "safety": {
                "request_method": "OPTIONS",
                "powerful_methods_executed": False,
                "forms_submitted": False,
                "credentials_sent": False,
                "redirects_followed": False,
                "response_body_read": False,
                "same_verified_hostname_only": True,
            },
        }

    except requests.RequestException as error:
        return {
            "name": "HTTP Method Exposure",
            "domain": safe_domain,
            "status": "Unavailable",
            "message": (
                "The server method information could not "
                "be collected."
            ),
            "checks": [],
            "advertised_methods": [],
            "finding_count": 0,
            "error_type": type(error).__name__,
            "score_eligible": False,
        }

    finally:
        if response is not None:
            response.close()
