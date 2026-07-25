import time

import requests
from app.utils.safe_http import safe_get


def classify_http_status(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "successful"

    if 300 <= status_code < 400:
        return "redirect"

    if 400 <= status_code < 500:
        return "client_error"

    if 500 <= status_code < 600:
        return "server_error"

    return "unexpected_status"


def classify_response_time(response_time_ms: int) -> str:
    if response_time_ms < 1000:
        return "Fast"

    if response_time_ms < 3000:
        return "Moderate"

    return "Slow"


def evaluate_health(
    status_code: int,
    response_time_ms: int,
    final_url: str,
    tls_verified: bool = True,
):
    response_category = classify_http_status(status_code)
    uses_https = final_url.startswith("https://")

    if (
        response_category == "successful"
        and uses_https
        and tls_verified is False
    ):
        status = "Needs Attention"
        message = (
            "The website responded, but its HTTPS certificate could "
            "not be trusted. The remaining read-only checks continued."
        )

    elif response_category == "successful" and uses_https:
        status = "Healthy"
        message = "Your website is responding normally over HTTPS."

    elif response_category == "successful":
        status = "Needs Attention"
        message = (
            "Your website responds, but its final connection is not HTTPS."
        )

    elif response_category == "redirect":
        status = "Available"
        message = "Your website returned a redirect response."

    elif response_category == "client_error":
        status = "Needs Attention"
        message = (
            f"Your website responded with HTTP {status_code}, "
            "which indicates a request or page-access problem."
        )

    elif response_category == "server_error":
        status = "Needs Attention"
        message = (
            f"Your website responded with HTTP {status_code}, "
            "which indicates a server problem."
        )

    else:
        status = "Needs Attention"
        message = (
            f"Your website returned an unexpected "
            f"HTTP status: {status_code}."
        )

    return {
        "name": "Website Health",
        "status": status,
        "message": message,
        "status_code": status_code,
        "response_category": response_category,
        "response_time_ms": response_time_ms,
        "performance": (
    classify_response_time(response_time_ms)
    if response_time_ms is not None
    else None
),
        "final_url": final_url,
        "https": uses_https,
        "tls_verified": tls_verified,
    }


def check_website_health(
    domain: str,
    response=None,
    response_time_ms=None,
):
    url = f"https://{domain}"

    try:
        if response is None:
            start = time.perf_counter()

            response = safe_get(
                url,
                timeout=10,
            )

            response_time_ms = round(
                (time.perf_counter() - start) * 1000
            )
        return evaluate_health(
            response.status_code,
            response_time_ms,
            response.url,
            getattr(
                response,
                "webshield_tls_verified",
                True,
            ),
        )

    except requests.Timeout as error:
        return {
            "name": "Website Health",
            "status": "Unavailable",
            "message": "The website took too long to respond.",
            "status_code": None,
            "response_category": "timeout",
            "response_time_ms": None,
            "performance": None,
            "final_url": url,
            "https": True,
            "advanced": {
                "error": str(error),
            },
        }

    except requests.TooManyRedirects as error:
        return {
            "name": "Website Health",
            "status": "Needs Attention",
            "message": "The website redirected too many times.",
            "status_code": None,
            "response_category": "redirect_loop",
            "response_time_ms": None,
            "performance": None,
            "final_url": url,
            "https": True,
            "advanced": {
                "error": str(error),
            },
        }

    except requests.RequestException as error:
        return {
            "name": "Website Health",
            "status": "Unavailable",
            "message": "WebShield could not reach the website.",
            "status_code": None,
            "response_category": "connection_failed",
            "response_time_ms": None,
            "performance": None,
            "final_url": url,
            "https": True,
            "advanced": {
                "error": str(error),
            },
        }
