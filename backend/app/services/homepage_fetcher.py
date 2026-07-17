import time

import requests

from app.utils.safe_http import safe_get


def fetch_homepage(domain):
    url = f"https://{domain}"
    start_time = time.perf_counter()

    try:
        response = safe_get(
            url,
            timeout=10,
        )

        response_time_ms = round(
            (time.perf_counter() - start_time) * 1000
        )

        return {
            "response": response,
            "response_time_ms": response_time_ms,
            "error": None,
            "error_type": None,
        }

    except requests.RequestException as error:
        return {
            "response": None,
            "response_time_ms": None,
            "error": str(error),
            "error_type": type(error).__name__,
        }