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
            "tls_verified": True,
            "tls_error": None,
        }

    except requests.exceptions.SSLError as tls_error:
        # The certificate failure is itself an important finding. Continue
        # one bounded, read-only homepage request so unrelated passive
        # scanners are not disabled by that single failure.
        try:
            response = safe_get(
                url,
                timeout=10,
                verify_tls=False,
            )
            response_time_ms = round(
                (time.perf_counter() - start_time) * 1000
            )
            return {
                "response": response,
                "response_time_ms": response_time_ms,
                "error": None,
                "error_type": None,
                "tls_verified": False,
                "tls_error": str(tls_error),
            }
        except requests.RequestException as retry_error:
            return {
                "response": None,
                "response_time_ms": None,
                "error": str(retry_error),
                "error_type": type(retry_error).__name__,
                "tls_verified": False,
                "tls_error": str(tls_error),
            }

    except requests.RequestException as error:
        return {
            "response": None,
            "response_time_ms": None,
            "error": str(error),
            "error_type": type(error).__name__,
            "tls_verified": None,
            "tls_error": None,
        }
