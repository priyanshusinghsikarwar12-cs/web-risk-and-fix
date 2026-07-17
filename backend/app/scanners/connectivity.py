from app.services.homepage_fetcher import (
    fetch_homepage,
)


def check_connectivity(domain: str):
    clean_domain = (
        domain
        .replace("https://", "")
        .replace("http://", "")
        .strip("/")
    )

    homepage = fetch_homepage(clean_domain)
    response = homepage["response"]

    if response is None:
        return {
            "domain": clean_domain,
            "reachable": False,
            "error": homepage["error"],
            "error_type": homepage["error_type"],
        }

    return {
        "domain": clean_domain,
        "url": response.url,
        "status_code": response.status_code,
        "reachable": True,

        # Internal values removed before creating the report.
        "_homepage_response": response,
        "_response_time_ms": homepage[
            "response_time_ms"
        ],
    }