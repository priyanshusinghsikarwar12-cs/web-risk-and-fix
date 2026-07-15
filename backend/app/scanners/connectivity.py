import requests
from app.utils.safe_http import safe_get


def check_connectivity(domain: str):
    try:
        clean_domain = (
            domain
            .replace("https://", "")
            .replace("http://", "")
            .strip("/")
        )

        url = f"https://{clean_domain}"
        response = safe_get(url, timeout=10)

        return {
            "domain": clean_domain,
            "url": url,
            "status_code": response.status_code,
            "reachable": True,
        }

    except Exception:
        return {
            "domain": domain,
            "reachable": False,
        }