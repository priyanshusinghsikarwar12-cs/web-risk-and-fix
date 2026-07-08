import requests


def check_connectivity(domain: str):
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10)

        return {
            "domain": domain,
            "url": url,
            "status_code": response.status_code,
            "reachable": True
        }

    except Exception:
        return {
            "domain": domain,
            "reachable": False
        }