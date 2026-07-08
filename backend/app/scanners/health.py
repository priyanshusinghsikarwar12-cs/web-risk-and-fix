import time
import requests


def check_website_health(domain: str):
    url = f"https://{domain}"

    try:
        start = time.perf_counter()
        response = requests.get(url, timeout=10, allow_redirects=True)
        end = time.perf_counter()

        response_time = round((end - start) * 1000)

        return {
            "name": "Website Health",
            "status": "Healthy",
            "response_time_ms": response_time,
            "final_url": response.url,
            "https": response.url.startswith("https://"),
            "message": "Your website is responding normally.",
        }

    except Exception:
        return {
            "name": "Website Health",
            "status": "Unavailable",
            "message": "WebShield could not reach your website.",
        }