import requests


def detect_technologies(domain: str):
    url = f"https://{domain}"
    response = requests.get(url, timeout=10)

    headers = response.headers
    html = response.text.lower()

    technologies = []

    server = headers.get("Server")
    if server:
        technologies.append({
            "name": "Web Server",
            "status": "Detected",
            "value": server,
        })

    if "wp-content" in html or "wordpress" in html:
        technologies.append({
            "name": "WordPress",
            "status": "Detected",
            "value": "WordPress indicators found",
        })

    if "shopify" in html:
        technologies.append({
            "name": "Shopify",
            "status": "Detected",
            "value": "Shopify indicators found",
        })
    if "drupal" in html:
        technologies.append({
            "name": "Drupal",
            "status": "Detected",
            "value": "Drupal indicators found",
    })

    if "joomla" in html:
        technologies.append({
            "name": "Joomla",
            "status": "Detected",
            "value": "Joomla indicators found",
    })

    if "wix" in html:
       technologies.append({
          "name": "Wix",
          "status": "Detected",
          "value": "Wix indicators found",
    })    

    if not technologies:
        technologies.append({
            "name": "Website Technology",
            "status": "Not Detected",
            "value": "WebShield could not identify the website technology yet.",
        })

    return {
        "name": "Technology Detection",
        "checks": technologies,
    }