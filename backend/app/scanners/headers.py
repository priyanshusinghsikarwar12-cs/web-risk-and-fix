import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HTTPS Protection",
        "missing": "Your website is missing a setting that tells browsers to always use a secure connection.",
        "present": "Your website tells browsers to always use a secure connection.",
    },
    "X-Frame-Options": {
        "name": "Click Protection",
        "missing": "Your website may be easier to display inside another fake website.",
        "present": "Your website is protected from being shown inside suspicious pages.",
    },
    "X-Content-Type-Options": {
        "name": "File Type Protection",
        "missing": "Browsers may guess file types incorrectly, which can create security risk.",
        "present": "Your website prevents browsers from guessing unsafe file types.",
    },
    "Content-Security-Policy": {
        "name": "Script Attack Protection",
        "missing": "Your website is missing extra protection against some malicious scripts.",
        "present": "Your website has extra protection against some malicious scripts.",
    },
    "Referrer-Policy": {
        "name": "Privacy Protection",
        "missing": "Your website may share more visitor information than necessary when users click links.",
        "present": "Your website limits how much visitor information is shared.",
    },
    "Permissions-Policy": {
        "name": "Browser Feature Protection",
        "missing": "Your website has not limited access to browser features like camera, microphone, or location.",
        "present": "Your website limits access to sensitive browser features.",
    },
}


def check_security_headers(domain: str):
    url = f"https://{domain}"
    response = requests.get(url, timeout=10)

    headers = response.headers
    checks = []

    for header, info in SECURITY_HEADERS.items():
        is_present = header in headers

        checks.append({
            "name": info["name"],
            "status": "Protected" if is_present else "Needs Attention",
            "message": info["present"] if is_present else info["missing"],
            "urgency": "No action needed" if is_present else "Fix this week",
            "advanced": {
            "technical_name": header,
            "present": is_present,
        }
    })

    return {
    "domain": domain,
    "url": url,
    "checks": checks,
    }