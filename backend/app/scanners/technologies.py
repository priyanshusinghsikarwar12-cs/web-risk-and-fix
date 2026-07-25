import requests
import re
from app.utils.safe_http import safe_get


def create_detection(
    name,
    value,
    confidence,
    evidence,
    status="Detected",
):
    return {
        "name": name,
        "status": status,
        "value": value,
        "confidence": confidence,
        "evidence": evidence,
    }


def detect_technologies_from_evidence(headers, html):
    normalized_headers = {
        str(name).lower(): str(value)
        for name, value in headers.items()
    }

    normalized_html = html.lower()
    detections = []

    # Cloudflare detection
    cloudflare_evidence = []

    if "cf-ray" in normalized_headers:
        cloudflare_evidence.append(
            "Cloudflare Cf-Ray response header"
        )

    if "cf-cache-status" in normalized_headers:
        cloudflare_evidence.append(
            "Cloudflare cache response header"
        )

    server = normalized_headers.get("server", "")

    if "cloudflare" in server.lower():
        cloudflare_evidence.append(
            "Server header identifies Cloudflare"
        )

    if cloudflare_evidence:
        detections.append(
            create_detection(
                name="Traffic Protection Service",
                value="Cloudflare",
                confidence="High",
                evidence=cloudflare_evidence,
            )
        )

    # WordPress detection
    wordpress_evidence = []

    if "wp-content" in normalized_html:
        wordpress_evidence.append(
            "HTML references the default wp-content path"
        )

    if "wp-includes" in normalized_html:
        wordpress_evidence.append(
            "HTML references the wp-includes path"
        )

    if (
        'name="generator"' in normalized_html
        and "wordpress" in normalized_html
    ):
        wordpress_evidence.append(
            "HTML generator metadata identifies WordPress"
        )

    if wordpress_evidence:
        confidence = (
            "High"
            if len(wordpress_evidence) >= 2
            else "Medium"
        )
        detections.append(
            create_detection(
                name="Website Platform",
                value="WordPress",
                confidence=confidence,
                evidence=wordpress_evidence,
            )
        )

    # Public frontend-library references are valid technology evidence even
    # when the origin platform and Server header are hidden.
    jquery_references = re.findall(
        r"""(?:src|href)\s*=\s*["'][^"']*jquery[^"']*["']""",
        normalized_html,
    )
    if jquery_references:
        detections.append(
            create_detection(
                name="Frontend Library",
                value="jQuery",
                confidence="Medium",
                evidence=[
                    (
                        f"HTML references {len(jquery_references)} "
                        "jQuery-named resource(s)."
                    )
                ],
            )
        )

    bootstrap_references = re.findall(
        r"""(?:src|href)\s*=\s*["'][^"']*bootstrap[^"']*["']""",
        normalized_html,
    )
    if bootstrap_references:
        detections.append(
            create_detection(
                name="Frontend Framework",
                value="Bootstrap",
                confidence="Medium",
                evidence=[
                    (
                        f"HTML references {len(bootstrap_references)} "
                        "Bootstrap-named resource(s)."
                    )
                ],
            )
        )

    if (
        "__viewstate" in normalized_html
        or "__eventvalidation" in normalized_html
    ):
        detections.append(
            create_detection(
                name="Application Framework",
                value="Microsoft ASP.NET",
                confidence="Medium",
                evidence=[
                    "HTML contains standard ASP.NET Web Forms state fields."
                ],
            )
        )

    # A Server header is only a weak signal because it may
    # describe a proxy rather than the origin web server.
    if server and "cloudflare" not in server.lower():
        detections.append(
            create_detection(
                name="Server Header",
                value=server,
                confidence="Low",
                evidence=[
                    "The website publicly returned a Server header"
                ],
                status="Observed",
            )
        )

    if not detections:
        detections.append(
            create_detection(
                name="Website Technology",
                value=(
                    "WebShield found insufficient public evidence "
                    "to identify the technology."
                ),
                confidence="None",
                evidence=[],
                status="Not Detected",
            )
        )

    return detections


def detect_technologies(domain: str, response=None):
    url = f"https://{domain}"

    try:
        if response is None:
            response = safe_get(
                url,
                timeout=10,
            )

        detections = detect_technologies_from_evidence(
            response.headers,
            response.text,
        )

        return {
            "name": "Technology Detection",
            "url": response.url,
            "checks": detections,
        }

    except requests.RequestException as error:
        return {
            "name": "Technology Detection",
            "url": url,
            "checks": [
                create_detection(
                    name="Website Technology",
                    value=(
                        "Technology detection could not be completed."
                    ),
                    confidence="None",
                    evidence=[],
                    status="Unavailable",
                )
            ],
            "error": str(error),
        }
