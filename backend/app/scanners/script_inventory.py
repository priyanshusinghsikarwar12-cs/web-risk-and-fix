from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from app.utils.safe_http import safe_get


MAX_DISPLAYED_SCRIPTS = 100


def classify_script_host(page_host, script_host):
    page_host = (page_host or "").lower()
    script_host = (script_host or "").lower()

    if script_host == page_host:
        return "Same Host"

    if (
        script_host.endswith(f".{page_host}")
        or page_host.endswith(f".{script_host}")
    ):
        return "Related Host"

    return "External Host"


class ScriptInventoryParser(HTMLParser):
    def __init__(self, page_url):
        super().__init__(convert_charrefs=True)

        self.page_url = page_url
        self.page_host = urlparse(page_url).hostname
        self.scripts = []
        self.seen_urls = set()
        self.inline_script_count = 0

    def handle_starttag(self, tag, attributes):
        if tag.lower() != "script":
            return

        attribute_map = dict(attributes)
        source = attribute_map.get("src")

        if not source:
            self.inline_script_count += 1
            return

        absolute_url = urljoin(
            self.page_url,
            source.strip(),
        )

        parsed_url = urlparse(absolute_url)

        if parsed_url.scheme.lower() not in {
            "http",
            "https",
        }:
            return

        if not parsed_url.hostname:
            return

        if absolute_url in self.seen_urls:
            return

        self.seen_urls.add(absolute_url)

        relationship = classify_script_host(
            self.page_host,
            parsed_url.hostname,
        )

        self.scripts.append({
            "name": parsed_url.hostname,
            "url": absolute_url,
            "host": parsed_url.hostname,
            "relationship": relationship,
            "secure_transport": (
                parsed_url.scheme.lower() == "https"
            ),
            "integrity_attribute": bool(
                attribute_map.get("integrity")
            ),
            "crossorigin_attribute": bool(
                attribute_map.get("crossorigin")
            ),
            "script_type": (
                attribute_map.get("type")
                or "classic"
            ),
            "status": (
                "Needs Attention"
                if parsed_url.scheme.lower() == "http"
                else "Observed"
            ),
            "message": (
                "This script uses an insecure HTTP connection."
                if parsed_url.scheme.lower() == "http"
                else (
                    "This JavaScript file is referenced by "
                    "the homepage."
                )
            ),
        })


def analyze_script_inventory(
    html_content,
    page_url,
    content_truncated=False,
):
    parser = ScriptInventoryParser(page_url)
    parser.feed(html_content)

    scripts = parser.scripts

    external_count = sum(
        script["relationship"] == "External Host"
        for script in scripts
    )

    insecure_count = sum(
        not script["secure_transport"]
        for script in scripts
    )

    if content_truncated:
        status = "Review"
        message = (
            "WebShield created a partial script inventory, "
            "but the homepage response was too large to "
            "inspect completely."
        )

    elif insecure_count:
        status = "Needs Attention"
        message = (
            f"WebShield found {insecure_count} script(s) "
            f"using an insecure HTTP connection."
        )

    elif external_count:
        status = "Observed"
        message = (
            f"The homepage references {external_count} "
            f"script(s) from external hosts. External does "
            f"not automatically mean unsafe."
        )

    else:
        status = "No External Scripts"
        message = (
            "No scripts from external hosts were observed "
            "in the initial homepage HTML."
        )

    return {
        "status": status,
        "message": message,
        "checks": scripts[:MAX_DISPLAYED_SCRIPTS],
        "total_script_files": len(scripts),
        "external_script_count": external_count,
        "inline_script_count": parser.inline_script_count,
        "insecure_script_count": insecure_count,
        "results_limited": (
            len(scripts) > MAX_DISPLAYED_SCRIPTS
        ),
    }


def check_script_inventory(domain, response=None):
    requested_url = f"https://{domain}"

    try:
        if response is None:
            response = safe_get(
                requested_url,
            timeout=10,
        )

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if "text/html" not in content_type:
            return {
                "name": "Script Inventory",
                "domain": domain,
                "url": response.url,
                "status": "Not Applicable",
                "message": (
                    "The homepage response was not HTML."
                ),
                "checks": [],
                "total_script_files": 0,
                "external_script_count": 0,
                "inline_script_count": 0,
                "insecure_script_count": 0,
                "results_limited": False,
                "scope": "Initial homepage HTML only",
                "score_eligible": False,
            }

        result = analyze_script_inventory(
            response.text,
            response.url,
            getattr(
                response,
                "webshield_content_truncated",
                False,
            ),
        )

        return {
            "name": "Script Inventory",
            "domain": domain,
            "url": response.url,
            "status": result["status"],
            "message": result["message"],
            "checks": result["checks"],
            "total_script_files": (
                result["total_script_files"]
            ),
            "external_script_count": (
                result["external_script_count"]
            ),
            "inline_script_count": (
                result["inline_script_count"]
            ),
            "insecure_script_count": (
                result["insecure_script_count"]
            ),
            "results_limited": result["results_limited"],
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
        }

    except requests.RequestException as error:
        return {
            "name": "Script Inventory",
            "domain": domain,
            "url": requested_url,
            "status": "Unavailable",
            "message": (
                "The script inventory could not be completed."
            ),
            "checks": [],
            "total_script_files": 0,
            "external_script_count": 0,
            "inline_script_count": 0,
            "insecure_script_count": 0,
            "results_limited": False,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
            "error": str(error),
        }