from html.parser import HTMLParser
from urllib.parse import urlparse

import requests

from app.utils.safe_http import safe_get


RESOURCE_ATTRIBUTES = {
    "script": ("src",),
    "img": ("src", "srcset"),
    "link": ("href",),
    "iframe": ("src",),
    "audio": ("src",),
    "video": ("src", "poster"),
    "source": ("src", "srcset"),
    "track": ("src",),
    "embed": ("src",),
    "object": ("data",),
    "input": ("src",),
}

LOADED_LINK_RELATIONS = {
    "stylesheet",
    "preload",
    "modulepreload",
    "icon",
    "manifest",
}


class MixedContentParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.findings = []
        self.seen = set()

    def add_finding(self, tag, attribute, resource_url):
        clean_url = resource_url.strip()

        if not clean_url.lower().startswith("http://"):
            return

        key = (
            tag.lower(),
            attribute.lower(),
            clean_url,
        )

        if key in self.seen:
            return

        self.seen.add(key)

        self.findings.append({
            "name": f"Insecure {tag} resource",
            "tag": tag,
            "attribute": attribute,
            "url": clean_url,
            "status": "Needs Attention",
            "message": (
                f"The HTTPS page loads a {tag} resource "
                f"through an insecure HTTP connection."
            ),
        })

    def inspect_attributes(self, tag, attributes):
        tag = tag.lower()

        if tag not in RESOURCE_ATTRIBUTES:
            return

        allowed_attributes = RESOURCE_ATTRIBUTES[tag]
        attribute_map = dict(attributes)

        if tag == "link":
            relation_values = set(
                str(attribute_map.get("rel", ""))
                .lower()
                .split()
            )

            if not relation_values.intersection(
                LOADED_LINK_RELATIONS
            ):
                return

        for attribute in allowed_attributes:
            value = attribute_map.get(attribute)

            if not value:
                continue

            if attribute == "srcset":
                candidates = value.split(",")

                for candidate in candidates:
                    resource_url = (
                        candidate.strip().split(" ")[0]
                    )

                    self.add_finding(
                        tag,
                        attribute,
                        resource_url,
                    )

            else:
                self.add_finding(
                    tag,
                    attribute,
                    value,
                )    

    def handle_starttag(self, tag, attributes):
        self.inspect_attributes(tag, attributes)

    def handle_startendtag(self, tag, attributes):
        self.inspect_attributes(tag, attributes)


def analyze_mixed_content(
    html_content: str,
    content_truncated: bool = False,
):
    parser = MixedContentParser()
    parser.feed(html_content)

    all_findings = parser.findings
    displayed_findings = all_findings[:50]

    if all_findings:
        return {
            "status": "Needs Attention",
            "message": (
                f"WebShield found {len(all_findings)} insecure "
                f"resource reference(s) in the homepage HTML."
            ),
            "checks": displayed_findings,
            "total_found": len(all_findings),
            "results_limited": len(all_findings) > 50,
        }

    if content_truncated:
        return {
            "status": "Review",
            "message": (
                "No mixed content was found in the inspected "
                "part of the homepage, but the response was "
                "too large to inspect completely."
            ),
            "checks": [],
            "total_found": 0,
            "results_limited": False,
        }

    return {
        "status": "Protected",
        "message": (
            "No insecure HTTP resource references were found "
            "in the initial homepage HTML."
        ),
        "checks": [],
        "total_found": 0,
        "results_limited": False,
    }


def check_mixed_content(domain: str, response=None):
    requested_url = f"https://{domain}"

    try:
        if response is None:
            response = safe_get(
               requested_url,
               timeout=10,
        )

        final_scheme = urlparse(response.url).scheme.lower()

        if final_scheme != "https":
            return {
                "name": "Mixed Content",
                "domain": domain,
                "url": response.url,
                "status": "Needs Attention",
                "message": (
                    "The homepage did not remain on a secure "
                    "HTTPS connection."
                ),
                "checks": [],
                "total_found": 0,
                "results_limited": False,
                "scope": "Initial homepage HTML only",
                "score_eligible": False,
            }

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if "text/html" not in content_type:
            return {
                "name": "Mixed Content",
                "domain": domain,
                "url": response.url,
                "status": "Not Applicable",
                "message": (
                    "The homepage response was not HTML, so "
                    "mixed HTML resources were not inspected."
                ),
                "checks": [],
                "total_found": 0,
                "results_limited": False,
                "scope": "Initial homepage HTML only",
                "score_eligible": False,
            }

        result = analyze_mixed_content(
            response.text,
            getattr(
                response,
                "webshield_content_truncated",
                False,
            ),
        )

        return {
            "name": "Mixed Content",
            "domain": domain,
            "url": response.url,
            "status": result["status"],
            "message": result["message"],
            "checks": result["checks"],
            "total_found": result["total_found"],
            "results_limited": result["results_limited"],
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
        }

    except requests.RequestException as error:
        return {
            "name": "Mixed Content",
            "domain": domain,
            "url": requested_url,
            "status": "Unavailable",
            "message": (
                "The mixed-content check could not be completed."
            ),
            "checks": [],
            "total_found": 0,
            "results_limited": False,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
            "error": str(error),
        }