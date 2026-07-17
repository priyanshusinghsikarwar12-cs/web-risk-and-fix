from html.parser import HTMLParser
from urllib.parse import urljoin

import requests

from app.utils.safe_http import safe_get


PRIVACY_LINK_TERMS = {
    "privacy",
    "privacy policy",
    "privacy notice",
    "data protection",
}

PRIVACY_URL_TERMS = {
    "/privacy",
    "privacy-policy",
    "privacy_policy",
    "privacy-notice",
    "data-protection",
}

CONSENT_TEXT_TERMS = {
    "accept all cookies",
    "accept cookies",
    "reject all cookies",
    "manage cookies",
    "cookie preferences",
    "cookie settings",
    "consent preferences",
    "manage consent",
}

CONSENT_ATTRIBUTE_TERMS = {
    "cookie-banner",
    "cookie-consent",
    "consent-banner",
    "cookie-notice",
    "onetrust",
    "cookiebot",
    "trustarc",
}


class PrivacySignalsParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)

        self.base_url = base_url
        self.current_link = None
        self.privacy_links = []
        self.consent_evidence = set()
        self.page_text = []

    def inspect_attributes(self, attributes):
        attribute_text = " ".join(
            str(value).lower()
            for _, value in attributes
            if value
        )

        for term in CONSENT_ATTRIBUTE_TERMS:
            if term in attribute_text:
                self.consent_evidence.add(
                    f"HTML attribute contains '{term}'"
                )

    def handle_starttag(self, tag, attributes):
        self.inspect_attributes(attributes)

        if tag.lower() != "a":
            return

        attribute_map = dict(attributes)
        href = str(attribute_map.get("href", "")).strip()

        self.current_link = {
            "href": href,
            "text": [],
        }

    def handle_data(self, data):
        clean_text = " ".join(data.split())

        if not clean_text:
            return

        self.page_text.append(clean_text)

        if self.current_link is not None:
            self.current_link["text"].append(clean_text)

    def handle_endtag(self, tag):
        if tag.lower() != "a" or self.current_link is None:
            return

        href = self.current_link["href"]
        link_text = " ".join(
            self.current_link["text"]
        ).strip()

        lower_href = href.lower()
        lower_text = link_text.lower()

        text_matches = any(
            term in lower_text
            for term in PRIVACY_LINK_TERMS
        )

        url_matches = any(
            term in lower_href
            for term in PRIVACY_URL_TERMS
        )

        if href and (text_matches or url_matches):
            full_url = urljoin(self.base_url, href)

            if full_url not in {
                item["url"]
                for item in self.privacy_links
            }:
                self.privacy_links.append({
                    "text": link_text or "Privacy page",
                    "url": full_url,
                })

        self.current_link = None


def analyze_privacy_signals(
    html_content: str,
    base_url: str,
    content_truncated: bool = False,
):
    parser = PrivacySignalsParser(base_url)
    parser.feed(html_content)

    page_text = " ".join(parser.page_text).lower()

    for term in CONSENT_TEXT_TERMS:
        if term in page_text:
            parser.consent_evidence.add(
                f"Homepage text contains '{term}'"
            )

    privacy_observed = bool(parser.privacy_links)
    consent_observed = bool(parser.consent_evidence)

    checks = [
        {
            "name": "Privacy Policy Signal",
            "status": (
                "Observed"
                if privacy_observed
                else "Not Observed"
            ),
            "message": (
                "A privacy-related page link was found "
                "in the initial homepage HTML."
                if privacy_observed
                else
                "No privacy-related page link was observed "
                "in the initial homepage HTML."
            ),
            "links": parser.privacy_links[:10],
        },
        {
            "name": "Cookie Consent Signal",
            "status": (
                "Observed"
                if consent_observed
                else "Not Observed"
            ),
            "message": (
                "Cookie or consent interface signals were "
                "observed in the initial homepage HTML."
                if consent_observed
                else
                "No cookie consent interface signal was "
                "observed in the initial homepage HTML. "
                "A JavaScript-delivered banner may still exist."
            ),
            "evidence": sorted(
                parser.consent_evidence
            )[:10],
        },
    ]

    if privacy_observed and consent_observed:
        status = "Observed"
        message = (
            "Privacy-page and cookie-consent signals were "
            "observed on the homepage."
        )
    elif privacy_observed or consent_observed:
        status = "Partial"
        message = (
            "WebShield observed some privacy or consent "
            "signals, but not both signals."
        )
    elif content_truncated:
        status = "Review"
        message = (
            "No privacy or consent signal was observed in "
            "the inspected content, but the homepage response "
            "was too large to inspect completely."
        )
    else:
        status = "Not Observed"
        message = (
            "No obvious privacy-policy link or cookie-consent "
            "interface signal was observed in the initial "
            "homepage HTML."
        )

    return {
        "status": status,
        "message": message,
        "checks": checks,
        "privacy_link_count": len(
            parser.privacy_links
        ),
        "consent_signal_count": len(
            parser.consent_evidence
        ),
    }


def check_privacy_signals(
    domain: str,
    response=None,
):
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
                "name": "Privacy and Consent Signals",
                "domain": domain,
                "url": response.url,
                "status": "Not Applicable",
                "message": (
                    "The homepage response was not HTML."
                ),
                "checks": [],
                "privacy_link_count": 0,
                "consent_signal_count": 0,
                "scope": "Initial homepage HTML only",
                "score_eligible": False,
            }

        result = analyze_privacy_signals(
            response.text,
            response.url,
            getattr(
                response,
                "webshield_content_truncated",
                False,
            ),
        )

        return {
            "name": "Privacy and Consent Signals",
            "domain": domain,
            "url": response.url,
            "status": result["status"],
            "message": result["message"],
            "checks": result["checks"],
            "privacy_link_count": (
                result["privacy_link_count"]
            ),
            "consent_signal_count": (
                result["consent_signal_count"]
            ),
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
        }

    except requests.RequestException as error:
        return {
            "name": "Privacy and Consent Signals",
            "domain": domain,
            "url": requested_url,
            "status": "Unavailable",
            "message": (
                "The privacy and consent signal check "
                "could not be completed."
            ),
            "checks": [],
            "privacy_link_count": 0,
            "consent_signal_count": 0,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
            "error": str(error),
        }