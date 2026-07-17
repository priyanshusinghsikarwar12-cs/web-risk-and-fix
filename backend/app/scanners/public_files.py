import re
from datetime import datetime, timezone

import requests

from app.utils.safe_http import safe_get


REVIEW_PATH_HINTS = {
    "admin",
    "backup",
    "config",
    "debug",
    "private",
    "secret",
    "staging",
    "database",
}


def looks_like_html(content):
    beginning = content.lstrip().lower()[:500]

    return (
        "<html" in beginning
        or "<!doctype html" in beginning
    )


def unavailable_result(name, message):
    return {
        "name": name,
        "status": "Unavailable",
        "message": message,
    }


def analyze_robots(status_code, content, url):
    if status_code in {404, 410}:
        return {
            "name": "robots.txt",
            "status": "Not Found",
            "message": "No robots.txt file was found.",
            "url": url,
            "disallowed_path_count": 0,
            "sitemap_reference_count": 0,
            "review_paths": [],
        }

    if not 200 <= status_code < 300:
        return unavailable_result(
            "robots.txt",
            "The robots.txt request returned an unexpected status.",
        )

    if looks_like_html(content):
        return {
            "name": "robots.txt",
            "status": "Review",
            "message": (
                "The robots.txt address returned HTML instead "
                "of a valid robots file."
            ),
            "url": url,
            "disallowed_path_count": 0,
            "sitemap_reference_count": 0,
            "review_paths": [],
        }

    directives = []

    for line in content.splitlines():
        clean_line = line.split("#", 1)[0].strip()

        if ":" not in clean_line:
            continue

        name, value = clean_line.split(":", 1)

        directives.append(
            (
                name.strip().lower(),
                value.strip(),
            )
        )

    disallowed_paths = [
        value
        for name, value in directives
        if name == "disallow" and value
    ]

    sitemap_references = [
        value
        for name, value in directives
        if name == "sitemap" and value
    ]

    review_paths = []

    for path in disallowed_paths:
        lowered_path = path.lower()

        if any(
            hint in lowered_path
            for hint in REVIEW_PATH_HINTS
        ):
            review_paths.append(path)

    review_paths = review_paths[:20]

    if review_paths:
        status = "Review"
        message = (
            "robots.txt contains paths with sensitive-looking "
            "names. These are review clues, not confirmed "
            "security vulnerabilities."
        )

    else:
        status = "Found"
        message = (
            "A robots.txt file was found and inspected."
        )

    return {
        "name": "robots.txt",
        "status": status,
        "message": message,
        "url": url,
        "disallowed_path_count": len(disallowed_paths),
        "sitemap_reference_count": len(
            sitemap_references
        ),
        "review_paths": review_paths,
    }


def analyze_sitemap(status_code, content, url):
    if status_code in {404, 410}:
        return {
            "name": "sitemap.xml",
            "status": "Not Found",
            "message": "No sitemap.xml file was found.",
            "url": url,
            "url_count": 0,
            "insecure_url_count": 0,
        }

    if not 200 <= status_code < 300:
        return unavailable_result(
            "sitemap.xml",
            "The sitemap request returned an unexpected status.",
        )

    lowered_content = content.lower()

    valid_structure = (
        "<urlset" in lowered_content
        or "<sitemapindex" in lowered_content
    )

    if not valid_structure:
        return {
            "name": "sitemap.xml",
            "status": "Review",
            "message": (
                "The sitemap address responded, but WebShield "
                "could not confirm a standard sitemap structure."
            ),
            "url": url,
            "url_count": 0,
            "insecure_url_count": 0,
        }

    locations = re.findall(
        r"<(?:[a-z0-9_-]+:)?loc\b[^>]*>(.*?)</"
        r"(?:[a-z0-9_-]+:)?loc>",
        content,
        flags=re.IGNORECASE | re.DOTALL,
    )

    insecure_url_count = sum(
        location.strip().lower().startswith("http://")
        for location in locations
    )

    status = (
        "Review"
        if insecure_url_count
        else "Found"
    )

    message = (
        f"The sitemap contains {insecure_url_count} insecure "
        f"HTTP URL(s)."
        if insecure_url_count
        else "A valid sitemap structure was found."
    )

    return {
        "name": "sitemap.xml",
        "status": status,
        "message": message,
        "url": url,
        "url_count": len(locations),
        "insecure_url_count": insecure_url_count,
    }


def parse_expiry(value):
    try:
        parsed_value = value.strip().replace(
            "Z",
            "+00:00",
        )

        expiry = datetime.fromisoformat(parsed_value)

        if expiry.tzinfo is None:
            return None

        return expiry.astimezone(timezone.utc)

    except (TypeError, ValueError):
        return None


def analyze_security_txt(
    status_code,
    content,
    url,
):
    if status_code in {404, 410}:
        return {
            "name": "security.txt",
            "status": "Not Found",
            "message": "No security.txt file was found.",
            "url": url,
            "contact_count": 0,
            "expires": None,
        }

    if not 200 <= status_code < 300:
        return unavailable_result(
            "security.txt",
            "The security.txt request returned an unexpected status.",
        )

    if looks_like_html(content):
        return {
            "name": "security.txt",
            "status": "Review",
            "message": (
                "The security.txt address returned HTML "
                "instead of a valid security.txt file."
            ),
            "url": url,
            "contact_count": 0,
            "expires": None,
        }

    fields = {}

    for line in content.splitlines():
        clean_line = line.strip()

        if (
            not clean_line
            or clean_line.startswith("#")
            or ":" not in clean_line
        ):
            continue

        name, value = clean_line.split(":", 1)

        fields.setdefault(
            name.strip().lower(),
            [],
        ).append(value.strip())

    contacts = fields.get("contact", [])
    expiry_values = fields.get("expires", [])
    expiry = (
        parse_expiry(expiry_values[0])
        if expiry_values
        else None
    )

    problems = []

    if not contacts:
        problems.append("Contact is missing.")

    if not expiry_values:
        problems.append("Expires is missing.")

    elif expiry is None:
        problems.append("Expires is invalid.")

    elif expiry <= datetime.now(timezone.utc):
        problems.append("The security.txt file has expired.")

    if problems:
        status = "Needs Attention"
        message = " ".join(problems)

    else:
        status = "Configured"
        message = (
            "A valid security contact and future expiry "
            "date were found."
        )

    return {
        "name": "security.txt",
        "status": status,
        "message": message,
        "url": url,
        "contact_count": len(contacts),
        "expires": (
            expiry.isoformat()
            if expiry
            else None
        ),
    }

def label_security_txt_location(
    result,
    preferred_location,
):
    labelled_result = result.copy()

    labelled_result["location"] = (
        "Preferred"
        if preferred_location
        else "Legacy"
    )

    if (
        not preferred_location
        and labelled_result.get("status") == "Configured"
    ):
        labelled_result["status"] = "Review"
        labelled_result["message"] = (
            "A valid security.txt file was found only at the "
            "legacy /security.txt location. Publish it at "
            "/.well-known/security.txt for RFC 9116 alignment."
        )

    return labelled_result    


def fetch_and_analyze(url, analyzer):
    try:
        response = safe_get(
            url,
            timeout=10,
            max_bytes=500_000,
        )

        return analyzer(
            response.status_code,
            response.text,
            response.url,
        )

    except requests.RequestException as error:
        result = unavailable_result(
            url,
            "The file check could not be completed.",
        )

        result["url"] = url
        result["error"] = str(error)

        return result


def check_public_security_files(domain):
    robots = fetch_and_analyze(
        f"https://{domain}/robots.txt",
        analyze_robots,
    )

    sitemap = fetch_and_analyze(
        f"https://{domain}/sitemap.xml",
        analyze_sitemap,
    )

    security_txt = fetch_and_analyze(
        f"https://{domain}/.well-known/security.txt",
        analyze_security_txt,
    )

    security_txt = label_security_txt_location(
        security_txt,
        preferred_location=True,
    )

    if security_txt["status"] == "Not Found":
        security_txt = fetch_and_analyze(
            f"https://{domain}/security.txt",
            analyze_security_txt,
        )

        security_txt = label_security_txt_location(
            security_txt,
            preferred_location=False,
        )    
    checks = [
        robots,
        sitemap,
        security_txt,
    ]

    if any(
        check["status"] == "Needs Attention"
        for check in checks
    ):
        status = "Needs Attention"

    elif any(
        check["status"] in {"Review", "Unavailable"}
        for check in checks
    ):
        status = "Review"

    else:
        status = "Completed"

    return {
        "name": "Public Security Files",
        "domain": domain,
        "status": status,
        "message": (
            "WebShield checked robots.txt, sitemap.xml, "
            "and security.txt."
        ),
        "checks": checks,
        "score_eligible": False,
    }