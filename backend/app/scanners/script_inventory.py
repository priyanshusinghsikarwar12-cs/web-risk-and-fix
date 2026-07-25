import re
from html.parser import HTMLParser
from urllib.parse import (
    unquote,
    urljoin,
    urlparse,
)

import requests

from app.utils.safe_http import safe_get
from urllib.parse import (
    parse_qs,
    unquote,
    urljoin,
    urlparse,
)


MAX_DISPLAYED_SCRIPTS = 100

VERSION_PATTERN = (
    r"(?P<version>"
    r"\d+\.\d+(?:\.\d+)?"
    r"(?:[-+][0-9a-zA-Z.-]+)?"
    r")"
)


KNOWN_LIBRARY_PATTERNS = [
    (
        "jQuery",
        r"(?:^|[/_.-])jquery"
        r"(?:\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
    (
        "Bootstrap",
        r"(?:^|[/_.-])bootstrap"
        r"(?:\.bundle)?(?:\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
    (
        "Lodash",
        r"(?:^|[/_.-])lodash"
        r"(?:\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
    (
        "Moment.js",
        r"(?:^|[/_.-])moment"
        r"(?:\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
    (
        "Axios",
        r"(?:^|[/_.-])axios"
        r"(?:\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
    (
        "React DOM",
        r"(?:^|[/_.-])react-dom"
        r"(?:\.production\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
    (
        "React",
        r"(?:^|[/_.-])react"
        r"(?:\.production\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
    (
        "Vue",
        r"(?:^|[/_.-])vue"
        r"(?:\.runtime)?(?:\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
    (
        "Angular",
        r"(?:^|[/_.-])angular"
        r"(?:\.min)?[-.]v?"
        + VERSION_PATTERN,
    ),
]

KNOWN_LIBRARY_NAMES = [
    (
        "jQuery UI",
        r"(?:^|[/_.-])jquery-ui"
        r"(?:\.min)?\.js$",
    ),
    (
        "jQuery Migrate",
        r"(?:^|[/_.-])jquery-migrate"
        r"(?:\.min)?\.js$",
    ),
    (
        "jQuery",
        r"(?:^|[/_.-])jquery"
        r"(?:-core)?(?:\.min)?\.js$",
    ),
    (
        "Bootstrap",
        r"(?:^|[/_.-])bootstrap"
        r"(?:\.bundle)?(?:\.min)?\.js$",
    ),
    (
        "Lodash",
        r"(?:^|[/_.-])lodash"
        r"(?:\.min)?\.js$",
    ),
    (
        "Moment.js",
        r"(?:^|[/_.-])moment"
        r"(?:\.min)?\.js$",
    ),
    (
        "Axios",
        r"(?:^|[/_.-])axios"
        r"(?:\.min)?\.js$",
    ),
    (
        "React DOM",
        r"(?:^|[/_.-])react-dom"
        r"(?:\.production\.min)?\.js$",
    ),
    (
        "React",
        r"(?:^|[/_.-])react"
        r"(?:\.production\.min)?\.js$",
    ),
    (
        "Vue",
        r"(?:^|[/_.-])vue"
        r"(?:\.runtime)?(?:\.min)?\.js$",
    ),
    (
        "Angular",
        r"(?:^|[/_.-])angular"
        r"(?:\.min)?\.js$",
    ),
]    



def library_result(
    name,
    version,
    confidence,
    evidence,
):
    return {
        "name": name,
        "version": version,
        "confidence": confidence,
        "evidence": evidence,
    }


def detect_library_from_url(script_url):
    parsed_url = urlparse(script_url)
    host = (parsed_url.hostname or "").lower()
    path = unquote(parsed_url.path)

    if host.endswith("cdn.jsdelivr.net"):
        match = re.search(
            r"/npm/"
            r"(?P<package>(?:@[^/]+/)?[^/@]+)"
            r"@"
            + VERSION_PATTERN
            + r"(?:/|$)",
            path,
            flags=re.IGNORECASE,
        )

        if match:
            return library_result(
                match.group("package"),
                match.group("version"),
                "High",
                "Version declared in jsDelivr package URL",
            )

    if host == "unpkg.com":
        match = re.search(
            r"^/"
            r"(?P<package>(?:@[^/]+/)?[^/@]+)"
            r"@"
            + VERSION_PATTERN
            + r"(?:/|$)",
            path,
            flags=re.IGNORECASE,
        )

        if match:
            return library_result(
                match.group("package"),
                match.group("version"),
                "High",
                "Version declared in unpkg package URL",
            )

    if host == "cdnjs.cloudflare.com":
        match = re.search(
            r"/ajax/libs/"
            r"(?P<package>[^/]+)/"
            + VERSION_PATTERN
            + r"/",
            path,
            flags=re.IGNORECASE,
        )

        if match:
            return library_result(
                match.group("package"),
                match.group("version"),
                "High",
                "Version declared in cdnjs package URL",
            )

    lowered_path = path.lower()

    for library_name, pattern in KNOWN_LIBRARY_PATTERNS:
        match = re.search(
            pattern,
            lowered_path,
            flags=re.IGNORECASE,
        )

        if match:
            return library_result(
                library_name,
                match.group("version"),
                "Medium",
                "Library name and version observed in filename",
            )
    query_values = parse_qs(parsed_url.query)
    query_version = (
        query_values.get("ver", [None])[0]
        or query_values.get("version", [None])[0]
        or query_values.get("v", [None])[0]
    )

    valid_query_version = None

    if query_version and re.fullmatch(
        r"\d+\.\d+(?:\.\d+)?"
        r"(?:[-+][0-9a-zA-Z.-]+)?",
        query_version,
    ):
        valid_query_version = query_version

    for library_name, pattern in KNOWN_LIBRARY_NAMES:
        if re.search(
            pattern,
            lowered_path,
            flags=re.IGNORECASE,
        ):
            if valid_query_version:
                return library_result(
                    library_name,
                    valid_query_version,
                    "Low",
                    (
                        "Library filename observed; possible "
                        "version found in URL query parameter"
                    ),
                )

            return library_result(
                library_name,
                None,
                "Low",
                "Known library filename observed",
            )            

    return None


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
        detected_library = detect_library_from_url(
            absolute_url
        )        

        self.scripts.append({
            "name": parsed_url.hostname,
            "url": absolute_url,
            "host": parsed_url.hostname,
            "relationship": relationship,
            "library": detected_library,
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

    detected_library_count = sum(
        script["library"] is not None
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
        "detected_library_count": detected_library_count,
        "results_limited": (
            len(scripts) > MAX_DISPLAYED_SCRIPTS
        ),
    }


def check_script_inventory(
    domain,
    response=None,
    same_host_only=False,
    allow_invalid_tls=False,
):
    requested_url = f"https://{domain}"

    try:
        if response is None:
            response = safe_get(
                requested_url,
                timeout=10,
                allowed_redirect_host=(domain if same_host_only else None),
                redirect_delay_seconds=(0.5 if same_host_only else 0),
                verify_tls=not allow_invalid_tls,
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
                "detected_library_count": 0,
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

            "detected_library_count": (
                result["detected_library_count"]
    
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
            "detected_library_count": 0,
            "results_limited": False,
            "scope": "Initial homepage HTML only",
            "score_eligible": False,
            "error": str(error),
        }
