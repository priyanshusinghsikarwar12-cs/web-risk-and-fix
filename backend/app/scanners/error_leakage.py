import re
from urllib.parse import urlparse

import requests

from app.utils.safe_http import safe_get


ERROR_PATTERNS = [
    {
        "name": "Python Stack Trace",
        "pattern": re.compile(
            r"Traceback\s+\(most recent call last\):",
            re.IGNORECASE,
        ),
        "message": (
            "The error page appears to expose a Python "
            "application stack trace."
        ),
    },
    {
        "name": "Django Debug Page",
        "pattern": re.compile(
            r"(Django Version|"
            r"Using the URLconf defined in|"
            r"settings\.py)",
            re.IGNORECASE,
        ),
        "message": (
            "The error page appears to expose Django "
            "debugging information."
        ),
    },
    {
        "name": "Werkzeug Debugger",
        "pattern": re.compile(
            r"(Werkzeug Debugger|"
            r"Debugger PIN|"
            r"interactive debugger)",
            re.IGNORECASE,
        ),
        "message": (
            "The error page appears to expose the Werkzeug "
            "development debugger."
        ),
    },
    {
        "name": "PHP Error Details",
        "pattern": re.compile(
            r"(Fatal error|Warning|Notice):"
            r".{0,300}\bin\b.{0,300}"
            r"\bon line\s+\d+",
            re.IGNORECASE | re.DOTALL,
        ),
        "message": (
            "The error page appears to expose PHP file or "
            "line-number information."
        ),
    },
    {
        "name": "ASP.NET Error Details",
        "pattern": re.compile(
            r"(Server Error in ['\"]?/['\"]? Application|"
            r"ASP\.NET.*Stack Trace|"
            r"System\.[A-Za-z.]+Exception)",
            re.IGNORECASE,
        ),
        "message": (
            "The error page appears to expose ASP.NET "
            "application details."
        ),
    },
    {
        "name": "Java Exception",
        "pattern": re.compile(
            r"\b(?:java|javax)\.[A-Za-z0-9_.$]+"
            r"(?:Exception|Error)\b",
            re.IGNORECASE,
        ),
        "message": (
            "The error page appears to expose a Java "
            "exception name."
        ),
    },
    {
        "name": "Node.js Stack Trace",
        "pattern": re.compile(
            r"\bat\s+(?:new\s+)?"
            r"[A-Za-z0-9_.$<>]+"
            r"\s*\([^)\r\n]+:\d+:\d+\)",
            re.IGNORECASE,
        ),
        "message": (
            "The error page appears to expose a Node.js "
            "stack trace."
        ),
    },
    {
        "name": "Database Error Details",
        "pattern": re.compile(
            r"(SQLSTATE\[|"
            r"You have an error in your SQL syntax|"
            r"PG::[A-Za-z]+Error|"
            r"ORA-\d{5})",
            re.IGNORECASE,
        ),
        "message": (
            "The error page appears to expose database "
            "error information."
        ),
    },
]


SERVER_VERSION_PATTERN = re.compile(
    r"\b(?:Apache|nginx|Microsoft-IIS|LiteSpeed)"
    r"/\d+(?:\.\d+)*",
    re.IGNORECASE,
)


def analyze_error_response(
    status_code,
    headers,
    body,
    requested_url,
    final_url,
    content_truncated=False,
):
    checks = []

    for error_pattern in ERROR_PATTERNS:
        if error_pattern["pattern"].search(body):
            checks.append({
                "name": error_pattern["name"],
                "status": "Needs Attention",
                "message": error_pattern["message"],
                "source": "Error page body",
            })

    server_header = headers.get("Server", "")

    if SERVER_VERSION_PATTERN.search(server_header):
        checks.append({
            "name": "Detailed Server Version",
            "status": "Review",
            "message": (
                "The response identifies a detailed web-server "
                "version. Consider hiding unnecessary version "
                "details."
            ),
            "source": "Server response header",
        })

    if headers.get("X-Powered-By"):
        checks.append({
            "name": "Technology Disclosure",
            "status": "Review",
            "message": (
                "The response exposes an X-Powered-By header "
                "that reveals implementation information."
            ),
            "source": "X-Powered-By response header",
        })

    if headers.get("X-AspNet-Version"):
        checks.append({
            "name": "ASP.NET Version Disclosure",
            "status": "Review",
            "message": (
                "The response exposes an ASP.NET version header."
            ),
            "source": "X-AspNet-Version response header",
        })

    requested = urlparse(requested_url)
    final = urlparse(final_url)

    redirected = (
        requested.netloc.lower() != final.netloc.lower()
        or requested.path.rstrip("/")
        != final.path.rstrip("/")
    )

    serious_findings = [
        check
        for check in checks
        if check["status"] == "Needs Attention"
    ]

    review_findings = [
        check
        for check in checks
        if check["status"] == "Review"
    ]

    if serious_findings:
        status = "Needs Attention"
        message = (
            f"WebShield observed {len(serious_findings)} "
            f"type(s) of detailed error information."
        )

    elif review_findings:
        status = "Review"
        message = (
            "No stack trace was observed, but the response "
            "exposes unnecessary technology details."
        )

    elif redirected:
        status = "Inconclusive"
        message = (
            "The missing-page request was redirected, so "
            "WebShield could not reliably inspect the site's "
            "normal error page."
        )

    elif content_truncated:
        status = "Review"
        message = (
            "No obvious error leakage was found in the "
            "inspected content, but the response was too "
            "large to inspect completely."
        )

    else:
        status = "Not Observed"
        message = (
            "No obvious stack trace, database error, or "
            "detailed debug page was observed in the tested "
            "missing-page response."
        )

    return {
        "name": "Error Information Leakage",
        "status": status,
        "message": message,
        "requested_url": requested_url,
        "final_url": final_url,
        "status_code": status_code,
        "redirected": redirected,
        "content_truncated": content_truncated,
        "checks": checks,
        "scope": "One intentionally missing page only",
        "score_eligible": False,
    }


def check_error_leakage(domain):
    requested_url = (
        f"https://{domain}/"
        f".well-known/webshield-missing-page-check"
    )

    try:
        response = safe_get(
            requested_url,
            timeout=10,
            max_bytes=250_000,
        )

        return analyze_error_response(
            response.status_code,
            response.headers,
            response.text,
            requested_url,
            response.url,
            getattr(
                response,
                "webshield_content_truncated",
                False,
            ),
        )

    except requests.RequestException as error:
        return {
            "name": "Error Information Leakage",
            "status": "Unavailable",
            "message": (
                "The error-information check could not "
                "be completed."
            ),
            "requested_url": requested_url,
            "final_url": None,
            "status_code": None,
            "redirected": None,
            "content_truncated": False,
            "checks": [],
            "scope": "One intentionally missing page only",
            "score_eligible": False,
            "error": str(error),
        }