import re
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get_once


REDIRECT_PARAMETER_NAMES = {
    "continue",
    "dest",
    "destination",
    "next",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_to",
    "returnurl",
    "url",
}
SENSITIVE_PARAMETER_PARTS = {
    "auth",
    "code",
    "cookie",
    "csrf",
    "key",
    "otp",
    "password",
    "secret",
    "session",
    "signature",
    "token",
}
STATE_CHANGING_PATH_PARTS = {
    "book",
    "buy",
    "cancel",
    "create",
    "delete",
    "logout",
    "pay",
    "purchase",
    "remove",
    "save",
    "submit",
    "transfer",
    "update",
    "upload",
    "withdraw",
}

DATABASE_ERROR_PATTERNS = {
    "MySQL": re.compile(
        r"you have an error in your sql syntax|warning.{0,40}mysql",
        re.IGNORECASE | re.DOTALL,
    ),
    "PostgreSQL": re.compile(
        r"postgresql.{0,40}error|pg_query\(|unterminated quoted string",
        re.IGNORECASE | re.DOTALL,
    ),
    "SQLite": re.compile(
        r"sqlite.{0,40}(error|exception)|sqlite3\.operationalerror",
        re.IGNORECASE | re.DOTALL,
    ),
    "Microsoft SQL Server": re.compile(
        r"unclosed quotation mark after the character string|"
        r"microsoft.{0,40}(ole db|sql server)|odbc sql server driver",
        re.IGNORECASE | re.DOTALL,
    ),
    "Oracle": re.compile(
        r"ora-\d{5}|quoted string not properly terminated",
        re.IGNORECASE,
    ),
    "Generic SQL": re.compile(
        r"sqlstate\[[0-9a-z]+\]|database query failed",
        re.IGNORECASE,
    ),
}


def _replace_parameter(url, index, value):
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs[index] = (pairs[index][0], value)
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        urlencode(pairs, doseq=True),
        "",
    ))


def _eligible_page_urls(domain, crawler):
    urls = []
    for page in (crawler or {}).get("pages", []):
        url = str(page.get("url") or "")
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() == "https"
            and clean_domain(parsed.hostname or "") == domain
            and parsed.query
            and not any(part in parsed.path.lower() for part in STATE_CHANGING_PATH_PARTS)
        ):
            urls.append(url)
    return list(dict.fromkeys(urls))


def _database_error_families(text):
    content = str(text or "")
    return {
        family
        for family, pattern in DATABASE_ERROR_PATTERNS.items()
        if pattern.search(content)
    }


def check_query_input_security(
    domain,
    crawler,
    max_requests=6,
    delay_seconds=0.5,
    fetcher=safe_get_once,
    sleeper=time.sleep,
    allow_invalid_tls=False,
):
    safe_domain = clean_domain(domain)
    if not 1 <= int(max_requests) <= 10:
        raise ValueError("Query-input testing supports 1 to 10 requests.")
    if not 0.5 <= float(delay_seconds) <= 5:
        raise ValueError("Query-input testing requires 0.5 to 5 seconds of pacing.")

    checks = []
    requests_made = 0
    tested_parameters = 0
    reflection_tests = 0
    database_error_tests = 0
    for url in _eligible_page_urls(safe_domain, crawler):
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for index, (name, _value) in enumerate(pairs):
            if requests_made >= int(max_requests):
                break
            normalized = name.strip().lower().replace("-", "_")
            if not normalized or any(part in normalized for part in SENSITIVE_PARAMETER_PARTS):
                continue

            tested_parameters += 1
            marker_id = secrets.token_hex(6)
            is_redirect = normalized in REDIRECT_PARAMETER_NAMES
            marker = (
                f"https://webshield.invalid/{marker_id}"
                if is_redirect
                else f"WSREFLECT-{marker_id}-<>\""
            )
            test_url = _replace_parameter(url, index, marker)
            if requests_made:
                sleeper(float(delay_seconds))
            try:
                response = fetcher(
                    test_url,
                    max_bytes=500_000,
                    allowed_host=safe_domain,
                    verify_tls=not allow_invalid_tls,
                )
            except requests.RequestException:
                requests_made += 1
                continue
            requests_made += 1

            if is_redirect:
                location = response.headers.get("Location", "")
                destination = urlsplit(location)
                if destination.hostname == "webshield.invalid":
                    checks.append({
                        "name": "Potential Open Redirect",
                        "status": "Needs Attention",
                        "severity": "Medium",
                        "confidence": "High",
                        "validation": "Requires Confirmation",
                        "category": "Unvalidated Redirects and Forwards",
                        "message": (
                            f"The existing '{name}' parameter caused the response "
                            "to point at an unrelated destination."
                        ),
                        "url": url,
                        "parameter": name,
                        "evidence": {
                            "status_code": response.status_code,
                            "external_destination_observed": True,
                            "destination_contacted": False,
                            "marker_value_returned": False,
                        },
                        "remediation": (
                            "Allow only approved internal destinations or map short "
                            "server-side identifiers to trusted paths."
                        ),
                    })
            else:
                reflection_tests += 1
                content_type = response.headers.get("Content-Type", "").lower()
                if (
                    200 <= response.status_code < 300
                    and "text/html" in content_type
                    and marker in response.text
                ):
                    checks.append({
                        "name": "Unescaped Query Input Reflected in HTML",
                        "status": "Needs Attention",
                        "severity": "Medium",
                        "confidence": "Medium",
                        "validation": "Requires Confirmation",
                        "category": "Injection",
                        "message": (
                            f"A harmless marker placed in the existing '{name}' "
                            "parameter returned with HTML-significant characters "
                            "unescaped. No script payload was sent."
                        ),
                        "url": url,
                        "parameter": name,
                        "evidence": {
                            "status_code": response.status_code,
                            "marker_reflected_unescaped": True,
                            "script_payload_sent": False,
                            "marker_value_returned": False,
                        },
                        "remediation": (
                            "Encode untrusted data for its exact HTML context and "
                            "validate input before rendering it."
                        ),
                    })

                if requests_made >= int(max_requests):
                    continue

                original_value = str(_value or "1")[:128]
                database_marker = f"{original_value}'"
                database_url = _replace_parameter(
                    url,
                    index,
                    database_marker,
                )
                sleeper(float(delay_seconds))
                try:
                    database_response = fetcher(
                        database_url,
                        max_bytes=500_000,
                        allowed_host=safe_domain,
                        verify_tls=not allow_invalid_tls,
                    )
                except requests.RequestException:
                    requests_made += 1
                    database_error_tests += 1
                    continue

                requests_made += 1
                database_error_tests += 1
                control_errors = _database_error_families(response.text)
                mutation_errors = _database_error_families(
                    database_response.text
                )
                new_errors = sorted(mutation_errors - control_errors)
                if new_errors:
                    checks.append({
                        "name": "Database Error Triggered by Query Input",
                        "status": "Needs Attention",
                        "severity": "High",
                        "confidence": "Medium",
                        "validation": "Requires Confirmation",
                        "category": "Injection",
                        "message": (
                            f"A harmless quote added to the existing '{name}' "
                            "parameter triggered a recognizable database-error "
                            "family that was absent from the control response."
                        ),
                        "url": url,
                        "parameter": name,
                        "evidence": {
                            "database_error_families": new_errors,
                            "control_error_absent": True,
                            "mutation_status_code": (
                                database_response.status_code
                            ),
                            "data_extraction_attempted": False,
                            "time_based_payload_sent": False,
                            "boolean_payload_sent": False,
                            "union_payload_sent": False,
                            "response_values_returned": False,
                        },
                        "remediation": (
                            "Use parameterized database queries, validate input "
                            "types, and return generic server errors without "
                            "database details."
                        ),
                    })

        if requests_made >= int(max_requests):
            break

    if checks:
        status = "Needs Attention"
        message = f"WebShield found {len(checks)} bounded query-input candidate(s)."
    elif tested_parameters:
        status = "Not Observed"
        message = (
            "No open-redirect, unescaped-reflection, or database-error "
            "candidate was observed."
        )
    else:
        status = "Not Applicable"
        message = "No eligible existing query parameters were available for safe testing."

    return {
        "name": "Application Input Security",
        "status": status,
        "message": message,
        "checks": checks,
        "finding_count": len(checks),
        "requests_made": requests_made,
        "parameters_tested": tested_parameters,
        "reflection_tests": reflection_tests,
        "database_error_tests": database_error_tests,
        "request_limit": int(max_requests),
        "forms_submitted": 0,
        "state_changing_requests_sent": 0,
        "script_payloads_sent": 0,
        "data_extraction_attempts": 0,
        "time_based_payloads_sent": 0,
        "boolean_payloads_sent": 0,
        "union_payloads_sent": 0,
        "external_destinations_contacted": 0,
        "scope": "Existing query parameters on already crawled same-host pages only",
    }
