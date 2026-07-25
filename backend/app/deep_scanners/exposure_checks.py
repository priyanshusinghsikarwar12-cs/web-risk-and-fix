import re
import secrets
import time
from difflib import SequenceMatcher
from urllib.parse import urlsplit

import requests

from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get


SENSITIVE_PATHS = {
    "/.env": "Environment Configuration",
    "/.git/config": "Git Repository Configuration",
    "/backup.zip": "Website Backup Archive",
    "/database.sql": "Database Export",
    "/config.php.bak": "PHP Configuration Backup",
    "/web.config.bak": "Web Server Configuration Backup",
}

DIRECTORY_PATHS = {
    "/uploads/",
    "/backup/",
    "/backups/",
}

MAX_RESPONSE_BYTES = 8192


def _response_text(response) -> str:
    return response.content.decode(
        "utf-8",
        errors="replace",
    )


def _normalized_text(value: str) -> str:
    return re.sub(
        r"\s+",
        " ",
        value.lower(),
    ).strip()


def _looks_like_soft_404(
    candidate_response,
    baseline_response,
) -> bool:
    if baseline_response is None:
        return False

    if (
        candidate_response.status_code
        != baseline_response.status_code
    ):
        return False

    candidate_text = _normalized_text(
        _response_text(candidate_response)
    )

    baseline_text = _normalized_text(
        _response_text(baseline_response)
    )

    if not candidate_text or not baseline_text:
        return False

    similarity = SequenceMatcher(
        None,
        candidate_text,
        baseline_text,
    ).ratio()

    return similarity >= 0.90


def _sensitive_fingerprint(
    path: str,
    response,
):
    content = response.content
    text = _response_text(response).lower()

    if path == "/.env":
        environment_keys = {
            "app_key=",
            "app_secret=",
            "database_url=",
            "db_host=",
            "db_name=",
            "db_password=",
            "db_username=",
            "secret_key=",
        }

        matches = sorted(
            key
            for key in environment_keys
            if key in text
        )

        if len(matches) >= 2:
            return (
                "Environment-style secret or database "
                "configuration keys were observed."
            )

    if path == "/.git/config":
        if (
            "[core]" in text
            and "repositoryformatversion" in text
        ):
            return (
                "The response resembles a Git repository "
                "configuration file."
            )

    if path == "/backup.zip":
        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if (
            content.startswith(b"PK\x03\x04")
            or "application/zip" in content_type
        ):
            return (
                "The response resembles a downloadable "
                "ZIP backup archive."
            )

    if path == "/database.sql":
        if (
            "create table" in text
            and (
                "insert into" in text
                or "sql dump" in text
            )
        ):
            return (
                "The response resembles a database "
                "export file."
            )

    if path == "/config.php.bak":
        if (
            "<?php" in text
            and any(
                term in text
                for term in {
                    "db_password",
                    "db_username",
                    "database",
                    "password",
                }
            )
        ):
            return (
                "The response resembles a PHP "
                "configuration backup."
            )

    if path == "/web.config.bak":
        if (
            "<configuration" in text
            and any(
                term in text
                for term in {
                    "connectionstrings",
                    "appsettings",
                    "system.web",
                }
            )
        ):
            return (
                "The response resembles a web-server "
                "configuration backup."
            )

    return None


def _directory_listing_fingerprint(
    response,
):
    text = _response_text(response).lower()

    signals = {
        signal
        for signal in {
            "<title>index of /",
            "directory listing for",
            "parent directory",
            "last modified",
            "name</a>",
        }
        if signal in text
    }

    if (
        "<title>index of /" in signals
        and len(signals) >= 2
    ):
        return (
            "The response resembles an automatically "
            "generated directory index."
        )

    if (
        "directory listing for" in signals
        and len(signals) >= 2
    ):
        return (
            "The response resembles an automatically "
            "generated directory listing."
        )

    return None


def _response_stays_in_scope(
    response,
    domain: str,
) -> bool:
    final_location = urlsplit(response.url)

    return (
        final_location.scheme.lower() == "https"
        and (
            final_location.hostname or ""
        ).lower() == domain
    )


def check_sensitive_exposures(
    domain: str,
    delay_seconds: float = 0.15,
    allow_invalid_tls: bool = False,
):
    safe_domain = clean_domain(domain)

    if not 0 <= delay_seconds <= 2:
        raise ValueError(
            "The exposure-check delay must be "
            "between 0 and 2 seconds."
        )

    findings = []
    errors = []
    requests_made = 0

    baseline_path = (
        "/.well-known/webshield-missing-"
        f"{secrets.token_urlsafe(12)}"
    )

    baseline_response = None

    try:
        baseline_response = safe_get(
            f"https://{safe_domain}{baseline_path}",
            timeout=10,
            max_bytes=MAX_RESPONSE_BYTES,
            allowed_redirect_host=safe_domain,
            redirect_delay_seconds=delay_seconds,
            verify_tls=not allow_invalid_tls,
        )
        requests_made += 1

    except requests.RequestException as error:
        errors.append({
            "path": baseline_path,
            "error_type": type(error).__name__,
            "message": (
                "The missing-page baseline could not "
                "be collected."
            ),
        })

    checks = [
        *(
            (path, name, "Sensitive File")
            for path, name in SENSITIVE_PATHS.items()
        ),
        *(
            (path, "Directory Listing", "Directory")
            for path in sorted(DIRECTORY_PATHS)
        ),
    ]

    if baseline_response is not None and delay_seconds:
        time.sleep(delay_seconds)

    for path, name, check_type in checks:
        url = f"https://{safe_domain}{path}"

        try:
            response = safe_get(
                url,
                timeout=10,
                max_bytes=MAX_RESPONSE_BYTES,
                allowed_redirect_host=safe_domain,
                redirect_delay_seconds=delay_seconds,
                verify_tls=not allow_invalid_tls,
            )
            requests_made += 1

            if not _response_stays_in_scope(
                response,
                safe_domain,
            ):
                continue

            if not 200 <= response.status_code < 300:
                continue

            if _looks_like_soft_404(
                response,
                baseline_response,
            ):
                continue

            if check_type == "Sensitive File":
                evidence = _sensitive_fingerprint(
                    path,
                    response,
                )
            else:
                evidence = (
                    _directory_listing_fingerprint(
                        response
                    )
                )

            if evidence:
                findings.append({
                    "name": name,
                    "status": "Needs Attention",
                    "severity": (
                        "High"
                        if check_type == "Sensitive File"
                        else "Medium"
                    ),
                    "path": path,
                    "url": url,
                    "message": evidence,
                    "content_returned": False,
                    "response_truncated": getattr(
                        response,
                        "webshield_content_truncated",
                        False,
                    ),
                })

        except requests.RequestException as error:
            errors.append({
                "path": path,
                "error_type": type(error).__name__,
                "message": (
                    "This exposure check could not "
                    "be completed."
                ),
            })

        if delay_seconds:
            time.sleep(delay_seconds)

    if findings:
        status = "Needs Attention"
        message = (
            f"WebShield found {len(findings)} response(s) "
            "that resemble exposed sensitive resources."
        )

    elif errors:
        status = "Partial"
        message = (
            "No sensitive exposure was confirmed, but "
            "some checks could not be completed."
        )

    else:
        status = "Not Observed"
        message = (
            "No tested sensitive file or automatic "
            "directory listing was confirmed."
        )

    return {
        "name": "Sensitive Exposure Checks",
        "domain": safe_domain,
        "status": status,
        "message": message,
        "checks": findings,
        "finding_count": len(findings),
        "error_count": len(errors),
        "errors": errors,
        "requests_made": requests_made,
        "request_budget": 10,
        "scope": (
            "A fixed verified-only list of sensitive "
            "paths and common directory locations"
        ),
        "score_eligible": False,
        "safety": {
            "http_methods": ["GET"],
            "maximum_bytes_per_response": (
                MAX_RESPONSE_BYTES
            ),
            "response_contents_returned": False,
            "same_verified_hostname_only": True,
        },
    }
