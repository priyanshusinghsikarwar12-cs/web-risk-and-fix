import json
import re

import requests

from app.scanners.script_inventory import (
    check_script_inventory,
)


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_PACKAGES_PER_SCAN = 20
MAX_OSV_RESPONSE_BYTES = 1_000_000

PACKAGE_NAME_MAP = {
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "lodash": "lodash",
    "moment.js": "moment",
    "axios": "axios",
    "react dom": "react-dom",
    "react": "react",
    "vue": "vue",
    "angular": "angular",
}

VERSION_PATTERN = re.compile(
    r"^\d+\.\d+(?:\.\d+)?"
    r"(?:[-+][0-9a-zA-Z.-]+)?$"
)

PACKAGE_PATTERN = re.compile(
    r"^(?:@[a-z0-9._-]+/)?"
    r"[a-z0-9._-]+$",
    re.IGNORECASE,
)


def normalize_package_name(
    library_name: str,
):
    clean_name = library_name.strip().lower()

    mapped_name = PACKAGE_NAME_MAP.get(
        clean_name,
        clean_name,
    )

    if not PACKAGE_PATTERN.fullmatch(
        mapped_name
    ):
        return None

    return mapped_name


def extract_versioned_packages(
    script_inventory: dict,
):
    packages = {}
    skipped_count = 0

    for script in script_inventory.get(
        "checks",
        [],
    ):
        library = script.get("library")

        if not library:
            continue

        confidence = library.get("confidence")
        version = str(
            library.get("version") or ""
        ).strip()

        if (
            confidence not in {"High", "Medium"}
            or not VERSION_PATTERN.fullmatch(version)
        ):
            skipped_count += 1
            continue

        package_name = normalize_package_name(
            str(library.get("name", ""))
        )

        if not package_name:
            skipped_count += 1
            continue

        key = (
            package_name,
            version,
        )

        packages.setdefault(key, {
            "package": package_name,
            "version": version,
            "confidence": confidence,
            "evidence": library.get("evidence"),
            "script_urls": [],
        })

        script_url = script.get("url")

        if (
            script_url
            and script_url not in packages[
                key
            ]["script_urls"]
        ):
            packages[key]["script_urls"].append(
                script_url
            )

    return {
        "packages": list(packages.values()),
        "skipped_count": skipped_count,
    }


def query_osv_package(
    package_name: str,
    version: str,
    session=None,
):
    http_session = (
        session or requests.Session()
    )
    owns_session = session is None
    response = None

    try:
        response = http_session.post(
            OSV_QUERY_URL,
            json={
                "package": {
                    "name": package_name,
                    "ecosystem": "npm",
                },
                "version": version,
            },
            timeout=12,
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": (
                    "WebShield/0.1 authorized "
                    "security assessment"
                ),
                "Accept": "application/json",
            },
        )

        if response.status_code != 200:
            raise requests.HTTPError(
                "The OSV provider returned an "
                "unsuccessful response."
            )

        content = bytearray()

        for chunk in response.iter_content(
            chunk_size=65_536
        ):
            if not chunk:
                continue

            if (
                len(content) + len(chunk)
                > MAX_OSV_RESPONSE_BYTES
            ):
                raise requests.RequestException(
                    "The OSV response exceeded "
                    "WebShield's size limit."
                )

            content.extend(chunk)

        try:
            payload = json.loads(
                bytes(content).decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise requests.RequestException(
                "The OSV response was not valid JSON."
            ) from error

        vulnerabilities = payload.get(
            "vulns",
            [],
        )

        if not isinstance(
            vulnerabilities,
            list,
        ):
            raise requests.RequestException(
                "The OSV response had an "
                "unexpected structure."
            )

        return vulnerabilities

    finally:
        if response is not None:
            response.close()

        if owns_session:
            http_session.close()


def simplify_vulnerability(
    vulnerability: dict,
):
    vulnerability_id = str(
        vulnerability.get("id", "")
    )

    aliases = [
        str(alias)
        for alias in vulnerability.get(
            "aliases",
            [],
        )
    ][:10]

    references = []

    for reference in vulnerability.get(
        "references",
        [],
    ):
        url = reference.get("url")

        if (
            url
            and url.startswith(
                ("https://", "http://")
            )
        ):
            references.append(url)

        if len(references) >= 5:
            break

    severity_values = []

    for severity in vulnerability.get(
        "severity",
        [],
    ):
        score = severity.get("score")
        severity_type = severity.get("type")

        if score:
            severity_values.append({
                "type": severity_type,
                "score": score,
            })

    database_severity = (
        vulnerability
        .get("database_specific", {})
        .get("severity")
    )

    return {
        "id": vulnerability_id,
        "aliases": aliases,
        "summary": (
            vulnerability.get("summary")
            or "Known vulnerability match"
        ),
        "details_available": bool(
            vulnerability.get("details")
        ),
        "modified": vulnerability.get(
            "modified"
        ),
        "published": vulnerability.get(
            "published"
        ),
        "database_severity": database_severity,
        "severity_values": severity_values,
        "references": references,
        "osv_url": (
            f"https://osv.dev/vulnerability/"
            f"{vulnerability_id}"
            if vulnerability_id
            else None
        ),
    }


def match_javascript_advisories(
    script_inventory: dict,
    query_function=query_osv_package,
):
    extraction = extract_versioned_packages(
        script_inventory
    )

    all_packages = extraction["packages"]
    inspected_packages = all_packages[
        :MAX_PACKAGES_PER_SCAN
    ]

    results_limited = (
        len(all_packages)
        > MAX_PACKAGES_PER_SCAN
    )

    checks = []
    errors = []

    for package in inspected_packages:
        try:
            vulnerabilities = query_function(
                package["package"],
                package["version"],
            )

            for vulnerability in vulnerabilities:
                simplified = (
                    simplify_vulnerability(
                        vulnerability
                    )
                )

                checks.append({
                    "name": (
                        f"{package['package']} "
                        f"{package['version']}"
                    ),
                    "status": (
                        "Known Vulnerability Match"
                    ),
                    "package": package["package"],
                    "version": package["version"],
                    "detection_confidence": (
                        package["confidence"]
                    ),
                    "detection_evidence": (
                        package["evidence"]
                    ),
                    "script_urls": (
                        package["script_urls"]
                    ),
                    "vulnerability": simplified,
                    "message": (
                        "OSV returned a known vulnerability "
                        "for this exact npm package version."
                    ),
                })

        except requests.RequestException as error:
            errors.append({
                "package": package["package"],
                "version": package["version"],
                "error_type": type(error).__name__,
                "message": (
                    "The advisory provider could not "
                    "check this package."
                ),
            })

    if checks:
        status = "Needs Attention"
        message = (
            f"WebShield found {len(checks)} known "
            "vulnerability match(es) for exact "
            "JavaScript package versions."
        )

    elif errors:
        status = "Partial"
        message = (
            "No vulnerability was confirmed, but some "
            "package advisory checks could not finish."
        )

    elif not inspected_packages:
        status = "Not Applicable"
        message = (
            "No High or Medium confidence JavaScript "
            "package version was available for matching."
        )

    else:
        status = "Not Observed"
        message = (
            "OSV returned no known vulnerability for "
            "the exact package versions checked."
        )

    return {
        "name": "JavaScript Known Vulnerabilities",
        "status": status,
        "message": message,
        "checks": checks,
        "vulnerability_match_count": len(
            checks
        ),
        "eligible_package_count": len(
            all_packages
        ),
        "packages_queried": len(
            inspected_packages
        ),
        "skipped_detection_count": (
            extraction["skipped_count"]
        ),
        "provider_error_count": len(errors),
        "provider_errors": errors,
        "results_limited": results_limited,
        "source": "OSV",
        "source_url": "https://osv.dev/",
        "score_eligible": False,
        "important_note": (
            "A match means the detected package version "
            "appears in a known advisory. It does not prove "
            "that the vulnerable code path is exploitable "
            "on this website."
        ),
    }


def check_javascript_advisories(
    domain: str,
    response=None,
    query_function=query_osv_package,
    same_host_only=False,
    allow_invalid_tls=False,
):
    inventory = check_script_inventory(
        domain,
        response=response,
        same_host_only=same_host_only,
        allow_invalid_tls=allow_invalid_tls,
    )

    result = match_javascript_advisories(
        inventory,
        query_function=query_function,
    )

    return {
        **result,
        "domain": domain,
        "inventory_status": inventory.get(
            "status"
        ),
        "scope": (
            "Exact High or Medium confidence package "
            "versions detected in initial homepage scripts"
        ),
    }
