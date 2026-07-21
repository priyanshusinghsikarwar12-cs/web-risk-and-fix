"""Bounded OSV advisory lookup for exact dependency versions."""

import json
import re

import requests


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_DETAIL_URL = "https://api.osv.dev/v1/vulns/{advisory_id}"
MAX_BATCH_SIZE = 100
MAX_ADVISORY_DETAILS = 50
MAX_RESPONSE_BYTES = 4_000_000


class DependencyAdvisoryError(RuntimeError):
    pass


def _bounded_json(response, *, max_bytes=MAX_RESPONSE_BYTES):
    response.raise_for_status()
    declared_length = response.headers.get("Content-Length")
    if declared_length:
        try:
            declared_bytes = int(declared_length)
        except ValueError as error:
            raise DependencyAdvisoryError(
                "The advisory service returned an invalid response length."
            ) from error

        if declared_bytes > max_bytes:
            raise DependencyAdvisoryError(
                "The advisory service returned an oversized response."
            )

    content = bytearray()
    for chunk in response.iter_content(chunk_size=65_536):
        if not chunk:
            continue
        if len(content) + len(chunk) > max_bytes:
            raise DependencyAdvisoryError(
                "The advisory service returned an oversized response."
            )
        content.extend(chunk)

    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise DependencyAdvisoryError(
            "The advisory service returned invalid JSON."
        ) from error


class OsvClient:
    def __init__(self, *, session=None, timeout=8):
        self.session = session or requests.Session()
        self.owns_session = session is None
        self.timeout = timeout

    def close(self):
        if self.owns_session:
            self.session.close()

    def _post_batch(self, packages):
        payload = {
            "queries": [
                {
                    "package": {
                        "ecosystem": package["ecosystem"],
                        "name": package["name"],
                    },
                    "version": package["version"],
                }
                for package in packages
            ]
        }
        response = self.session.post(
            OSV_BATCH_URL,
            json=payload,
            timeout=self.timeout,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "WebShield/0.1 dependency review"},
        )
        try:
            return _bounded_json(response)
        finally:
            response.close()

    def _get_detail(self, advisory_id):
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", advisory_id):
            raise DependencyAdvisoryError("Invalid advisory identifier.")

        response = self.session.get(
            OSV_DETAIL_URL.format(advisory_id=advisory_id),
            timeout=self.timeout,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "WebShield/0.1 dependency review"},
        )
        try:
            return _bounded_json(response, max_bytes=2_000_000)
        finally:
            response.close()

    def query(self, packages):
        matches = []
        unique_ids = []

        for start in range(0, len(packages), MAX_BATCH_SIZE):
            batch = packages[start:start + MAX_BATCH_SIZE]
            result = self._post_batch(batch)
            responses = result.get("results", [])

            if len(responses) != len(batch):
                raise DependencyAdvisoryError(
                    "The advisory response did not match the dependency request."
                )

            for package, response in zip(batch, responses):
                for vulnerability in response.get("vulns", []):
                    advisory_id = vulnerability.get("id")
                    if not advisory_id:
                        continue
                    matches.append((package, advisory_id))
                    if advisory_id not in unique_ids:
                        unique_ids.append(advisory_id)

        details = {}
        detail_errors = []
        for advisory_id in unique_ids[:MAX_ADVISORY_DETAILS]:
            try:
                details[advisory_id] = self._get_detail(advisory_id)
            except (requests.RequestException, DependencyAdvisoryError) as error:
                detail_errors.append({
                    "advisory_id": advisory_id,
                    "error_type": type(error).__name__,
                })

        return {
            "matches": matches,
            "details": details,
            "detail_errors": detail_errors,
            "results_limited": len(unique_ids) > MAX_ADVISORY_DETAILS,
        }


SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MODERATE": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
}

SEVERITY_RANK = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}


def _advisory_severity(detail):
    candidates = [
        detail.get("database_specific", {}).get("severity"),
    ]
    for affected in detail.get("affected", []):
        candidates.append(affected.get("ecosystem_specific", {}).get("severity"))
        candidates.append(affected.get("database_specific", {}).get("severity"))

    for candidate in candidates:
        normalized = str(candidate or "").upper()
        if normalized in SEVERITY_MAP:
            return SEVERITY_MAP[normalized], "Advisory"

    return "Medium", "WebShield conservative fallback"


def _fixed_versions(detail, package):
    versions = []
    for affected in detail.get("affected", []):
        affected_package = affected.get("package", {})
        if (
            str(affected_package.get("ecosystem", "")).lower()
            != package["ecosystem"].lower()
            or str(affected_package.get("name", "")).lower()
            != package["name"].lower()
        ):
            continue

        for range_item in affected.get("ranges", []):
            for event in range_item.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed not in versions:
                    versions.append(fixed)
    return versions[:10]


def _advisory_reference(detail, advisory_id):
    for reference in detail.get("references", []):
        url = str(reference.get("url", ""))
        if url.startswith(("https://", "http://")):
            return url
    return f"https://osv.dev/vulnerability/{advisory_id}"


def _dependency_finding(package, advisory_id, detail):
    severity, severity_source = _advisory_severity(detail)
    fixed_versions = _fixed_versions(detail, package)
    aliases = [
        str(alias) for alias in detail.get("aliases", [])
        if re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", str(alias))
    ][:10]
    summary = str(detail.get("summary") or "Known dependency vulnerability")
    summary = re.sub(r"\s+", " ", summary).strip()[:500]

    if fixed_versions:
        fix = (
            f"Upgrade {package['name']} to a fixed version identified by the "
            f"advisory ({', '.join(fixed_versions)}), then run the project's "
            "tests before deployment."
        )
    else:
        fix = (
            f"Review advisory {advisory_id}, upgrade {package['name']} to a "
            "maintained non-affected version, and run the project's tests."
        )

    return {
        "rule_id": f"dependency-{advisory_id.lower()}",
        "title": (
            f"{package['name']} {package['version']}: {summary}"
        ),
        "severity": severity,
        "confidence": "High",
        "path": package["path"],
        "line": 1,
        "fix": fix,
        "explanation": summary,
        "evidence": (
            f"{package['ecosystem']} package {package['name']} "
            f"version {package['version']} matched {advisory_id}."
        ),
        "secret_redacted": False,
        "finding_type": "Known Dependency Vulnerability",
        "package": {
            "ecosystem": package["ecosystem"],
            "name": package["name"],
            "version": package["version"],
            "scope": package["scope"],
            "direct": package["direct"],
        },
        "advisory": {
            "id": advisory_id,
            "ids": [advisory_id],
            "aliases": aliases,
            "reference": _advisory_reference(detail, advisory_id),
            "fixed_versions": fixed_versions,
            "severity_source": severity_source,
        },
    }


def _advisory_identities(finding):
    advisory = finding["advisory"]
    return {
        str(identifier).upper()
        for identifier in [
            *advisory.get("ids", [advisory.get("id")]),
            *advisory.get("aliases", []),
        ]
        if identifier
    }


def _merge_advisory_findings(primary, duplicate):
    primary_advisory = primary["advisory"]
    duplicate_advisory = duplicate["advisory"]

    for key in ("ids", "aliases", "fixed_versions"):
        values = []
        for value in [
            *primary_advisory.get(key, []),
            *duplicate_advisory.get(key, []),
        ]:
            if value and value not in values:
                values.append(value)
        primary_advisory[key] = values[:20]

    if SEVERITY_RANK.get(
        duplicate["severity"], 4
    ) < SEVERITY_RANK.get(primary["severity"], 4):
        primary["severity"] = duplicate["severity"]
        primary_advisory["severity_source"] = duplicate_advisory[
            "severity_source"
        ]

    primary_advisory["records_merged"] = (
        primary_advisory.get("records_merged", 1)
        + duplicate_advisory.get("records_merged", 1)
    )
    return primary


def _deduplicate_advisory_findings(findings):
    groups = []

    for finding in findings:
        identities = _advisory_identities(finding)
        matching_indexes = [
            index
            for index, group in enumerate(groups)
            if identities & _advisory_identities(group)
        ]

        if not matching_indexes:
            finding["advisory"]["records_merged"] = 1
            groups.append(finding)
            continue

        primary_index = matching_indexes[0]
        groups[primary_index] = _merge_advisory_findings(
            groups[primary_index], finding
        )

        for duplicate_index in reversed(matching_indexes[1:]):
            groups[primary_index] = _merge_advisory_findings(
                groups[primary_index], groups[duplicate_index]
            )
            del groups[duplicate_index]

    return groups


def check_dependency_advisories(packages, *, client=None):
    if not packages:
        return {
            "status": "Not Applicable",
            "message": "No exact dependency versions were available to check.",
            "packages_checked": 0,
            "vulnerabilities_found": 0,
            "findings": [],
            "results_limited": False,
            "service": "OSV.dev",
            "data_shared": [],
        }

    advisory_client = client or OsvClient()
    owns_client = client is None
    try:
        result = advisory_client.query(packages)
    except (requests.RequestException, DependencyAdvisoryError) as error:
        return {
            "status": "Unavailable",
            "message": (
                "Dependency versions were identified, but the advisory service "
                "could not be reached. No clean result is claimed."
            ),
            "packages_checked": 0,
            "vulnerabilities_found": 0,
            "findings": [],
            "results_limited": False,
            "service": "OSV.dev",
            "data_shared": ["package ecosystem", "package name", "exact version"],
            "error_type": type(error).__name__,
        }
    finally:
        if owns_client:
            advisory_client.close()

    findings = []
    unresolved_details = 0
    for package, advisory_id in result["matches"]:
        detail = result["details"].get(advisory_id)
        if detail is None:
            unresolved_details += 1
            continue
        findings.append(_dependency_finding(
            package, advisory_id, detail
        ))

    raw_records_matched = len(findings)
    findings = _deduplicate_advisory_findings(findings)
    findings.sort(key=lambda item: (
        SEVERITY_RANK.get(item["severity"], 4),
        item["package"]["name"].lower(),
        item["advisory"]["id"],
    ))
    partial = unresolved_details > 0 or bool(result["detail_errors"])
    return {
        "status": "Partial" if partial else "Completed",
        "message": (
            f"WebShield identified {len(findings)} unique known vulnerability "
            f"group(s) across {len(packages)} exact dependency version(s)."
        ),
        "packages_checked": len(packages),
        "vulnerabilities_found": len(findings),
        "advisory_records_matched": raw_records_matched,
        "duplicate_records_merged": raw_records_matched - len(findings),
        "findings": findings,
        "unresolved_advisory_details": unresolved_details,
        "results_limited": result["results_limited"],
        "service": "OSV.dev",
        "data_shared": ["package ecosystem", "package name", "exact version"],
        "scope": "Known advisory matching only; exploitability is not confirmed.",
    }
