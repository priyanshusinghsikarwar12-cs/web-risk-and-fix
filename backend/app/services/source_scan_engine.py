from collections import Counter
from pathlib import Path

from app.source_scanners.project_files import (
    SOURCE_EXTENSIONS,
    read_project_files,
)
from app.source_scanners.dependency_advisories import (
    check_dependency_advisories,
)
from app.source_scanners.dependency_inventory import (
    collect_dependencies,
)
from app.source_scanners.static_analysis import analyze_source_files


class SourceScanAuthorizationError(PermissionError):
    pass


LANGUAGES = {
    ".c": "C", ".cs": "C#", ".go": "Go", ".java": "Java",
    ".js": "JavaScript", ".jsx": "JavaScript / JSX", ".php": "PHP",
    ".py": "Python", ".rb": "Ruby", ".rs": "Rust",
    ".ts": "TypeScript", ".tsx": "TypeScript / TSX",
}


def build_language_inventory(files):
    counts = Counter(
        LANGUAGES[item["extension"]]
        for item in files
        if item["extension"] in SOURCE_EXTENSIONS
        and item["extension"] in LANGUAGES
    )
    return [
        {"name": name, "file_count": count}
        for name, count in sorted(counts.items())
    ]


def severity_counts(findings):
    counts = Counter(item["severity"] for item in findings)
    return {
        severity: counts.get(severity, 0)
        for severity in (
            "Critical", "High", "Medium", "Low", "Informational"
        )
    }


def run_authorized_source_scan(
    project_path,
    *,
    authorization_attested=False,
    client_reference=None,
    project_name=None,
    dependency_advisory_lookup=False,
    dependency_advisory_client=None,
):
    if authorization_attested is not True:
        raise SourceScanAuthorizationError(
            "Source-code scanning requires explicit authorization."
        )

    project = read_project_files(project_path)
    analysis = analyze_source_files(project["files"])
    dependency_inventory = collect_dependencies(project["files"])

    if dependency_advisory_lookup:
        dependency_scan = check_dependency_advisories(
            dependency_inventory["packages"],
            client=dependency_advisory_client,
        )
    else:
        dependency_scan = {
            "status": "Not Requested",
            "message": (
                "Known-vulnerability matching was not requested. "
                "Dependency files were inventoried locally only."
            ),
            "packages_checked": 0,
            "vulnerabilities_found": 0,
            "findings": [],
            "results_limited": False,
            "service": "OSV.dev",
            "data_shared": [],
        }

    findings = [
        *analysis["findings"],
        *dependency_scan["findings"],
    ]
    counts = severity_counts(findings)

    if counts["Critical"] or counts["High"]:
        status = "Needs Attention"
        message = (
            "WebShield found source-code patterns that should be "
            "reviewed before production use."
        )
    elif findings:
        status = "Review Recommended"
        message = (
            "WebShield found source-code patterns that deserve "
            "a developer's review."
        )
    else:
        status = "No Listed Patterns Observed"
        message = (
            "WebShield did not observe the limited patterns covered by "
            "this scan. This does not prove that the code is vulnerability-free."
        )

    return {
        "name": "Authorized Source Code Review",
        "project_name": project_name or Path(project["root"]).name,
        "client_reference": client_reference,
        "status": status,
        "message": message,
        "authorization_attested": True,
        "files_scanned": len(project["files"]),
        "bytes_scanned": project["total_bytes"],
        "files_skipped": project["skipped"],
        "languages": build_language_inventory(project["files"]),
        "dependency_manifests": analysis["dependency_manifests"],
        "dependency_inventory": {
            "exact_versions_found": len(dependency_inventory["packages"]),
            "unresolved_entries": dependency_inventory["unresolved"],
            "results_limited": dependency_inventory["results_limited"],
        },
        "dependency_scan": {
            key: value
            for key, value in dependency_scan.items()
            if key != "findings"
        },
        "finding_counts": counts,
        "findings": findings,
        "secrets_redacted": True,
        "execution_policy": "Source files were read but never executed.",
        "scope": (
            "Pattern-based secret and static source review of supported "
            "text files only"
        ),
        "limitations": [
            "Findings require human confirmation.",
            "Business-logic and authorization flaws may require manual review.",
            (
                "Dependency advisory matches identify known vulnerable "
                "versions but do not prove exploitability in this application."
            ),
        ],
        "score_eligible": False,
    }
