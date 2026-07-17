import html
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from app.utils.domain import clean_domain


ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
REPORT_FILENAME = "webshield-zap-report.json"

MAX_ALERTS = 100
MAX_INSTANCES_PER_ALERT = 10

RISK_LEVELS = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
}


def clean_report_text(value) -> str:
    if not value:
        return ""

    without_tags = re.sub(
        r"<[^>]+>",
        " ",
        str(value),
    )

    decoded = html.unescape(without_tags)

    return " ".join(decoded.split())


def as_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def belongs_to_domain(
    url: str,
    expected_domain: str,
) -> bool:
    try:
        hostname = urlparse(url).hostname
    except ValueError:
        return False

    return (
        hostname is not None
        and hostname.rstrip(".").lower()
        == expected_domain.rstrip(".").lower()
    )


def build_zap_command(
    domain: str,
    work_directory,
    spider_minutes: int = 1,
    maximum_minutes: int = 5,
):
    clean_host = clean_domain(domain)

    if not 1 <= spider_minutes <= 3:
        raise ValueError(
            "Spider time must be between 1 and 3 minutes."
        )

    if not 2 <= maximum_minutes <= 10:
        raise ValueError(
            "Maximum scan time must be between 2 and 10 minutes."
        )

    mounted_directory = str(
        Path(work_directory).resolve()
    )

    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "bridge",
        "--memory",
        "2g",
        "--cpus",
        "2",
        "-v",
        (
            f"{mounted_directory}:"
            "/zap/wrk:rw"
        ),
        ZAP_IMAGE,
        "zap-baseline.py",
        "-t",
        f"https://{clean_host}",
        "-m",
        str(spider_minutes),
        "-T",
        str(maximum_minutes),
        "-J",
        REPORT_FILENAME,
        "-I",
        "-s",
    ]


def parse_zap_report(
    payload: dict,
    expected_domain: str,
):
    clean_host = clean_domain(expected_domain)

    checks = []
    risk_summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for site in as_list(payload.get("site")):
        site_name = str(
            site.get("@name")
            or site.get("@host")
            or ""
        )

        if not belongs_to_domain(
            site_name,
            clean_host,
        ):
            continue

        for alert in as_list(site.get("alerts")):
            risk_code = str(
                alert.get("riskcode")
                or alert.get("@riskcode")
                or "0"
            )

            risk = RISK_LEVELS.get(
                risk_code,
                "Informational",
            )

            risk_summary[risk] += 1

            affected_locations = []

            for instance in as_list(
                alert.get("instances")
            ):
                uri = str(
                    instance.get("uri") or ""
                )

                if (
                    uri
                    and not belongs_to_domain(
                        uri,
                        clean_host,
                    )
                ):
                    continue

                affected_locations.append({
                    "url": uri or None,
                    "method": (
                        instance.get("method")
                        or None
                    ),
                    "parameter": (
                        instance.get("param")
                        or None
                    ),
                })

                if (
                    len(affected_locations)
                    >= MAX_INSTANCES_PER_ALERT
                ):
                    break

            checks.append({
                "rule_id": str(
                    alert.get("pluginid")
                    or alert.get("@pluginid")
                    or ""
                ),
                "name": (
                    alert.get("alert")
                    or alert.get("name")
                    or "Passive security finding"
                ),
                "risk": risk,
                "confidence": (
                    alert.get("confidence")
                    or alert.get("@confidence")
                ),
                "description": clean_report_text(
                    alert.get("desc")
                ),
                "solution": clean_report_text(
                    alert.get("solution")
                ),
                "reference": clean_report_text(
                    alert.get("reference")
                ),
                "cwe_id": (
                    alert.get("cweid")
                    or None
                ),
                "wasc_id": (
                    alert.get("wascid")
                    or None
                ),
                "affected_locations": (
                    affected_locations
                ),
                "instance_count": len(
                    affected_locations
                ),
            })

            if len(checks) >= MAX_ALERTS:
                break

        if len(checks) >= MAX_ALERTS:
            break

    if (
        risk_summary["High"] > 0
        or risk_summary["Medium"] > 0
    ):
        status = "Needs Attention"
        message = (
            "ZAP found passive security warnings that "
            "should be reviewed."
        )

    elif checks:
        status = "Review"
        message = (
            "ZAP found low-risk or informational items "
            "for review."
        )

    else:
        status = "Not Observed"
        message = (
            "ZAP did not report a passive security "
            "warning for the verified domain."
        )

    return {
        "name": "OWASP ZAP Baseline",
        "domain": clean_host,
        "status": status,
        "message": message,
        "checks": checks,
        "risk_summary": risk_summary,
        "finding_count": len(checks),
        "results_limited": (
            len(checks) >= MAX_ALERTS
        ),
        "scan_type": "Passive baseline scan",
        "active_attack_payloads": False,
        "source": "OWASP ZAP",
        "score_eligible": False,
        "important_note": (
            "A passive ZAP warning is evidence that a "
            "configuration should be reviewed. It does "
            "not by itself prove that the website is "
            "exploitable."
        ),
    }


def unavailable_result(
    domain: str,
    message: str,
    error_type: str,
):
    return {
        "name": "OWASP ZAP Baseline",
        "domain": clean_domain(domain),
        "status": "Unavailable",
        "message": message,
        "checks": [],
        "risk_summary": {
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        },
        "finding_count": 0,
        "error_type": error_type,
        "scan_type": "Passive baseline scan",
        "active_attack_payloads": False,
        "source": "OWASP ZAP",
        "score_eligible": False,
    }


def run_zap_baseline(
    domain: str,
    spider_minutes: int = 1,
    maximum_minutes: int = 5,
    runner=subprocess.run,
):
    clean_host = clean_domain(domain)

    with tempfile.TemporaryDirectory(
        prefix="webshield-zap-"
    ) as temporary_directory:
        command = build_zap_command(
            clean_host,
            temporary_directory,
            spider_minutes=spider_minutes,
            maximum_minutes=maximum_minutes,
        )

        try:
            completed_process = runner(
                command,
                capture_output=True,
                text=True,
                timeout=(
                    maximum_minutes + 2
                ) * 60,
                check=False,
            )

        except FileNotFoundError:
            return unavailable_result(
                clean_host,
                (
                    "Docker was not found on this "
                    "WebShield server."
                ),
                "DockerNotFound",
            )

        except subprocess.TimeoutExpired:
            return unavailable_result(
                clean_host,
                (
                    "The ZAP baseline scan exceeded "
                    "WebShield's time limit."
                ),
                "ScanTimeout",
            )

        report_path = (
            Path(temporary_directory)
            / REPORT_FILENAME
        )

        if (
            completed_process.returncode == 3
            or not report_path.exists()
        ):
            return unavailable_result(
                clean_host,
                (
                    "ZAP could not produce a valid "
                    "baseline report."
                ),
                "ZapExecutionError",
            )

        try:
            payload = json.loads(
                report_path.read_text(
                    encoding="utf-8"
                )
            )

        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return unavailable_result(
                clean_host,
                (
                    "ZAP produced a report that "
                    "WebShield could not read."
                ),
                "InvalidZapReport",
            )

        result = parse_zap_report(
            payload,
            clean_host,
        )

        result["zap_exit_code"] = (
            completed_process.returncode
        )
        result["spider_minutes"] = (
            spider_minutes
        )
        result["maximum_minutes"] = (
            maximum_minutes
        )

        return result