import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.deep_scanners.zap_baseline import (
    REPORT_FILENAME,
    ZAP_IMAGE,
    build_zap_command,
    clean_report_text,
    parse_zap_report,
    run_zap_baseline,
)


def example_report():
    return {
        "site": [{
            "@name": "https://example.com",
            "@host": "example.com",
            "alerts": [{
                "pluginid": "10020",
                "alert": (
                    "X-Frame-Options Header Not Set"
                ),
                "riskcode": "2",
                "confidence": "2",
                "desc": (
                    "<p>The response does not include "
                    "click protection.</p>"
                ),
                "solution": (
                    "<p>Add an appropriate header.</p>"
                ),
                "instances": [{
                    "uri": "https://example.com/login",
                    "method": "GET",
                    "param": "",
                    "evidence": "Raw evidence",
                }],
                "cweid": "1021",
                "wascid": "15",
            }],
        }],
    }


def test_command_uses_fixed_zap_image(tmp_path):
    command = build_zap_command(
        "example.com",
        tmp_path,
    )

    assert command[0] == "docker"
    assert ZAP_IMAGE in command
    assert "zap-baseline.py" in command
    assert "https://example.com" in command
    assert REPORT_FILENAME in command


def test_command_rejects_excessive_spider_time(
    tmp_path,
):
    with pytest.raises(ValueError):
        build_zap_command(
            "example.com",
            tmp_path,
            spider_minutes=20,
        )


def test_html_is_removed_from_report_text():
    result = clean_report_text(
        "<p>Hello &amp; welcome</p>"
    )

    assert result == "Hello & welcome"


def test_medium_alert_needs_attention():
    result = parse_zap_report(
        example_report(),
        "example.com",
    )

    assert result["status"] == "Needs Attention"
    assert result["finding_count"] == 1
    assert result["risk_summary"]["Medium"] == 1


def test_raw_evidence_is_not_returned():
    result = parse_zap_report(
        example_report(),
        "example.com",
    )

    finding = result["checks"][0]

    assert "evidence" not in finding
    assert (
        "evidence"
        not in finding["affected_locations"][0]
    )


def test_external_site_is_ignored():
    report = example_report()

    report["site"].append({
        "@name": "https://external.example.net",
        "@host": "external.example.net",
        "alerts": [{
            "pluginid": "999",
            "alert": "External finding",
            "riskcode": "3",
        }],
    })

    result = parse_zap_report(
        report,
        "example.com",
    )

    assert result["finding_count"] == 1
    assert result["risk_summary"]["High"] == 0


def test_empty_report_is_not_observed():
    result = parse_zap_report(
        {
            "site": [{
                "@name": "https://example.com",
                "alerts": [],
            }],
        },
        "example.com",
    )

    assert result["status"] == "Not Observed"
    assert result["checks"] == []


def test_successful_runner_reads_json_report():
    def fake_runner(command, **kwargs):
        volume_value = command[
            command.index("-v") + 1
        ]

        host_directory = volume_value.rsplit(
            ":/zap/wrk:rw",
            1,
        )[0]

        report_path = (
            Path(host_directory)
            / REPORT_FILENAME
        )

        report_path.write_text(
            json.dumps(example_report()),
            encoding="utf-8",
        )

        return SimpleNamespace(
            returncode=2,
            stdout="",
            stderr="",
        )

    result = run_zap_baseline(
        "example.com",
        runner=fake_runner,
    )

    assert result["status"] == "Needs Attention"
    assert result["finding_count"] == 1
    assert result["zap_exit_code"] == 2


def test_missing_docker_is_unavailable():
    def missing_docker(command, **kwargs):
        raise FileNotFoundError()

    result = run_zap_baseline(
        "example.com",
        runner=missing_docker,
    )

    assert result["status"] == "Unavailable"
    assert result["error_type"] == "DockerNotFound"


def test_timeout_is_unavailable():
    def timed_out(command, **kwargs):
        raise subprocess.TimeoutExpired(
            command,
            timeout=1,
        )

    result = run_zap_baseline(
        "example.com",
        runner=timed_out,
    )

    assert result["status"] == "Unavailable"
    assert result["error_type"] == "ScanTimeout"