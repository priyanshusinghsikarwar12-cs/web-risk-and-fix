import os

import pytest

from app.services.source_scan_engine import (
    SourceScanAuthorizationError,
    run_authorized_source_scan,
)
from app.source_scanners.project_files import (
    SourceProjectError,
    read_project_files,
)


def test_source_scan_requires_explicit_authorization(tmp_path):
    with pytest.raises(
        SourceScanAuthorizationError,
        match="explicit authorization",
    ):
        run_authorized_source_scan(tmp_path)


def test_missing_project_is_rejected(tmp_path):
    with pytest.raises(SourceProjectError, match="not found"):
        run_authorized_source_scan(
            tmp_path / "missing",
            authorization_attested=True,
        )


def test_ignored_dependency_directories_are_not_scanned(tmp_path):
    (tmp_path / "app.py").write_text("print('safe')")
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "unsafe.js").write_text("eval(userInput)")

    result = run_authorized_source_scan(
        tmp_path, authorization_attested=True
    )

    assert result["files_scanned"] == 1
    assert result["findings"] == []


def test_private_key_is_redacted(tmp_path):
    (tmp_path / "settings.py").write_text(
        "KEY = '''-----BEGIN PRIVATE KEY-----\nsecret-data'''"
    )

    result = run_authorized_source_scan(
        tmp_path, authorization_attested=True
    )

    finding = result["findings"][0]
    assert finding["severity"] == "Critical"
    assert finding["secret_redacted"] is True
    assert "secret-data" not in str(result)
    assert finding["evidence"] == "[REDACTED POSSIBLE SECRET]"


def test_literal_password_is_reported_without_value(tmp_path):
    (tmp_path / "config.py").write_text(
        'password = "correct-horse-battery-staple"'
    )

    result = run_authorized_source_scan(
        tmp_path, authorization_attested=True
    )

    assert result["finding_counts"]["High"] == 1
    assert "correct-horse" not in str(result)


def test_python_shell_execution_is_explained(tmp_path):
    (tmp_path / "worker.py").write_text(
        "subprocess.run(command, shell=True)"
    )

    result = run_authorized_source_scan(
        tmp_path, authorization_attested=True
    )

    finding = result["findings"][0]
    assert finding["rule_id"] == "python-shell-true"
    assert "command injection" in finding["explanation"].lower()
    assert finding["line"] == 1


def test_javascript_dom_insertion_is_reported(tmp_path):
    (tmp_path / "page.js").write_text(
        "element.innerHTML = userContent;"
    )

    result = run_authorized_source_scan(
        tmp_path, authorization_attested=True
    )

    assert result["finding_counts"]["Medium"] == 1
    assert result["findings"][0]["rule_id"] == (
        "javascript-inner-html"
    )


def test_dependency_manifests_are_inventoried(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "fastapi==0.139.0\n"
    )
    (tmp_path / "app.py").write_text("print('hello')")

    result = run_authorized_source_scan(
        tmp_path, authorization_attested=True
    )

    assert result["dependency_manifests"] == [{
        "path": "requirements.txt",
        "type": "Python requirements",
    }]
    assert result["languages"] == [
        {"name": "Python", "file_count": 1}
    ]


def test_no_findings_does_not_claim_the_project_is_secure(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')")

    result = run_authorized_source_scan(
        tmp_path, authorization_attested=True
    )

    assert result["status"] == "No Listed Patterns Observed"
    assert "does not prove" in result["message"].lower()


def test_large_file_is_skipped(tmp_path):
    (tmp_path / "large.py").write_text("a" * 20)

    project = read_project_files(tmp_path, max_file_bytes=10)

    assert project["files"] == []
    assert project["skipped"][0]["reason"].startswith(
        "File exceeded"
    )


@pytest.mark.skipif(
    os.name == "nt",
    reason="Creating symlinks may require Windows privileges.",
)
def test_symlinked_files_are_not_followed(tmp_path):
    outside = tmp_path.parent / "outside-secret.py"
    outside.write_text('password = "not-for-this-project"')
    (tmp_path / "linked.py").symlink_to(outside)

    result = run_authorized_source_scan(
        tmp_path, authorization_attested=True
    )

    assert result["files_scanned"] == 0
