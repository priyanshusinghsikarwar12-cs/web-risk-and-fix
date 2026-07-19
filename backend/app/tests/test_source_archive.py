import io
import zipfile

import pytest

from app.services.source_archive import (
    SourceArchiveError,
    scan_authorized_source_archive,
)


def zip_bytes(files):
    output = io.BytesIO()

    with zipfile.ZipFile(output, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)

    return output.getvalue()


def test_valid_archive_is_scanned_and_deleted(tmp_path):
    result = scan_authorized_source_archive(
        zip_bytes({"project/app.py": "print('hello')"}),
        project_name="Client Portal",
        authorization_attested=True,
        client_reference="approved-ticket-123",
        work_directory=tmp_path,
    )

    assert result["project_name"] == "Client Portal"
    assert result["files_scanned"] == 1
    assert result["client_reference"] == "approved-ticket-123"
    assert result["intake"]["temporary_files_deleted"] is True
    assert list(tmp_path.iterdir()) == []


def test_empty_upload_is_rejected(tmp_path):
    with pytest.raises(SourceArchiveError, match="non-empty"):
        scan_authorized_source_archive(
            b"",
            project_name="Project",
            authorization_attested=True,
            work_directory=tmp_path,
        )


def test_invalid_zip_is_rejected(tmp_path):
    with pytest.raises(SourceArchiveError, match="valid ZIP"):
        scan_authorized_source_archive(
            b"not a zip",
            project_name="Project",
            authorization_attested=True,
            work_directory=tmp_path,
        )


@pytest.mark.parametrize(
    "unsafe_name",
    ["../secret.py", "/absolute.py", "C:/windows.py", "..\\secret.py"],
)
def test_archive_path_escape_is_rejected(tmp_path, unsafe_name):
    with pytest.raises(SourceArchiveError, match="unsafe file path"):
        scan_authorized_source_archive(
            zip_bytes({unsafe_name: "print('unsafe')"}),
            project_name="Project",
            authorization_attested=True,
            work_directory=tmp_path,
        )


def test_archive_findings_keep_secrets_redacted(tmp_path):
    result = scan_authorized_source_archive(
        zip_bytes({
            "config.py": 'api_key = "a-real-looking-secret-value"'
        }),
        project_name="Project",
        authorization_attested=True,
        work_directory=tmp_path,
    )

    assert result["finding_counts"]["High"] == 1
    assert "real-looking" not in str(result)
