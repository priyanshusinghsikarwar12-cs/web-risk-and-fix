import io
import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from app.services.source_scan_engine import (
    run_authorized_source_scan,
)


class SourceArchiveError(ValueError):
    pass


MAX_ARCHIVE_BYTES = 20_000_000
MAX_ARCHIVE_FILES = 2000
MAX_FILE_BYTES = 2_000_000
MAX_EXTRACTED_BYTES = 50_000_000


def safe_member_path(name):
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)

    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in path.parts[0]
    ):
        raise SourceArchiveError(
            "The source archive contains an unsafe file path."
        )

    return Path(*path.parts)


def is_symbolic_link(info):
    unix_mode = info.external_attr >> 16
    return stat.S_ISLNK(unix_mode)


def validate_archive(infos, archive_size):
    if archive_size > MAX_ARCHIVE_BYTES:
        raise SourceArchiveError(
            "The source archive exceeds the upload safety limit."
        )

    files = [info for info in infos if not info.is_dir()]

    if len(files) > MAX_ARCHIVE_FILES:
        raise SourceArchiveError(
            "The source archive contains too many files."
        )

    total_size = 0

    for info in files:
        safe_member_path(info.filename)

        if info.flag_bits & 0x1:
            raise SourceArchiveError(
                "Encrypted source archives are not supported."
            )

        if is_symbolic_link(info):
            raise SourceArchiveError(
                "Symbolic links are not allowed in source archives."
            )

        if info.file_size > MAX_FILE_BYTES:
            raise SourceArchiveError(
                "A source file exceeds the per-file safety limit."
            )

        total_size += info.file_size

        if total_size > MAX_EXTRACTED_BYTES:
            raise SourceArchiveError(
                "The extracted source exceeds the size safety limit."
            )


def extract_archive(archive, destination):
    destination = Path(destination).resolve()

    for info in archive.infolist():
        relative = safe_member_path(info.filename)
        target = (destination / relative).resolve()

        if os.path.commonpath([destination, target]) != str(destination):
            raise SourceArchiveError(
                "The source archive attempted to escape its scan folder."
            )

        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)

        with archive.open(info, "r") as source:
            with target.open("wb") as output:
                shutil.copyfileobj(source, output)


def scan_authorized_source_archive(
    archive_bytes,
    *,
    project_name,
    authorization_attested=False,
    client_reference=None,
    work_directory=None,
    dependency_advisory_lookup=False,
    dependency_advisory_client=None,
):
    if not isinstance(archive_bytes, bytes) or not archive_bytes:
        raise SourceArchiveError(
            "Upload a non-empty ZIP source archive."
        )

    if not project_name or len(project_name.strip()) > 120:
        raise SourceArchiveError(
            "Provide a short project name for the source review."
        )

    if work_directory is None:
        work_directory = os.getenv("WEBSHIELD_WORK_DIRECTORY")

    if not work_directory:
        raise SourceArchiveError(
            "Configure WEBSHIELD_WORK_DIRECTORY on a non-system drive "
            "before accepting source archives."
        )

    work_directory = Path(work_directory).expanduser().resolve()
    if not work_directory.exists() or not work_directory.is_dir():
        raise SourceArchiveError(
            "The configured WebShield work directory does not exist."
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as error:
        raise SourceArchiveError(
            "The uploaded source file is not a valid ZIP archive."
        ) from error

    with archive:
        validate_archive(archive.infolist(), len(archive_bytes))

        with tempfile.TemporaryDirectory(
            prefix="webshield-source-",
            dir=work_directory,
        ) as temporary_directory:
            extract_archive(archive, temporary_directory)

            report = run_authorized_source_scan(
                temporary_directory,
                authorization_attested=authorization_attested,
                client_reference=client_reference,
                project_name=project_name.strip(),
                dependency_advisory_lookup=dependency_advisory_lookup,
                dependency_advisory_client=dependency_advisory_client,
            )

    report["intake"] = {
        "type": "ZIP archive",
        "temporary_files_deleted": True,
        "archive_bytes": len(archive_bytes),
    }
    return report
