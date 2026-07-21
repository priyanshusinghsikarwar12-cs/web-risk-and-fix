import os
from pathlib import Path


class SourceProjectError(ValueError):
    pass


IGNORED_DIRECTORIES = {
    ".git", ".idea", ".next", ".pytest_cache", ".venv",
    ".vscode", "build", "coverage", "dist", "node_modules",
    "target", "venv", "vendor", "__pycache__",
}

SOURCE_EXTENSIONS = {
    ".c", ".cs", ".go", ".java", ".js", ".jsx", ".php",
    ".py", ".rb", ".rs", ".ts", ".tsx",
}

CONFIG_EXTENSIONS = {
    ".env", ".ini", ".json", ".toml", ".xml", ".yaml", ".yml",
}

SPECIAL_FILES = {
    "dockerfile", "gemfile", "package-lock.json", "package.json",
    "pipfile", "pipfile.lock", "poetry.lock", "pom.xml", "requirements.txt",
    "yarn.lock",
}


def is_supported_file(path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    return (
        name in SPECIAL_FILES
        or suffix in SOURCE_EXTENSIONS
        or suffix in CONFIG_EXTENSIONS
    )


def read_project_files(
    project_path,
    *,
    max_files=2000,
    max_file_bytes=2_000_000,
    max_total_bytes=50_000_000,
):
    root = Path(project_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise SourceProjectError(
            "The authorized source-code folder was not found."
        )

    files = []
    skipped = []
    total_bytes = 0

    for current_root, directories, filenames in os.walk(
        root,
        followlinks=False,
    ):
        current_path = Path(current_root)
        directories[:] = [
            name for name in directories
            if name.lower() not in IGNORED_DIRECTORIES
            and not (current_path / name).is_symlink()
        ]

        for filename in sorted(filenames):
            path = current_path / filename

            if path.is_symlink() or not is_supported_file(path):
                continue

            relative_path = path.relative_to(root).as_posix()

            try:
                size = path.stat().st_size
            except OSError:
                skipped.append({
                    "path": relative_path,
                    "reason": "File metadata could not be read.",
                })
                continue

            if size > max_file_bytes:
                skipped.append({
                    "path": relative_path,
                    "reason": "File exceeded the per-file safety limit.",
                })
                continue

            if len(files) >= max_files:
                raise SourceProjectError(
                    "The project exceeded the source-file safety limit."
                )

            if total_bytes + size > max_total_bytes:
                raise SourceProjectError(
                    "The project exceeded the total source-size safety limit."
                )

            try:
                content = path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                skipped.append({
                    "path": relative_path,
                    "reason": "File content could not be read.",
                })
                continue

            files.append({
                "path": relative_path,
                "extension": path.suffix.lower(),
                "name": path.name,
                "size": size,
                "content": content,
            })
            total_bytes += size

    return {
        "root": str(root),
        "files": files,
        "skipped": skipped,
        "total_bytes": total_bytes,
    }
