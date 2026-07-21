"""Parse exact dependency versions without executing client code."""

import json
import re
import tomllib


MAX_DEPENDENCIES = 1000


def _package(
    *,
    ecosystem,
    name,
    version,
    path,
    direct=None,
    scope="runtime",
):
    clean_name = str(name or "").strip()
    clean_version = str(version or "").strip().lstrip("v")

    if not clean_name or not clean_version:
        return None

    return {
        "ecosystem": ecosystem,
        "name": clean_name,
        "version": clean_version,
        "path": path,
        "direct": direct,
        "scope": scope,
    }


def _unresolved(path, reason, line=None):
    return {"path": path, "line": line, "reason": reason}


def _parse_requirements(item):
    packages = []
    unresolved = []

    for line_number, raw_line in enumerate(
        item["content"].splitlines(), start=1
    ):
        line = raw_line.strip()

        if not line or line.startswith(("#", "-")):
            continue

        requirement = line.split(";", 1)[0].strip()
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)"
            r"(?:\[[^\]]+\])?\s*={2,3}\s*([^\s#]+)",
            requirement,
        )

        if match:
            package = _package(
                ecosystem="PyPI",
                name=match.group(1),
                version=match.group(2),
                path=item["path"],
                direct=True,
            )
            if package:
                packages.append(package)
        elif re.match(r"^[A-Za-z0-9]", requirement):
            unresolved.append(_unresolved(
                item["path"],
                "Dependency does not use an exact pinned version.",
                line_number,
            ))

    return packages, unresolved


def _npm_name_from_path(package_path, details):
    declared_name = details.get("name")
    if isinstance(declared_name, str) and declared_name.strip():
        return declared_name.strip()

    marker = "node_modules/"
    if marker not in package_path:
        return None
    return package_path.rsplit(marker, 1)[-1]


def _parse_npm_dependency_tree(dependencies, path, *, top_level=True):
    packages = []
    for name, details in (dependencies or {}).items():
        if not isinstance(details, dict):
            continue

        package = _package(
            ecosystem="npm",
            name=name,
            version=details.get("version"),
            path=path,
            direct=top_level,
            scope="development" if details.get("dev") else "runtime",
        )
        if package:
            packages.append(package)

        packages.extend(_parse_npm_dependency_tree(
            details.get("dependencies"), path, top_level=False
        ))
    return packages


def _parse_package_lock(item):
    try:
        data = json.loads(item["content"])
    except (TypeError, ValueError):
        return [], [_unresolved(item["path"], "Lockfile is not valid JSON.")]

    packages = []
    package_map = data.get("packages")
    if isinstance(package_map, dict):
        for package_path, details in package_map.items():
            if not package_path or not isinstance(details, dict):
                continue

            name = _npm_name_from_path(package_path, details)
            package = _package(
                ecosystem="npm",
                name=name,
                version=details.get("version"),
                path=item["path"],
                direct=(package_path == f"node_modules/{name}" if name else False),
                scope="development" if details.get("dev") else "runtime",
            )
            if package:
                packages.append(package)
    else:
        packages.extend(_parse_npm_dependency_tree(
            data.get("dependencies"), item["path"]
        ))
    return packages, []


def _exact_npm_version(value):
    clean_value = str(value or "").strip()
    if re.fullmatch(
        r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?", clean_value
    ):
        return clean_value
    return None


def _parse_package_json(item):
    try:
        data = json.loads(item["content"])
    except (TypeError, ValueError):
        return [], [_unresolved(
            item["path"], "Package manifest is not valid JSON."
        )]

    packages = []
    unresolved = []
    for field, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
    ):
        for name, declared_version in (data.get(field) or {}).items():
            exact_version = _exact_npm_version(declared_version)
            if exact_version:
                package = _package(
                    ecosystem="npm",
                    name=name,
                    version=exact_version,
                    path=item["path"],
                    direct=True,
                    scope=scope,
                )
                if package:
                    packages.append(package)
            else:
                unresolved.append(_unresolved(
                    item["path"],
                    f"{name} does not use an exact version in package.json.",
                ))
    return packages, unresolved


def _parse_poetry_lock(item):
    try:
        data = tomllib.loads(item["content"])
    except (TypeError, ValueError):
        return [], [_unresolved(
            item["path"], "Poetry lockfile is not valid TOML."
        )]

    packages = []
    for details in data.get("package", []):
        if not isinstance(details, dict):
            continue
        package = _package(
            ecosystem="PyPI",
            name=details.get("name"),
            version=details.get("version"),
            path=item["path"],
            direct=None,
            scope=(
                "development"
                if details.get("category") in {"dev", "development"}
                else "runtime"
            ),
        )
        if package:
            packages.append(package)
    return packages, []


def _parse_pipfile_lock(item):
    try:
        data = json.loads(item["content"])
    except (TypeError, ValueError):
        return [], [_unresolved(
            item["path"], "Pipfile lock is not valid JSON."
        )]

    packages = []
    unresolved = []
    for field, scope in (("default", "runtime"), ("develop", "development")):
        for name, details in (data.get(field) or {}).items():
            version = details.get("version") if isinstance(details, dict) else None
            match = re.fullmatch(r"={2,3}([^\s]+)", str(version or "").strip())
            if match:
                package = _package(
                    ecosystem="PyPI",
                    name=name,
                    version=match.group(1),
                    path=item["path"],
                    direct=True,
                    scope=scope,
                )
                if package:
                    packages.append(package)
            else:
                unresolved.append(_unresolved(
                    item["path"], f"{name} does not have an exact locked version."
                ))
    return packages, unresolved


def _yarn_package_name(selector):
    clean_selector = selector.strip().strip("\"'")
    if clean_selector.startswith("@"):
        separator = clean_selector.find("@", 1)
        return clean_selector[:separator] if separator > 0 else None
    return clean_selector.split("@", 1)[0]


def _parse_yarn_lock(item):
    packages = []
    unresolved = []
    selectors = None

    for line_number, line in enumerate(item["content"].splitlines(), start=1):
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            selectors = line.rstrip()[:-1].split(",")
            continue
        if selectors is None:
            continue

        version_match = re.match(
            r"^\s+version(?:\s+|:\s*)[\"']?([^\"'\s]+)", line
        )
        if not version_match:
            continue

        package = _package(
            ecosystem="npm",
            name=_yarn_package_name(selectors[0]),
            version=version_match.group(1),
            path=item["path"],
            direct=None,
        )
        if package:
            packages.append(package)
        else:
            unresolved.append(_unresolved(
                item["path"],
                "Yarn dependency entry could not be identified.",
                line_number,
            ))
        selectors = None

    return packages, unresolved


PARSERS = {
    "requirements.txt": _parse_requirements,
    "package-lock.json": _parse_package_lock,
    "package.json": _parse_package_json,
    "poetry.lock": _parse_poetry_lock,
    "pipfile.lock": _parse_pipfile_lock,
    "yarn.lock": _parse_yarn_lock,
}


def collect_dependencies(files, *, max_dependencies=MAX_DEPENDENCIES):
    packages = []
    unresolved = []

    for item in files:
        parser = PARSERS.get(item["name"].lower())
        if parser is None:
            continue
        parsed, unresolved_items = parser(item)
        packages.extend(parsed)
        unresolved.extend(unresolved_items)

    unique = {}
    for package in packages:
        key = (
            package["ecosystem"].lower(),
            package["name"].lower(),
            package["version"],
        )
        if key not in unique:
            unique[key] = package

    ordered = sorted(
        unique.values(),
        key=lambda item: (
            item["ecosystem"].lower(),
            item["name"].lower(),
            item["version"],
        ),
    )
    return {
        "packages": ordered[:max_dependencies],
        "unresolved": unresolved[:200],
        "results_limited": len(ordered) > max_dependencies,
    }
