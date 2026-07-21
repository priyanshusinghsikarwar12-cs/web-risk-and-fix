import json

from app.source_scanners.dependency_inventory import (
    collect_dependencies,
)


def source_file(name, content):
    return {
        "name": name,
        "path": name,
        "content": content,
        "extension": ".json",
        "size": len(content),
    }


def test_pinned_python_requirements_are_collected():
    result = collect_dependencies([
        source_file(
            "requirements.txt",
            "requests==2.31.0\nflask>=2\n-r base.txt\n",
        )
    ])

    assert result["packages"] == [{
        "ecosystem": "PyPI",
        "name": "requests",
        "version": "2.31.0",
        "path": "requirements.txt",
        "direct": True,
        "scope": "runtime",
    }]
    assert len(result["unresolved"]) == 1


def test_package_lock_collects_direct_and_transitive_versions():
    content = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "portal", "version": "1.0.0"},
            "node_modules/react": {"version": "19.2.7"},
            "node_modules/tool/node_modules/lodash": {
                "version": "4.17.20",
                "dev": True,
            },
        },
    })

    result = collect_dependencies([
        source_file("package-lock.json", content)
    ])

    assert [item["name"] for item in result["packages"]] == [
        "lodash", "react"
    ]
    lodash = result["packages"][0]
    assert lodash["direct"] is False
    assert lodash["scope"] == "development"


def test_package_json_ranges_are_not_guessed():
    content = json.dumps({
        "dependencies": {
            "react": "^19.0.0",
            "exact-library": "1.2.3",
        }
    })

    result = collect_dependencies([
        source_file("package.json", content)
    ])

    assert [item["name"] for item in result["packages"]] == [
        "exact-library"
    ]
    assert "react" in result["unresolved"][0]["reason"]


def test_poetry_lock_is_parsed_without_executing_project_code():
    content = """
[[package]]
name = "jinja2"
version = "2.4.1"
category = "main"
"""
    result = collect_dependencies([
        source_file("poetry.lock", content)
    ])

    assert result["packages"][0]["ecosystem"] == "PyPI"
    assert result["packages"][0]["version"] == "2.4.1"


def test_duplicate_coordinates_are_removed():
    result = collect_dependencies([
        source_file("requirements.txt", "requests==2.31.0\nrequests==2.31.0")
    ])

    assert len(result["packages"]) == 1


def test_dependency_inventory_is_bounded():
    content = "\n".join(
        f"package-{index}==1.0.{index}" for index in range(5)
    )
    result = collect_dependencies(
        [source_file("requirements.txt", content)],
        max_dependencies=2,
    )

    assert len(result["packages"]) == 2
    assert result["results_limited"] is True
