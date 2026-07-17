from app.scanners.script_inventory import (
    detect_library_from_url,
)


def test_detects_jsdelivr_package_version():
    result = detect_library_from_url(
        "https://cdn.jsdelivr.net/npm/"
        "jquery@3.7.1/dist/jquery.min.js"
    )

    assert result["name"] == "jquery"
    assert result["version"] == "3.7.1"
    assert result["confidence"] == "High"


def test_detects_unpkg_package_version():
    result = detect_library_from_url(
        "https://unpkg.com/axios@1.7.2/"
        "dist/axios.min.js"
    )

    assert result["name"] == "axios"
    assert result["version"] == "1.7.2"
    assert result["confidence"] == "High"


def test_detects_cdnjs_package_version():
    result = detect_library_from_url(
        "https://cdnjs.cloudflare.com/ajax/libs/"
        "lodash.js/4.17.21/lodash.min.js"
    )

    assert result["name"] == "lodash.js"
    assert result["version"] == "4.17.21"
    assert result["confidence"] == "High"


def test_detects_version_from_filename():
    result = detect_library_from_url(
        "https://example.com/js/jquery-3.6.0.min.js"
    )

    assert result["name"] == "jQuery"
    assert result["version"] == "3.6.0"
    assert result["confidence"] == "Medium"


def test_unknown_script_is_not_guessed():
    result = detect_library_from_url(
        "https://example.com/js/application.js"
    )

    assert result is None

def test_detects_wordpress_query_version():
    result = detect_library_from_url(
        "https://example.com/wp-includes/js/"
        "jquery/jquery.min.js?ver=3.7.1"
    )

    assert result["name"] == "jQuery"
    assert result["version"] == "3.7.1"
    assert result["confidence"] == "Low"


def test_detects_library_without_version():
    result = detect_library_from_url(
        "https://example.com/js/bootstrap.bundle.min.js"
    )

    assert result["name"] == "Bootstrap"
    assert result["version"] is None
    assert result["confidence"] == "Low"