from app.deep_scanners.exposure_checks import (
    _directory_listing_fingerprint,
    _looks_like_soft_404,
    _sensitive_fingerprint,
)


class FakeResponse:
    def __init__(
        self,
        content,
        status_code=200,
        content_type="text/plain",
    ):
        self.content = content
        self.status_code = status_code
        self.headers = {
            "Content-Type": content_type,
        }


def test_env_file_requires_multiple_signals():
    response = FakeResponse(
        b"DB_HOST=localhost\nDB_PASSWORD=secret"
    )

    result = _sensitive_fingerprint(
        "/.env",
        response,
    )

    assert result is not None


def test_normal_text_is_not_env_file():
    response = FakeResponse(
        b"Welcome to our website"
    )

    result = _sensitive_fingerprint(
        "/.env",
        response,
    )

    assert result is None


def test_git_configuration_is_detected():
    response = FakeResponse(
        b"[core]\nrepositoryformatversion = 0"
    )

    result = _sensitive_fingerprint(
        "/.git/config",
        response,
    )

    assert result is not None


def test_zip_magic_is_detected():
    response = FakeResponse(
        b"PK\x03\x04binary-data",
        content_type="application/zip",
    )

    result = _sensitive_fingerprint(
        "/backup.zip",
        response,
    )

    assert result is not None


def test_sql_dump_is_detected():
    response = FakeResponse(
        b"""
        -- SQL dump
        CREATE TABLE users (id INT);
        INSERT INTO users VALUES (1);
        """
    )

    result = _sensitive_fingerprint(
        "/database.sql",
        response,
    )

    assert result is not None


def test_directory_listing_is_detected():
    response = FakeResponse(
        b"""
        <html>
          <title>Index of /uploads/</title>
          <a href="../">Parent Directory</a>
          Last Modified
        </html>
        """
    )

    result = _directory_listing_fingerprint(
        response
    )

    assert result is not None


def test_normal_page_is_not_directory_listing():
    response = FakeResponse(
        b"<title>Photo Gallery</title>"
    )

    result = _directory_listing_fingerprint(
        response
    )

    assert result is None


def test_matching_soft_404_is_recognized():
    baseline = FakeResponse(
        b"<html>Page not found</html>",
        status_code=200,
    )

    candidate = FakeResponse(
        b"<html>Page not found</html>",
        status_code=200,
    )

    assert _looks_like_soft_404(
        candidate,
        baseline,
    ) is True