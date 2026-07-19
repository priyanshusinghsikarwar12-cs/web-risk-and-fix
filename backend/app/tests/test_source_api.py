import io
import zipfile

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def archive_bytes():
    output = io.BytesIO()

    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("app.py", "print('hello')")

    return output.getvalue()


def authorized_headers():
    return {
        "Content-Type": "application/zip",
        "X-WebShield-Project-Name": "Client Portal",
        "X-WebShield-Source-Authorization": "authorized",
        "X-WebShield-Client-Reference": "approval-email-2026-07-18",
    }


def test_source_archive_endpoint_requires_authorization():
    response = client.post(
        "/source-scan/archive",
        content=archive_bytes(),
        headers={"Content-Type": "application/zip"},
    )

    assert response.status_code == 403
    assert "authorization" in response.json()["detail"].lower()


def test_source_archive_endpoint_requires_client_reference():
    headers = authorized_headers()
    headers.pop("X-WebShield-Client-Reference")

    response = client.post(
        "/source-scan/archive",
        content=archive_bytes(),
        headers=headers,
    )

    assert response.status_code == 400
    assert "reference" in response.json()["detail"].lower()


def test_source_archive_endpoint_rejects_other_media_types():
    headers = authorized_headers()
    headers["Content-Type"] = "application/json"

    response = client.post(
        "/source-scan/archive",
        content=b"{}",
        headers=headers,
    )

    assert response.status_code == 415


def test_source_archive_endpoint_returns_report(monkeypatch):
    received = {}

    def fake_scan(archive, **kwargs):
        received["archive"] = archive
        received.update(kwargs)
        return {
            "name": "Authorized Source Code Review",
            "project_name": kwargs["project_name"],
            "status": "No Listed Patterns Observed",
        }

    monkeypatch.setattr(
        "app.main.scan_authorized_source_archive",
        fake_scan,
    )

    response = client.post(
        "/source-scan/archive",
        content=archive_bytes(),
        headers=authorized_headers(),
    )

    assert response.status_code == 200
    assert response.json()["project_name"] == "Client Portal"
    assert received["authorization_attested"] is True
    assert received["client_reference"] == (
        "approval-email-2026-07-18"
    )


def test_source_archive_endpoint_enforces_stream_limit(monkeypatch):
    monkeypatch.setattr("app.main.MAX_ARCHIVE_BYTES", 5)

    response = client.post(
        "/source-scan/archive",
        content=b"123456",
        headers=authorized_headers(),
    )

    assert response.status_code == 413
