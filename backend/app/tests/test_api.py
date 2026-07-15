from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_home_endpoint_returns_success():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Welcome to WebShield"
    }


def test_scan_endpoint_returns_report(monkeypatch):
    def fake_scan(domain):
        return {
            "domain": domain,
            "scan_status": "Complete",
            "overall_status": "Good",
            "score": 80,
        }

    monkeypatch.setattr(
        "app.main.run_full_scan",
        fake_scan,
    )

    response = client.get(
        "/scan",
        params={"domain": "example.com"},
    )

    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert response.json()["scan_status"] == "Complete"
    assert response.json()["score"] == 80


def test_scan_rejects_localhost():
    response = client.get(
        "/scan",
        params={"domain": "localhost"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Local or internal websites cannot be scanned."
    )


def test_scan_requires_domain():
    response = client.get("/scan")

    assert response.status_code == 422