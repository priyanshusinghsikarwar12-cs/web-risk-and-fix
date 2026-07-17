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
    def fake_scan(
        domain,
        dkim_selector=None,
    ):
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

def test_scan_passes_dkim_selector(monkeypatch):
    received_values = {}

    def fake_scan(
        domain,
        dkim_selector=None,
    ):
        received_values["domain"] = domain
        received_values["selector"] = dkim_selector

        return {
            "domain": domain,
            "scan_status": "Complete",
            "dkim": {
                "status": "Configured",
                "selector": dkim_selector,
            },
        }

    monkeypatch.setattr(
        "app.main.run_full_scan",
        fake_scan,
    )

    response = client.get(
        "/scan",
        params={
            "domain": "example.com",
            "dkim_selector": "Selector1",
        },
    )

    assert response.status_code == 200
    assert received_values["domain"] == "example.com"
    assert received_values["selector"] == "selector1"
    assert response.json()["dkim"]["status"] == (
        "Configured"
    )


def test_scan_rejects_invalid_dkim_selector():
    response = client.get(
        "/scan",
        params={
            "domain": "example.com",
            "dkim_selector": "../invalid selector",
        },
    )

    assert response.status_code == 400
    assert "selector" in response.json()["detail"].lower()    