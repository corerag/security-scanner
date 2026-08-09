from datetime import datetime, timezone

from fastapi.testclient import TestClient

from server import main as server_main

client = TestClient(server_main.app)

VALID_REPORT = {
    "scan_id": "22222222-2222-2222-2222-222222222222",
    "hostname": "ci-host",
    "os_platform": "Linux",
    "os_version": "test",
    "agent_version": "1.0.0",
    "scan_started_at": datetime.now(timezone.utc).isoformat(),
    "scan_completed_at": datetime.now(timezone.utc).isoformat(),
    "owner_email": "owner@example.com",
    "processes": [],
    "network_connections": [],
    "persistence": {"registry_run_keys": [], "scheduled_tasks": [], "startup_items": []},
    "file_hashes": [],
}


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_reports_endpoint_rejects_missing_api_key():
    response = client.post("/api/v1/reports", json=VALID_REPORT)
    assert response.status_code == 401


def test_reports_endpoint_rejects_wrong_api_key():
    response = client.post(
        "/api/v1/reports", json=VALID_REPORT, headers={"X-API-Key": "wrong-key"}
    )
    assert response.status_code == 401


def test_reports_endpoint_accepts_valid_report(tmp_path, monkeypatch):
    monkeypatch.setattr(server_main.cfg, "storage_dir", str(tmp_path))
    monkeypatch.setattr(server_main.email_service, "send_report_email", lambda report, cfg: None)

    response = client.post(
        "/api/v1/reports", json=VALID_REPORT, headers={"X-API-Key": server_main.cfg.api_key}
    )

    assert response.status_code == 201
    body = response.json()
    assert body["scan_id"] == VALID_REPORT["scan_id"]
    assert body["email_sent"] is True
    assert list(tmp_path.iterdir()), "report JSON should have been written to storage_dir"


def test_reports_endpoint_still_stores_report_when_email_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(server_main.cfg, "storage_dir", str(tmp_path))

    def _raise(*args, **kwargs):
        raise RuntimeError("SMTP unreachable")

    monkeypatch.setattr(server_main.email_service, "send_report_email", _raise)

    response = client.post(
        "/api/v1/reports", json=VALID_REPORT, headers={"X-API-Key": server_main.cfg.api_key}
    )

    assert response.status_code == 201
    assert response.json()["email_sent"] is False
    assert list(tmp_path.iterdir()), "report should still be saved even if email delivery fails"
