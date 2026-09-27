from __future__ import annotations

import io
import json
import zipfile
from importlib.resources import files
from pathlib import Path

from fastapi.testclient import TestClient


def test_packaged_demo_fixture_matches_original():
    source = Path(__file__).resolve().parents[2] / "demo" / "powershell-event.json"
    packaged = files("app").joinpath("data/powershell-event.json")
    assert json.loads(packaged.read_text(encoding="utf-8")) == json.loads(source.read_text(encoding="utf-8"))


def _incident(client: TestClient, auth: dict[str, str], event: dict[str, object]) -> str:
    result = client.post("/api/v1/events", headers=auth, json=event)
    assert result.status_code == 201, result.text
    return result.json()["incident_ids"][0]


def test_response_allowlist_target_validation_approval_and_idempotency(
    client: TestClient, auth: dict[str, str], demo_event: dict[str, object]
):
    incident_id = _incident(client, auth, demo_event)
    unsafe = client.post(
        "/api/v1/response-actions",
        headers=auth,
        json={
            "incident_id": incident_id,
            "action_type": "ISOLATE_ENDPOINT",
            "target": "demo-endpoint-01; rm -rf /",
            "idempotency_key": "unsafe-request-001",
        },
    )
    assert unsafe.status_code == 422

    request = {
        "incident_id": incident_id,
        "action_type": "ISOLATE_ENDPOINT",
        "target": "demo-endpoint-01",
        "idempotency_key": "isolation-request-001",
    }
    created = client.post("/api/v1/response-actions", headers=auth, json=request)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["approval_status"] == "PENDING"
    assert body["execution_status"] == "PENDING"
    assert body["dry_run"] is True

    duplicate = client.post("/api/v1/response-actions", headers=auth, json=request)
    assert duplicate.status_code == 201
    assert duplicate.json()["id"] == body["id"]

    changed = dict(request, target="demo-endpoint-02")
    conflict = client.post("/api/v1/response-actions", headers=auth, json=changed)
    assert conflict.status_code == 409

    approval = client.post(
        f"/api/v1/response-actions/{body['id']}/approval",
        headers=auth,
        json={"decision": "APPROVED", "reason": "Authorized controlled test"},
    )
    assert approval.status_code == 200, approval.text
    approved = approval.json()
    assert approved["execution_status"] == "DRY_RUN"
    assert approved["execution_result"]["executed"] is False
    assert approved["execution_result"]["verified"] is True
    again = client.post(
        f"/api/v1/response-actions/{body['id']}/approval",
        headers=auth,
        json={"decision": "APPROVED", "reason": "Duplicate decision"},
    )
    assert again.status_code == 409


def test_reports_contain_incident_data(client: TestClient, auth: dict[str, str], demo_event: dict[str, object]):
    incident_id = _incident(client, auth, demo_event)
    for report_format in ("pdf", "json", "csv", "zip"):
        result = client.post(f"/api/v1/incidents/{incident_id}/reports/{report_format}", headers=auth)
        assert result.status_code == 200, result.text
        download = client.get(result.json()["download_url"], headers=auth)
        assert download.status_code == 200
        assert download.content
        if report_format == "json":
            assert download.json()["id"] == incident_id
        if report_format == "csv":
            assert b"INCIDENT_CREATED" in download.content
        if report_format == "pdf":
            assert download.content.startswith(b"%PDF")
        if report_format == "zip":
            with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
                names = set(archive.namelist())
                assert {
                    "incident-report.pdf",
                    "incident.json",
                    "timeline.csv",
                    "iocs.csv",
                    "mitre-mapping.json",
                    "response-actions.json",
                }.issubset(names)
                assert incident_id in archive.read("incident.json").decode()
    listed = client.get("/api/v1/reports", headers=auth)
    assert listed.status_code == 200
    assert {item["format"] for item in listed.json()} == {"PDF", "JSON", "CSV", "ZIP"}


def test_complete_demo_reset_and_repeat(client: TestClient, auth: dict[str, str]):
    first = client.post("/api/v1/demo/run", headers=auth)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["safe_simulation"] is True
    assert body["external_actions_executed"] is False
    assert body["steps"]["normalization"] == "PASS"
    assert body["steps"]["mitre"] == "T1059.001"
    assert "DEMO_MOCK" in body["steps"]["cti"]
    assert body["steps"]["dry_run"] == "DRY_RUN"
    assert body["steps"]["approval"] == "APPROVED"
    assert body["steps"]["containment"] == "DRY_RUN"
    assert set(body["steps"]["reports"]) == {"pdf", "json", "csv", "zip"}
    detail = client.get(f"/api/v1/incidents/{body['incident_id']}", headers=auth).json()
    assert len(detail["evidence"]) == 3
    assert all(item["details"]["mode"] == "DEMO_MOCK" for item in detail["evidence"])
    assert detail["status"] == "INVESTIGATING"
    assert all(action["execution_result"]["executed"] is False for action in detail["response_actions"])
    assert all(action["execution_status"] == "DRY_RUN" for action in detail["response_actions"])

    reset = client.post("/api/v1/demo/reset", headers=auth)
    assert reset.status_code == 200, reset.text
    assert client.get("/api/v1/incidents", headers=auth).json() == []
    second = client.post("/api/v1/demo/run", headers=auth)
    assert second.status_code == 200, second.text
    assert second.json()["incident_id"] != body["incident_id"]
