from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.services.detection import RULE_DIR, RuleValidationError, load_rule_files, validate_rule


def test_packaged_rules_match_reviewed_source():
    source = Path(__file__).resolve().parents[1] / "rules"
    originals = {item.name: item.read_bytes() for item in source.glob("*.yml")}
    packaged = {item.name: item.read_bytes() for item in RULE_DIR.glob("*.yml")}
    assert len(originals) >= 3 and packaged == originals


def test_rule_files_validate_and_unsafe_condition_rejected():
    rules = load_rule_files()
    assert {rule["id"] for rule in rules} >= {"GS-SIGMA-001", "GS-SIGMA-002"}
    bad = {
        "id": "bad",
        "title": "bad",
        "description": "bad",
        "level": "low",
        "detection": {"selection": {"host": "x"}, "condition": "selection | eval"},
    }
    try:
        validate_rule(bad)
        raise AssertionError("unsafe rule was accepted")
    except RuleValidationError:
        pass


def test_event_to_detection_incident_risk_and_deduplication(
    client: TestClient, auth: dict[str, str], demo_event: dict[str, object]
):
    created = client.post("/api/v1/events", headers=auth, json=demo_event)
    assert created.status_code == 201, created.text
    result = created.json()
    assert result["duplicate"] is False
    assert result["alerts_created"] == 1
    assert len(result["incident_ids"]) == 1

    duplicate = client.post("/api/v1/events", headers=auth, json=demo_event)
    assert duplicate.status_code == 201
    assert duplicate.json()["duplicate"] is True
    assert duplicate.json()["alerts_created"] == 0
    assert duplicate.json()["incident_ids"] == result["incident_ids"]

    alerts = client.get("/api/v1/alerts", headers=auth).json()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "GS-SIGMA-001"
    assert alerts[0]["mitre_techniques"] == ["T1059.001"]
    incident = client.get(f"/api/v1/incidents/{result['incident_ids'][0]}", headers=auth)
    assert incident.status_code == 200
    body = incident.json()
    assert body["alerts"][0]["evidence_reference"] == "fixture:pytest"
    assert body["risk_score"] > 50
    assert "Detection confidence" in " ".join(body["risk_reasons"])
    assert {ioc["ioc_type"] for ioc in body["iocs"]} == {"IP", "DOMAIN", "URL", "HASH"}
    assert body["timeline"][0]["event_type"] == "INCIDENT_CREATED"

    hosts = client.get("/api/v1/hosts", headers=auth).json()
    assert hosts[0]["host"] == "demo-endpoint-01"
    assert hosts[0]["event_count"] == 1
    assert client.get("/api/v1/iocs", headers=auth).json()[0]["incident_id"] == body["id"]
    assert "T1059.001" in {item["id"] for item in client.get("/api/v1/mitre", headers=auth).json()}
    assert client.get(f"/api/v1/timeline?incident_id={body['id']}", headers=auth).json()
    assert client.get("/api/v1/response-policies", headers=auth).json()[0]["name"] == "Safe default"

    dashboard = client.get("/api/v1/dashboard", headers=auth).json()
    assert dashboard["metrics"]["active_threats"] == 1
    assert dashboard["metrics"]["critical_alerts"] == 0
    assert dashboard["metrics"]["hosts"] == 1
    assert dashboard["metrics"]["events"] == 1
    assert dashboard["metrics"]["contained_confirmed"] == 0


def test_telemetry_normalization_and_malformed_input(client: TestClient, auth: dict[str, str]):
    sysmon = {
        "System": {
            "EventRecordID": 42,
            "EventID": 1,
            "TimeCreated": "2026-08-17T10:00:00Z",
            "Computer": "demo-endpoint-01",
        },
        "EventData": {
            "Image": "C:\\Windows\\powershell.exe",
            "CommandLine": "powershell.exe -enc ZABlAG0AbwA=",
            "User": "LAB\\user",
        },
    }
    result = client.post("/api/v1/events/telemetry/sysmon", headers=auth, json=sysmon)
    assert result.status_code == 201, result.text
    assert result.json()["event"]["event_id"] == "sysmon:42"
    assert result.json()["alerts_created"] == 1
    malformed = client.post("/api/v1/events/telemetry/sysmon", headers=auth, json={})
    assert malformed.status_code == 422
    assert "normalization failed" in malformed.json()["error"]["message"].lower()


def test_hunt_uses_controlled_filters(client: TestClient, auth: dict[str, str], demo_event: dict[str, object]):
    client.post("/api/v1/events", headers=auth, json=demo_event)
    result = client.get("/api/v1/hunt?q=demo-endpoint", headers=auth)
    assert result.status_code == 200
    assert len(result.json()["events"]) == 1
    invalid = client.get("/api/v1/hunt?q=x", headers=auth)
    assert invalid.status_code == 422
