from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.security import create_access_token, hash_password
from app.models import ResponsePolicy, User
from app.services.realtime import live_broker


def test_response_context_exposes_only_server_validated_targets(client: TestClient, auth: dict[str, str]):
    demo = client.post("/api/v1/demo/web-run", headers=auth)
    assert demo.status_code == 200
    incident_id = demo.json()["incident_ids"][0]
    context = client.get(f"/api/v1/incidents/{incident_id}/response-context", headers=auth)
    assert context.status_code == 200
    body = context.json()
    assert body["mode"] == "DRY_RUN"
    assert body["permissions"] == {"can_request": True, "can_approve": True}
    assert all(item["status"] in {"PASS", "DRY_RUN"} for item in body["guardrails"])
    actions = {item["action_type"]: item for item in body["actions"]}
    assert set(actions) == {
        "COLLECT_EVIDENCE",
        "RATE_LIMIT_SOURCE",
        "BLOCK_SOURCE",
        "BLOCK_IOC",
        "QUARANTINE_FILE",
        "TERMINATE_PROCESS",
        "ISOLATE_ENDPOINT",
    }
    assert actions["RATE_LIMIT_SOURCE"]["preapproved"] is True
    assert actions["RATE_LIMIT_SOURCE"]["targets"] == [
        {
            "value": "198.51.100.23",
            "label": "198.51.100.23",
            "type": "SOURCE_IP",
            "source": actions["RATE_LIMIT_SOURCE"]["targets"][0]["source"],
        }
    ]
    assert actions["BLOCK_SOURCE"]["approval_required"] is True
    assert actions["COLLECT_EVIDENCE"]["enabled"] is False
    assert actions["TERMINATE_PROCESS"]["targets"] == []
    assert "arbitrary" in body["guardrails"][-1]["detail"].lower()


def test_manual_request_approval_and_sse_response_updates(client: TestClient, auth: dict[str, str]):
    demo = client.post("/api/v1/demo/web-run", headers=auth).json()
    incident_id = demo["incident_ids"][0]
    request = client.post(
        "/api/v1/response-actions",
        headers=auth,
        json={
            "incident_id": incident_id,
            "action_type": "BLOCK_SOURCE",
            "target": "198.51.100.23",
            "idempotency_key": "manual-block-source-001",
        },
    )
    assert request.status_code == 201, request.text
    action = request.json()
    assert action["approval_status"] == "PENDING"
    assert action["execution_status"] == "PENDING"
    assert live_broker.recent(1)[0]["type"] == "response"

    context = client.get(f"/api/v1/incidents/{incident_id}/response-context", headers=auth).json()
    pending = next(item for item in context["response_actions"] if item["id"] == action["id"])
    assert pending["approval_status"] == "PENDING"

    approval = client.post(
        f"/api/v1/response-actions/{action['id']}/approval",
        headers=auth,
        json={"decision": "APPROVED", "reason": "Confirmed controlled source in demo"},
    )
    assert approval.status_code == 200
    assert approval.json()["approval_status"] == "APPROVED"
    assert approval.json()["execution_status"] == "DRY_RUN"
    assert approval.json()["execution_result"]["executed"] is False
    assert live_broker.recent(1)[0]["data"]["execution_status"] == "DRY_RUN"


def test_response_context_permissions_and_policy_minimum(client: TestClient, auth: dict[str, str]):
    demo = client.post("/api/v1/demo/web-run", headers=auth).json()
    incident_id = demo["incident_ids"][0]
    with SessionLocal() as db:
        viewer = User(
            email="response-viewer@ghostsoc.local",
            password_hash=hash_password("response-viewer-password"),
            role="VIEWER",
        )
        db.add(viewer)
        db.commit()
        db.refresh(viewer)
        viewer_token = create_access_token(viewer.id, viewer.role)
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    context = client.get(f"/api/v1/incidents/{incident_id}/response-context", headers=viewer_headers)
    assert context.status_code == 200
    assert context.json()["permissions"] == {"can_request": False, "can_approve": False}
    denied = client.post(
        "/api/v1/response-actions",
        headers=viewer_headers,
        json={
            "incident_id": incident_id,
            "action_type": "RATE_LIMIT_SOURCE",
            "target": "198.51.100.23",
            "idempotency_key": "viewer-rate-limit-001",
        },
    )
    assert denied.status_code == 403

    endpoint_demo = client.post("/api/v1/demo/run", headers=auth).json()
    endpoint_incident = endpoint_demo["incident_id"]
    with SessionLocal() as db:
        policy = db.scalar(select(ResponsePolicy).where(ResponsePolicy.name == "Safe default"))
        policy.min_risk_level = "CRITICAL"
        db.commit()
    below_minimum = client.post(
        "/api/v1/response-actions",
        headers=auth,
        json={
            "incident_id": endpoint_incident,
            "action_type": "ISOLATE_ENDPOINT",
            "target": "demo-endpoint-01",
            "idempotency_key": "below-minimum-risk-001",
        },
    )
    assert below_minimum.status_code == 403
    assert "below policy minimum" in below_minimum.json()["error"]["message"]
