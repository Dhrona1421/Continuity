"""Hindsight REST contract tests (in-process HTTP emulator, NOT a live provider)."""
import json
from datetime import UTC, datetime

import httpx

from app.core.config import get_settings
from app.services import hindsight


def provider(monkeypatch):
    docs = {}
    recall_requests = []
    def handle(request):
        body = json.loads(request.content)
        if request.url.path.endswith("/recall"):
            recall_requests.append(body)
            return httpx.Response(200, json={"results": [
                {"document_id": key, "text": value} for key, value in docs.items()
            ]})
        for item in body["items"]:
            docs[item["document_id"]] = item["content"]
        return httpx.Response(200, json={"success": True, "async": False})
    original = httpx.Client
    monkeypatch.setattr(hindsight.httpx, "Client", lambda **kw: original(transport=httpx.MockTransport(handle), **kw))
    monkeypatch.setattr(get_settings(), "hindsight_url", "http://memory.test:8888")
    return docs, recall_requests


def create(client, auth, demo_event, *, host="demo-endpoint-01", title=None):
    data = dict(demo_event, event_id=f"test-{host}-{datetime.now(UTC).timestamp()}", host=host)
    result = client.post("/api/v1/events", headers=auth, json=data)
    assert result.status_code == 201, result.text
    return result.json()["incident_ids"][0]


def test_retain_recall_learn_update_and_irrelevant(client, auth, demo_event, monkeypatch):
    docs, recall_requests = provider(monkeypatch)
    first = create(client, auth, demo_event)
    stored = client.post("/api/v1/memory/retain", headers=auth, json={
        "incident_id": first, "outcome": "Simulation only; account evidence was lost in an analyst exercise",
        "initial_hypothesis": "Malware process", "failed_paths": ["Premature isolation lost session evidence"],
        "successful_paths": ["Collected original logs"], "important_evidence": ["Auth log"],
        "response_result": "Simulated containment; no external action", "side_effects": ["Lost session context"],
        "lessons": [{"lesson": "Preserve session evidence before isolation", "condition": "When operationally safe",
                     "recommended_behavior": "Collect logs first", "confidence": 0.8, "source_incident": first}],
    })
    assert stored.status_code == 200, stored.text
    assert stored.json()["status"] == "retained"
    assert len(docs) == 1 and "FAILED_PATHS" not in next(iter(docs.values()))  # structured JSON under heading
    searched = client.post("/api/v1/memory/search", headers=auth,
                           json={"query": "failed containment and preserved evidence"})
    assert searched.status_code == 200 and searched.json()["status"] == "available"
    assert searched.json()["matches"][0]["source_incident_id"] == first
    # Search spans Hindsight's retained memory types, including world facts
    # and observations that may not have a local GhostSOC source row.
    assert recall_requests[-1]["budget"] == "high"
    assert "types" not in recall_requests[-1]
    similar = create(client, auth, demo_event, host="demo-endpoint-02")
    recalled = client.post("/api/v1/memory/recall", headers=auth, json={"incident_id": similar}).json()
    assert recalled["status"] == "available" and len(recalled["matches"]) == 1
    experience = recalled["matches"][0]["experience"]
    assert experience["investigation"]["failed_paths"] and experience["response"]["side_effects"]
    assert experience["lessons"][0]["source_incident"] == first
    for decision in ("accepted", "modified", "rejected"):
        feedback = {"incident_id": first, "decision": decision, "reason": "Documented analyst decision",
                    "outcome": "Simulation only"}
        if decision == "modified":
            feedback["modification"] = "Preserve evidence first"
        result = client.post("/api/v1/memory/learn", headers=auth, json=feedback)
        assert result.json()["status"] == "retained"
    recalled = client.post("/api/v1/memory/recall", headers=auth, json={"incident_id": similar}).json()
    assert [f["decision"] for f in recalled["matches"][0]["experience"]["analyst_feedback"]] == [
        "accepted", "modified", "rejected"]
    row = recalled["matches"][0]
    update = client.post("/api/v1/memory/update", headers=auth, json={"memory_id": row["memory_id"],
        "expected_version": 4, "annotation": "Preserve critical forensic logs first", "correction_reason": "Review"})
    assert update.json()["status"] == "retained"
    assert len(docs) == 1  # document ID upsert, not duplicate memories
    conflict = client.post("/api/v1/memory/update", headers=auth, json={"memory_id": row["memory_id"],
        "expected_version": 4, "annotation": "Old correction", "correction_reason": "Old"})
    assert conflict.json()["status"] == "conflict"
    # Unrelated rows are filtered even if the provider returns an overly broad candidate set.
    from app.core.database import SessionLocal
    from app.models import Incident
    with SessionLocal() as db:
        unrelated = Incident(title="Ransomware encryption", description="Disk encryption", severity="HIGH",
                             correlation_key="unrelated-case")
        db.add(unrelated)
        db.commit()
        db.refresh(unrelated)
        other_id = unrelated.id
    response = client.post("/api/v1/memory/recall", headers=auth, json={"incident_id": other_id}).json()
    assert response["status"] == "available" and response["matches"] == []


def test_transient_provider_failure_is_explicit(client, auth, demo_event, monkeypatch):
    incident = create(client, auth, demo_event)
    monkeypatch.setattr(get_settings(), "hindsight_url", "http://memory.test:8888")
    original = httpx.Client

    def failure(_):
        raise httpx.ConnectError("provider offline")

    monkeypatch.setattr(hindsight.httpx, "Client", lambda **kw: original(transport=httpx.MockTransport(failure), **kw))
    assert client.post("/api/v1/memory/recall", headers=auth,
                       json={"incident_id": incident}).json()["status"] == "unavailable"
    assert client.post("/api/v1/memory/retain", headers=auth,
                       json={"incident_id": incident, "outcome": "Reviewed only"}).json()["status"] == "unavailable"
    assert client.get(f"/api/v1/incidents/{incident}", headers=auth).status_code == 200


def test_memory_rbac_and_unverified_lessons_rejected(client, auth, demo_event, monkeypatch):
    monkeypatch.setattr(get_settings(), "hindsight_url", None)
    incident = create(client, auth, demo_event)
    client.cookies.clear()
    assert client.post("/api/v1/memory/recall", json={"incident_id": incident}).status_code == 401
    assert client.post("/api/v1/memory/search", json={"query": "credential theft"}).status_code == 401
    fake = client.post("/api/v1/memory/retain", headers=auth, json={"incident_id": incident,
        "outcome": "Synthetic test", "lessons": [{"source_incident": "fabricated-source", "lesson": "fake"}]})
    assert fake.status_code == 422


def test_provider_unavailable_does_not_block_incident(client, auth, demo_event, monkeypatch):
    monkeypatch.setattr(get_settings(), "hindsight_url", None)
    incident = create(client, auth, demo_event)
    assert client.post("/api/v1/memory/recall", headers=auth, json={"incident_id": incident}).json() == {
        "status": "unavailable", "matches": []}
    retained = client.post("/api/v1/memory/retain", headers=auth,
                           json={"incident_id": incident, "outcome": "Reviewed; no external response"})
    assert retained.json()["status"] == "unavailable"
    local = client.get(f"/api/v1/incidents/{incident}/experience", headers=auth).json()
    assert local["status"] == "recorded" and local["provider_status"] == "unavailable"
    assert local["experience"]["incident"]["outcome"] == "Reviewed; no external response"
    assert client.get(f"/api/v1/incidents/{incident}", headers=auth).status_code == 200
    assert client.patch(f"/api/v1/incidents/{incident}", headers=auth, json={"status": "CLOSED"}).status_code == 200
