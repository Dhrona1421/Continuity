"""Seven API contract cases using a STUB Hindsight and STUB inference provider.

These DO NOT constitute live Hindsight/LLM evaluation. See docs/AI_AGENT.md.
"""
import json
import uuid

import httpx

from app.core.config import get_settings
from app.models import Incident
from app.services import agent


def adapters(monkeypatch):
    docs = {}
    contexts = []

    def handle(request):
        data = json.loads(request.content)
        if request.url.path.endswith("/memories"):
            for item in data["items"]:
                docs[item["document_id"]] = item["content"]
            return httpx.Response(200, json={"success": True, "async": False})
        if request.url.path.endswith("/recall"):
            return httpx.Response(200, json={"results": [
                {"document_id": doc, "text": text[:200]} for doc, text in docs.items()]})
        assert request.url.path.endswith("/chat/completions")
        context = json.loads(data["messages"][1]["content"])
        contexts.append(context)
        history = context["historical_evidence"]
        failed = any(h["failed_paths"] or h["side_effects"] or
                     any(f["decision"] == "rejected" for f in h["analyst_feedback"]) for h in history)
        success = any(h["successful_paths"] or any(f["decision"] == "accepted" and f.get("outcome")
                                                   for f in h["analyst_feedback"]) for h in history)
        steps = (["Preserve authentication evidence", "Capture session information",
                  "Escalate session revocation", "Escalate account disable", "Continue investigation"]
                 if failed else ["Review current telemetry", "Correlate source IP", "Review containment policy"])
        output = {"steps": steps, "reasoning": "Prior investigation failure requires preservation before containment."
                  if failed else "Current evidence warrants a careful review of the alert.",
                  "suggested_next_steps": ["Review IOC context"], "confidence": 0.6,
                  "cited_incident_ids": [h["source_incident_id"] for h in history],
                  "conflict_reasoning": (
                      "One approach succeeded, while another lost evidence; prioritize preservation "
                      "then assess urgent containment against current risk."
                  ) if failed and success else None}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(output)}}]})

    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: original(transport=httpx.MockTransport(handle), **kw))
    settings = get_settings()
    monkeypatch.setattr(settings, "hindsight_url", "http://memory.test:8888")
    monkeypatch.setattr(settings, "llm_base_url", "http://llm.test/v1")
    monkeypatch.setattr(settings, "llm_api_key", "test-only-placeholder")
    return docs, contexts


def incident(db, title="Credential compromise"):
    case = Incident(title=title, description="Authentication and session investigation",
                    severity="HIGH", correlation_key=str(uuid.uuid4()))
    db.add(case)
    db.commit()
    db.refresh(case)
    return case.id


def retain(client, auth, incident_id, **changes):
    response = client.post("/api/v1/memory/retain", headers=auth, json={
        "incident_id": incident_id, "outcome": "Synthetic test exercise with no external action", **changes})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "retained"


def recommend(client, auth, incident_id, **kwargs):
    response = client.post(f"/api/v1/incidents/{incident_id}/recommendation", headers=auth, **kwargs)
    assert response.status_code == 200, response.text
    return response.json()


def test_1_relevant_memory_retrieved(client, auth, db_session, monkeypatch):
    adapters(monkeypatch)
    old = incident(db_session)
    retain(client, auth, old, successful_paths=["Correlated sign-ins"])
    new = incident(db_session)
    result = recommend(client, auth, new)
    assert result["historical_evidence"][0]["source_incident_id"] == old


def test_2_no_memory_never_fabricated(client, auth, db_session, monkeypatch):
    _, contexts = adapters(monkeypatch)
    current = incident(db_session)
    result = recommend(client, auth, current)
    assert result["memory_note"] == "No relevant historical experience found."
    assert result["historical_evidence"] == [] and contexts[-1]["historical_evidence"] == []


def test_provider_outage_is_not_reported_as_no_history(client, auth, db_session, monkeypatch):
    _, contexts = adapters(monkeypatch)
    monkeypatch.setattr(agent, "recall", lambda *_: {"status": "unavailable", "matches": []})
    current = incident(db_session)
    result = recommend(client, auth, current)
    assert result["status"] == "ready"
    assert result["memory_status"] == "unavailable"
    assert result["memory_note"] == "Security Memory unavailable; recommendation uses current evidence only."
    assert contexts[-1]["memory_status"] == "unavailable"
    assert not result["historical_evidence"]
    bypassed = recommend(client, auth, current, params={"without_memory": "true"})
    assert bypassed["memory_status"] == "bypassed"
    assert "intentionally bypassed" in bypassed["memory_note"]


def test_3_prior_failure_changes_order(client, auth, db_session, monkeypatch):
    adapters(monkeypatch)
    old = incident(db_session)
    retain(client, auth, old, failed_paths=["Premature disable lost session evidence"],
           side_effects=["Session evidence lost"], lessons=[{
               "lesson": "Preserve logs first", "condition": "When safe", "source_incident": old}])
    result = recommend(client, auth, incident(db_session))
    assert result["steps"][0] == "Preserve authentication evidence"
    assert "Session evidence lost" in result["historical_evidence"][0]["side_effects"]


def test_4_prior_success_recalled(client, auth, db_session, monkeypatch):
    adapters(monkeypatch)
    old = incident(db_session)
    retain(client, auth, old, successful_paths=["Correlate source IP across accounts"])
    result = recommend(client, auth, incident(db_session))
    assert "Correlate source IP across accounts" in result["historical_evidence"][0]["successful_paths"]


def test_5_analyst_rejection_is_learning_signal(client, auth, db_session, monkeypatch):
    adapters(monkeypatch)
    old = incident(db_session)
    retain(client, auth, old)
    saved = client.post("/api/v1/memory/learn", headers=auth, json={"incident_id": old, "decision": "rejected",
        "reason": "Preserve active-session evidence first", "outcome": "Evidence was retained"})
    assert saved.json()["status"] == "retained"
    result = recommend(client, auth, incident(db_session))
    assert result["steps"][0] == "Preserve authentication evidence"
    assert result["historical_evidence"][0]["analyst_feedback"][0]["decision"] == "rejected"


def test_6_conflict_explained(client, auth, db_session, monkeypatch):
    adapters(monkeypatch)
    first = incident(db_session)
    retain(client, auth, first, successful_paths=["Correlated source IP early"])
    second = incident(db_session)
    retain(client, auth, second, failed_paths=["Containment too early lost logs"])
    result = recommend(client, auth, incident(db_session))
    assert len(result["historical_evidence"]) == 2
    assert "lost evidence" in result["conflict_reasoning"]


def test_7_new_outcome_changes_later_recommendation(client, auth, db_session, monkeypatch):
    adapters(monkeypatch)
    first = incident(db_session)
    future = incident(db_session)
    before = recommend(client, auth, future)
    retain(client, auth, first, failed_paths=["Premature containment lost logs"])
    after = recommend(client, auth, future)
    assert before["steps"][0] != after["steps"][0]
    assert after["historical_evidence"][0]["source_incident_id"] == first


def test_historical_claim_in_steps_without_memory_fails_closed(client, auth, db_session, monkeypatch):
    adapters(monkeypatch)
    case = incident(db_session)
    original = agent.Draft.model_validate
    def misleading(_):
        return original({"steps": ["As we saw before, isolate this host"],
                         "reasoning": "Current evidence requires review.", "confidence": .5})
    monkeypatch.setattr(agent.Draft, "model_validate", misleading)
    result = recommend(client, auth, case)
    assert result["status"] == "unavailable"
    assert not result["historical_evidence"]


def test_invalid_citation_and_conflict_fail_closed(client, auth, db_session, monkeypatch):
    adapters(monkeypatch)
    case = incident(db_session)
    # Invalid model output is rejected, not reported as an AI recommendation.
    original = agent.Draft.model_validate
    def bad(_):
        draft = original({"steps": ["Investigate"], "reasoning": "Current evidence requires review.",
                          "confidence": .5, "cited_incident_ids": ["fabricated-incident"]})
        return draft
    monkeypatch.setattr(agent.Draft, "model_validate", bad)
    result = recommend(client, auth, case)
    assert result["status"] == "unavailable"
