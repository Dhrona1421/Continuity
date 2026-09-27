"""Synthetic demo arc contract; external services are emulated, not live tested."""
from test_agent_contract import adapters, recommend


def test_novabank_three_incident_loop(client, auth, monkeypatch):
    docs, contexts = adapters(monkeypatch)
    loaded = client.post("/api/v1/demo/novabank", headers=auth)
    assert loaded.status_code == 200, loaded.text
    data = loaded.json()
    assert data["synthetic"] is True and data["memory_status"] == "retained"
    first, second, third = data["incident_ids"]
    assert len(set(data["incident_ids"])) == 3
    assert len(docs) == 1
    source = client.get(f"/api/v1/incidents/{first}/experience", headers=auth)
    assert source.status_code == 200
    assert source.json()["provider_status"] == "retained"
    assert source.json()["experience"]["investigation"]["failed_paths"]
    assert "Preserve critical authentication evidence" in source.json()["experience"]["lessons"][0]["lesson"]
    assert client.post("/api/v1/demo/novabank", headers=auth).json()["status"] == "EXISTING"
    for case in data["incident_ids"]:
        detail = client.get(f"/api/v1/incidents/{case}", headers=auth).json()
        assert "Synthetic security incidents" in detail["description"]
        assert detail["alerts"] and detail["timeline"] and detail["iocs"]
    no_history = recommend(client, auth, first)
    assert no_history["memory_note"] == "No relevant historical experience found."
    without = recommend(client, auth, second, params={"without_memory": "true"})
    with_memory = recommend(client, auth, second)
    assert without["historical_evidence"] == []
    assert with_memory["steps"][0] != without["steps"][0]
    assert with_memory["historical_evidence"][0]["source_incident_id"] == first
    assert "lost" in with_memory["historical_evidence"][0]["side_effects"][0]
    accepted = client.post("/api/v1/memory/learn", headers=auth, json={
        "incident_id": second, "recommendation_id": with_memory["recommendation_id"],
        "decision": "accepted", "reason": "Preservation-first plan approved after analyst review",
        "outcome": "Synthetic exercise: authentication logs preserved; source IP correlated across accounts",
        "lesson": {"lesson": "Correlate source IP across related accounts before containment",
                   "condition": "When spray signals span accounts", "recommended_behavior": "Preserve then correlate",
                   "source_incident": second, "confidence": None},
    })
    assert accepted.json()["status"] == "retained" and len(docs) == 2
    recorded = client.get(f"/api/v1/incidents/{second}/experience", headers=auth).json()
    assert recorded["experience"]["analyst_feedback"][0]["decision"] == "accepted"
    assert "Correlate source IP" in recorded["experience"]["lessons"][0]["lesson"]
    refined = recommend(client, auth, third)
    assert refined["status"] == "ready" and len(refined["historical_evidence"]) == 2
    assert refined["conflict_reasoning"]
    assert {h["source_incident_id"] for h in refined["historical_evidence"]} == {first, second}
    assert contexts[-1]["current_incident"]["alerts"]


def test_novabank_never_enables_real_actions(client, auth, monkeypatch):
    adapters(monkeypatch)
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "dry_run", False)
    result = client.post("/api/v1/demo/novabank", headers=auth)
    assert result.status_code == 403
