"""Real HTTP transport against local Hindsight/LLM TEST DOUBLES (not live providers)."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread

from app.core.config import get_settings


def test_novabank_through_http_provider_and_outage(client, auth, monkeypatch):
    documents = {}
    calls = []
    lock = Lock()

    class ProviderDouble(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler contract
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            if self.path.endswith("/memories"):
                with lock:
                    for item in body["items"]:
                        documents[item["document_id"]] = item["content"]
                result = {"success": True, "async": False, "items_count": len(body["items"])}
            elif self.path.endswith("/memories/recall"):
                with lock:
                    result = {"results": [{"document_id": key, "text": content[:300],
                                           "type": "experience"} for key, content in documents.items()]}
            elif self.path.endswith("/chat/completions"):
                context = json.loads(body["messages"][1]["content"])
                calls.append(context)
                history = context["historical_evidence"]
                failed = any(item["failed_paths"] or item["side_effects"] for item in history)
                accepted = any(feedback["decision"] == "accepted" for item in history
                               for feedback in item["analyst_feedback"])
                steps = (["Preserve session evidence", "Correlate source IP across accounts"] if accepted else
                         ["Preserve session evidence", "Collect authentication logs"] if failed else
                         ["Review current telemetry", "Investigate source IP"])
                draft = {
                    "steps": steps,
                    "reasoning": ("Prior investigation failure requires preserving evidence."
                                  if failed else "Current telemetry warrants investigation."),
                    "confidence": 0.65,
                    "cited_incident_ids": [item["source_incident_id"] for item in history],
                    "conflict_reasoning": (
                        "Early containment lost evidence but the accepted preservation-first approach retained it."
                        if failed and accepted else None
                    ),
                }
                result = {"choices": [{"message": {"content": json.dumps(draft)}}]}
            else:
                self.send_error(404)
                return
            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), ProviderDouble)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    settings = get_settings()
    monkeypatch.setattr(settings, "hindsight_url", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setattr(settings, "llm_base_url", f"http://127.0.0.1:{server.server_port}/v1")
    monkeypatch.setattr(settings, "llm_api_key", "test-only-placeholder")
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(settings, "dry_run", True)
    try:
        loaded = client.post("/api/v1/demo/novabank", headers=auth)
        assert loaded.status_code == 200, loaded.text
        assert loaded.json()["status"] == "LOADED" and loaded.json()["memory_status"] == "retained"
        first, second, third = loaded.json()["incident_ids"]
        source = client.get(f"/api/v1/incidents/{first}/experience", headers=auth).json()
        assert source["provider_status"] == "retained" and source["experience"]["investigation"]["failed_paths"]
        assert client.post("/api/v1/memory/recall", headers=auth,
                           json={"incident_id": first}).json()["matches"] == []
        history = client.post("/api/v1/memory/recall", headers=auth,
                              json={"incident_id": second}).json()
        assert {item["source_incident_id"] for item in history["matches"]} == {first}
        without = client.post(f"/api/v1/incidents/{second}/recommendation?without_memory=true",
                              headers=auth).json()
        with_memory = client.post(f"/api/v1/incidents/{second}/recommendation", headers=auth).json()
        assert without["status"] == with_memory["status"] == "ready"
        assert without["historical_evidence"] == [] and without["steps"][0] != with_memory["steps"][0]
        assert with_memory["historical_evidence"][0]["source_incident_id"] == first
        learned = client.post("/api/v1/memory/learn", headers=auth, json={
            "incident_id": second, "recommendation_id": with_memory["recommendation_id"],
            "decision": "accepted", "reason": "Preservation-first plan approved by an analyst",
            "outcome": "Synthetic exercise: source IP correlated and evidence preserved",
            "lesson": {"lesson": "Correlate source IP across accounts before containment",
                       "condition": "Spray signals span accounts", "recommended_behavior": "Preserve then correlate"},
        })
        assert learned.status_code == 200 and learned.json()["status"] == "retained"
        saved = client.get(f"/api/v1/incidents/{second}/experience", headers=auth).json()["experience"]
        assert saved["analyst_feedback"][0]["decision"] == "accepted"
        assert saved["lessons"][0]["source_incident"] == second
        later = client.post(f"/api/v1/incidents/{third}/recommendation", headers=auth).json()
        assert later["status"] == "ready" and later["conflict_reasoning"]
        assert {item["source_incident_id"] for item in later["historical_evidence"]} == {first, second}
        assert later["steps"][1] == "Correlate source IP across accounts"
        assert len(documents) == 2 and len(calls) == 3  # upsert; each comparison invokes actual HTTP
        assert client.post("/api/v1/demo/novabank", headers=auth).json()["status"] == "EXISTING"
        client.cookies.clear()  # login also sets a session cookie
        assert client.get(f"/api/v1/incidents/{first}/experience").status_code == 401
    finally:
        server.shutdown()
        worker.join(timeout=3)
        server.server_close()

    unavailable = client.post("/api/v1/memory/recall", headers=auth, json={"incident_id": third}).json()
    assert unavailable == {"status": "unavailable", "matches": []}
    agent = client.post(f"/api/v1/incidents/{third}/recommendation", headers=auth).json()
    assert agent["status"] == "unavailable" and agent["memory_status"] == "unavailable"
    assert client.get(f"/api/v1/incidents/{third}", headers=auth).status_code == 200
