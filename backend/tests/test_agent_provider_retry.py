import json
from types import SimpleNamespace

import httpx
import pytest

from app.services import agent


def _draft_response():
    draft = {"steps": ["Review current evidence"],
             "reasoning": "Review the current evidence before deciding what to do.",
             "suggested_next_steps": [], "confidence": 0.5,
             "cited_incident_ids": [], "conflict_reasoning": None}
    return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(draft)}}]})


def test_retries_transient_provider_server_error_once(monkeypatch):
    calls = 0

    def handle(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(503, headers={"Retry-After": "0"}) if calls == 1 else _draft_response()

    client_class = httpx.Client
    monkeypatch.setattr(agent.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(agent.httpx, "Client", lambda **kwargs: client_class(
        transport=httpx.MockTransport(handle), **kwargs))
    settings = SimpleNamespace(llm_timeout_seconds=2, llm_base_url="https://llm.test/v1",
                               llm_api_key="test-only-placeholder", llm_model="test-model")

    result = agent._inference_draft(settings, "system", {"current_incident": {}}, history=[])

    assert result.steps == ["Review current evidence"]
    assert calls == 2


def test_does_not_retry_provider_authentication_error(monkeypatch):
    calls = 0

    def handle(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(401)

    client_class = httpx.Client
    monkeypatch.setattr(agent.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(agent.httpx, "Client", lambda **kwargs: client_class(
        transport=httpx.MockTransport(handle), **kwargs))
    settings = SimpleNamespace(llm_timeout_seconds=2, llm_base_url="https://llm.test/v1",
                               llm_api_key="test-only-placeholder", llm_model="test-model")

    with pytest.raises(httpx.HTTPStatusError):
        agent._inference_draft(settings, "system", {"current_incident": {}}, history=[])

    assert calls == 1


def test_repairs_missing_required_conflict_reasoning_once(monkeypatch):
    calls = 0

    def handle(_request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _draft_response()
        draft = {"steps": ["Preserve evidence"],
                 "reasoning": "The mixed history makes preservation the safest first step.",
                 "suggested_next_steps": [], "confidence": 0.7,
                 "cited_incident_ids": ["source-incident"],
                 "conflict_reasoning": (
                     "A successful case supports correlation, while an earlier failure lost evidence; "
                     "preserve first.")}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(draft)}}]})

    client_class = httpx.Client
    monkeypatch.setattr(agent.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(agent.httpx, "Client", lambda **kwargs: client_class(
        transport=httpx.MockTransport(handle), **kwargs))
    settings = SimpleNamespace(llm_timeout_seconds=2, llm_base_url="https://llm.test/v1",
                               llm_api_key="test-only-placeholder", llm_model="test-model")

    history = [{"source_incident_id": "source-incident", "successful_paths": ["Correlate accounts"],
                "successful_actions": [], "failed_paths": ["Premature containment"],
                "failed_actions": [], "side_effects": [], "analyst_feedback": []}]
    result = agent._inference_draft(settings, "system instruction", {
        "requires_conflict_reasoning": True,
        "historical_evidence": [{"source_incident_id": "source-incident"}],
    }, history=history)

    assert calls == 2
    assert result.conflict_reasoning
