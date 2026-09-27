from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.services.realtime import EventBroker
from app.services.web_detection import redact, safe_headers
from app.web_catalog import WEB_ATTACK_CATALOG


def web_payload(
    request_id: str,
    *,
    source_ip: str = "203.0.113.10",
    target_host: str = "authorized-web.test",
    method: str = "GET",
    path: str = "/",
    query: str | None = None,
    status: int = 200,
    username: str | None = None,
    signals: list[str] | None = None,
    timestamp: datetime | None = None,
) -> dict[str, object]:
    return {
        "request_id": request_id,
        "timestamp": (timestamp or datetime.now(UTC)).isoformat(),
        "source_ip": source_ip,
        "target_host": target_host,
        "method": method,
        "path": path,
        "query_string": query,
        "status_code": status,
        "response_bytes": 512,
        "latency_ms": 12.5,
        "user_agent": "GhostSOC-Pytest/1.0",
        "headers": {"host": target_host, "authorization": "must-not-persist"},
        "username": username,
        "upstream_signals": signals or [],
        "metadata": {"authorized_test": True},
    }


def test_catalog_contains_all_35_unique_categories(client: TestClient, auth: dict[str, str]):
    assert len(WEB_ATTACK_CATALOG) == 35
    assert len({item.slug for item in WEB_ATTACK_CATALOG}) == 35
    response = client.get("/api/v1/web/attack-catalog", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 35
    assert sum(body["families"].values()) == 35
    assert {item["number"] for item in body["definitions"]} == set(range(1, 36))
    assert "Context-dependent" in body["truth_note"]


def test_signature_detection_correlation_and_duplicate_request(client: TestClient, auth: dict[str, str]):
    malformed = client.post(
        "/api/v1/web/requests",
        headers=auth,
        json=web_payload("invalid-source", source_ip="not-an-ip"),
    )
    assert malformed.status_code == 422

    unauthorized = client.post(
        "/api/v1/web/requests",
        headers=auth,
        json=web_payload("unauthorized-target", target_host="not-authorized.test"),
    )
    assert unauthorized.status_code == 403

    sql = client.post(
        "/api/v1/web/requests",
        headers=auth,
        json=web_payload("web-sqli-1", path="/api/login", query="id=1%27 OR %271%27=%271--"),
    )
    assert sql.status_code == 201, sql.text
    assert sql.json()["attacks"][0]["attack_type"] == "SQL Injection"
    assert sql.json()["attacks"][0]["classification"] == "SUSPICIOUS"
    incident_id = sql.json()["incident_ids"][0]

    xss = client.post(
        "/api/v1/web/requests",
        headers=auth,
        json=web_payload("web-xss-1", path="/search", query="q=<script>alert(1)</script>"),
    )
    assert xss.status_code == 201
    assert xss.json()["attacks"][0]["attack_type"] == "Cross-Site Scripting (XSS)"
    assert xss.json()["incident_ids"] == [incident_id]

    duplicate = client.post(
        "/api/v1/web/requests",
        headers=auth,
        json=web_payload("web-sqli-1", path="/api/login", query="id=1%27 OR %271%27=%271--"),
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["duplicate"] is True
    assert duplicate.json()["attacks"] == []

    detail_id = sql.json()["attacks"][0]["id"]
    detail = client.get(f"/api/v1/web/attacks/{detail_id}", headers=auth)
    assert detail.status_code == 200
    assert detail.json()["incident"]["id"] == incident_id
    assert detail.json()["incident"]["alerts"][0]["rule_id"] == "GS-WEB-001"
    assert detail.json()["requests"][0]["safe_headers"] == {"host": "authorized-web.test"}
    triage = client.patch(
        f"/api/v1/web/attacks/{detail_id}",
        headers=auth,
        json={"status": "INVESTIGATING"},
    )
    assert triage.status_code == 200
    assert triage.json()["status"] == "INVESTIGATING"


def test_every_category_accepts_explicit_authorized_upstream_signal(client: TestClient, auth: dict[str, str]):
    now = datetime.now(UTC)
    # Keep all generated events within one four-hour incident correlation bucket.
    now = now.replace(hour=(now.hour // 4) * 4, minute=1, second=0, microsecond=0)
    observed: set[str] = set()
    incidents: set[str] = set()
    for index, definition in enumerate(WEB_ATTACK_CATALOG):
        payload = web_payload(
            f"signal-{index}",
            signals=[definition.slug],
            timestamp=now + timedelta(milliseconds=index),
        )
        result = client.post("/api/v1/web/requests", headers=auth, json=payload)
        assert result.status_code == 201, f"{definition.slug}: {result.text}"
        matching = [item for item in result.json()["attacks"] if item["attack_type"] == definition.name]
        assert matching, definition.slug
        assert matching[0]["classification"] == "CONFIRMED_ATTACK"
        observed.add(matching[0]["attack_type"])
        incidents.update(result.json()["incident_ids"])
    assert observed == {item.name for item in WEB_ATTACK_CATALOG}
    assert len(incidents) == 1


def test_behavioral_brute_force_and_password_spray_escalate(client: TestClient, auth: dict[str, str]):
    now = datetime.now(UTC)
    # Seven requests must not straddle the 15-minute attack aggregation boundary.
    now = now.replace(minute=(now.minute // 15) * 15 + 1, second=0, microsecond=0)
    latest = None
    for index in range(7):
        result = client.post(
            "/api/v1/web/requests",
            headers=auth,
            json=web_payload(
                f"auth-failure-{index}",
                method="POST",
                path="/login",
                status=401,
                username=f"user-{index}",
                timestamp=now + timedelta(seconds=index),
            ),
        )
        assert result.status_code == 201
        latest = result.json()
    attack_types = {item["attack_type"]: item for item in latest["attacks"]}
    assert "Brute-Force Attack" in attack_types
    brute = next(
        item
        for item in client.get("/api/v1/web/attacks", headers=auth).json()
        if item["attack_type"] == "Brute-Force Attack"
    )
    spray = next(
        item
        for item in client.get("/api/v1/web/attacks", headers=auth).json()
        if item["attack_type"] == "Password Spraying"
    )
    assert brute["request_count"] == 3
    assert brute["classification"] == "LIKELY_ATTACK"
    assert brute["confidence"] >= 0.78
    assert spray["classification"] == "LIKELY_ATTACK"


def test_web_summary_is_derived_from_persisted_state(client: TestClient, auth: dict[str, str]):
    client.post(
        "/api/v1/web/requests",
        headers=auth,
        json=web_payload("summary-sqli", query="id=1 UNION SELECT password FROM users"),
    )
    summary = client.get("/api/v1/web/summary", headers=auth)
    assert summary.status_code == 200
    body = summary.json()
    assert body["metrics"]["requests"] == 1
    assert body["metrics"]["attacks"] >= 1
    assert body["metrics"]["blocked_confirmed"] == 0
    assert body["metrics"]["block_rate"] == 0
    assert body["top_sources"][0]["value"] == "203.0.113.10"
    assert body["system_health"]["database"] == "HEALTHY"
    assert body["system_health"]["stream"] == "HEALTHY"
    assert body["system_health"]["opensearch"] == "NOT_CONFIGURED"


def test_sensitive_web_values_are_redacted_or_excluded():
    assert redact("username=a&password=secret123&token=abcdef") == ("username=a&password=[REDACTED]&token=[REDACTED]")
    assert safe_headers({"Host": "example.test", "Authorization": "Bearer secret", "Cookie": "session=secret"}) == {
        "host": "example.test"
    }


def test_realtime_broker_publishes_and_bounds_history():
    async def scenario():
        broker = EventBroker(history_size=2, queue_size=2)
        subscription = broker.subscribe()
        pending = asyncio.create_task(anext(subscription))
        await asyncio.sleep(0)
        await broker.publish("attack", {"id": "one"})
        received = await asyncio.wait_for(pending, timeout=1)
        await subscription.aclose()
        await broker.publish("attack", {"id": "two"})
        await broker.publish("attack", {"id": "three"})
        return received, broker.recent()

    received, history = asyncio.run(scenario())
    assert received["type"] == "attack"
    assert received["data"]["id"] == "one"
    assert [item["data"]["id"] for item in history] == ["two", "three"]


def test_controlled_web_demo_response_is_truthful_and_resettable(client: TestClient, auth: dict[str, str]):
    run = client.post("/api/v1/demo/web-run", headers=auth)
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["mode"] == "SIMULATED"
    assert body["requests"] == 11
    assert body["attack_detections"] >= 6
    assert body["response_status"] == "DRY_RUN"
    assert body["external_actions_executed"] is False
    assert set(body["reports"]) == {"pdf", "json", "csv", "zip"}
    json_report = client.get(f"/api/v1/reports/{body['reports']['json']['id']}/download", headers=auth)
    assert json_report.status_code == 200
    assert json_report.json()["web_attacks"]
    assert all(item["response_status"] == "DRY_RUN" for item in json_report.json()["web_attacks"])
    replay = client.get("/api/v1/web/replay", headers=auth)
    assert replay.status_code == 200
    assert replay.json()["incident_id"] == body["incident_ids"][0]
    assert any(item["type"] == "RESPONSE_VERIFICATION" for item in replay.json()["events"])

    attacks = client.get("/api/v1/web/attacks", headers=auth).json()
    assert attacks
    assert {item["response_status"] for item in attacks} == {"DRY_RUN"}
    incident = client.get(f"/api/v1/incidents/{body['incident_ids'][0]}", headers=auth).json()
    assert incident["status"] != "CONTAINED"
    assert incident["response_actions"][0]["execution_status"] == "DRY_RUN"
    assert incident["response_actions"][0]["execution_result"]["executed"] is False

    reset = client.post("/api/v1/demo/web-reset", headers=auth)
    assert reset.status_code == 200, reset.text
    assert reset.json()["requests_removed"] == 11
    assert client.get("/api/v1/web/requests", headers=auth).json() == []
    assert client.get("/api/v1/web/attacks", headers=auth).json() == []
