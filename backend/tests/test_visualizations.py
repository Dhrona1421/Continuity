from __future__ import annotations

from fastapi.testclient import TestClient


def _web_demo(client: TestClient, auth: dict[str, str]) -> dict[str, object]:
    response = client.post("/api/v1/demo/web-run", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def test_backend_derived_trends_and_dashboard_metrics(client: TestClient, auth: dict[str, str]):
    demo = _web_demo(client, auth)
    trends = client.get("/api/v1/visualizations/trends?range=24h", headers=auth)
    assert trends.status_code == 200
    body = trends.json()
    assert body["range"] == "24h"
    assert sum(item["events"] for item in body["series"]) >= demo["requests"]
    assert sum(item["attacks"] for item in body["series"]) >= demo["attack_detections"]
    assert body["severity_distribution"]["CRITICAL"] >= 1
    assert body["attack_type_distribution"]
    assert body["confidence_distribution"]["HIGH"] >= 1
    assert body["response_distribution"]["DRY_RUN"] >= 1

    dashboard = client.get("/api/v1/dashboard", headers=auth).json()
    assert dashboard["metrics"]["critical_incidents"] >= 1
    assert dashboard["metrics"]["detected_attacks"] >= demo["attack_detections"]
    assert dashboard["metrics"]["contained_confirmed"] == 0
    assert dashboard["metrics"]["requests_per_sec"] >= 0
    assert dashboard["metrics"]["active_investigations"] >= 0


def test_network_topology_is_aggregated_from_requests(client: TestClient, auth: dict[str, str]):
    _web_demo(client, auth)
    response = client.get("/api/v1/visualizations/network?range=24h", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["nodes"] >= 2
    assert body["summary"]["connections"] >= 1
    assert body["summary"]["suspicious_connections"] >= 1
    source = next(item for item in body["nodes"] if item["label"] == "198.51.100.23")
    target = next(item for item in body["nodes"] if item["label"] == "demo-web.local")
    assert source["type"] == "external_source"
    assert source["status"] == "SUSPICIOUS"
    assert target["status"] == "UNDER_ATTACK"
    edge = next(item for item in body["edges"] if item["source"] == source["id"] and item["target"] == target["id"])
    assert edge["event_count"] == 11
    assert edge["protocol"] == "HTTPS"
    assert edge["attack_types"]


def test_attack_and_incident_relationship_graphs(client: TestClient, auth: dict[str, str]):
    demo = _web_demo(client, auth)
    attack_graph = client.get("/api/v1/visualizations/attack-graph?range=24h", headers=auth)
    assert attack_graph.status_code == 200
    graph = attack_graph.json()
    assert graph["summary"]["attacks"] >= demo["attack_detections"]
    assert {item["type"] for item in graph["nodes"]} >= {"source", "attack", "endpoint", "target", "incident"}
    assert {item["relationship"] for item in graph["edges"]} >= {"generated", "targeted", "correlated_to"}

    incident_id = demo["incident_ids"][0]
    incident_graph = client.get(f"/api/v1/visualizations/incidents/{incident_id}", headers=auth)
    assert incident_graph.status_code == 200
    body = incident_graph.json()
    assert body["incident_id"] == incident_id
    types = {item["type"] for item in body["nodes"]}
    assert {"incident", "source", "alert", "mitre", "event_group", "evidence", "response"}.issubset(types)
    assert body["summary"]["events"] == 11
    missing = client.get("/api/v1/visualizations/incidents/missing", headers=auth)
    assert missing.status_code == 404


def test_global_search_links_to_real_workspaces(client: TestClient, auth: dict[str, str]):
    demo = _web_demo(client, auth)
    sql = client.get("/api/v1/search/global?q=SQL%20Injection", headers=auth)
    assert sql.status_code == 200
    assert any(item["type"] == "ATTACK" and item["page"] == "Attacks" for item in sql.json()["results"])

    source = client.get("/api/v1/search/global?q=198.51.100.23", headers=auth).json()
    assert {item["type"] for item in source["results"]} >= {"ATTACK", "IOC", "EVENT"}

    incident = client.get(f"/api/v1/search/global?q={demo['incident_ids'][0][:8]}", headers=auth).json()
    assert any(item["type"] == "INCIDENT" and item["page"] == "Incidents" for item in incident["results"])

    invalid = client.get("/api/v1/search/global?q=x", headers=auth)
    assert invalid.status_code == 422
