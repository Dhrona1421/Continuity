from __future__ import annotations

from pathlib import Path

import yaml


def test_compose_core_contract_and_optional_demo_profile():
    compose_path = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose["services"]
    assert {
        "postgres",
        "opensearch",
        "backend",
        "frontend",
        "demo-runner",
        "web-demo-runner",
    }.issubset(services)
    for name in ("postgres", "opensearch", "backend", "frontend"):
        assert "healthcheck" in services[name]
        assert "no-new-privileges:true" in services[name]["security_opt"]
    assert services["frontend"]["ports"] == ["127.0.0.1:8080:8080"]
    assert "ports" not in services["postgres"]
    assert "ports" not in services["opensearch"]
    assert set(services["demo-runner"]["profiles"]) == {"demo", "full"}
    assert set(services["web-demo-runner"]["profiles"]) == {"demo", "full"}
    assert services["web-demo-runner"]["command"][-1] == "web-run"
    backend_environment = services["backend"]["environment"]
    assert backend_environment["GHOSTSOC_DRY_RUN"] == "${GHOSTSOC_DRY_RUN:-true}"
    assert backend_environment["GHOSTSOC_DEMO_MODE"] == "${GHOSTSOC_DEMO_MODE:-true}"
    assert backend_environment["GHOSTSOC_DEMO_AUTO_ACCESS"] == "${GHOSTSOC_DEMO_AUTO_ACCESS:-false}"
    assert (
        backend_environment["GHOSTSOC_WEB_ALLOWED_HOSTS"]
        == "${GHOSTSOC_WEB_ALLOWED_HOSTS:-demo-web.local,authorized-web.test}"
    )
    assert backend_environment["GHOSTSOC_ABUSE_CH_AUTH_KEY"] == "${GHOSTSOC_ABUSE_CH_AUTH_KEY:-}"
