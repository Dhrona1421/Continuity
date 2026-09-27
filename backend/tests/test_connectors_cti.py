from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from app.connectors.base import validate_connector_url
from app.connectors.cti import AbuseIPDBProvider, CTIResult, ThreatFoxProvider, URLhausProvider, VirusTotalProvider
from app.core.config import Settings


@pytest.mark.anyio
async def test_threatfox_success_normalization():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://threatfox-api.abuse.ch/api/v1/"
        assert request.headers["Auth-Key"] == "test-auth-key"
        assert b'"exact_match":true' in request.content
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [{"ioc": "198.51.100.42", "threat_type": "botnet_cc"}],
            },
        )

    settings = Settings(_env_file=None, abuse_ch_auth_key="test-auth-key")
    provider = ThreatFoxProvider(settings=settings, transport=httpx.MockTransport(handler))
    result = await provider.enrich("198.51.100.42", "IP")
    assert result.status == "SUCCESS"
    assert result.verdict == "MALICIOUS"
    assert result.mock is False
    assert result.attributes["matches"][0]["threat_type"] == "botnet_cc"


@pytest.mark.anyio
async def test_cti_timeout_rate_limit_malformed_and_missing_key():
    async def timeout_handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("test timeout")

    abuse_settings = Settings(_env_file=None, abuse_ch_auth_key="test-auth-key")
    timeout = URLhausProvider(settings=abuse_settings, transport=httpx.MockTransport(timeout_handler))
    timeout_result = await timeout.enrich("https://example.invalid/a", "URL")
    assert timeout_result.status == "UNAVAILABLE"
    assert "timeout" in (timeout_result.error or "")

    rate = ThreatFoxProvider(settings=abuse_settings, transport=httpx.MockTransport(lambda _: httpx.Response(429)))
    rate_result = await rate.enrich("example.invalid", "DOMAIN")
    assert rate_result.status == "UNAVAILABLE"
    assert rate_result.error == "rate limited"

    malformed = ThreatFoxProvider(
        settings=abuse_settings,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"not-json")),
    )
    malformed_result = await malformed.enrich("example.invalid", "DOMAIN")
    assert malformed_result.status == "UNAVAILABLE"

    settings = Settings(_env_file=None, abuseipdb_api_key=None, abuse_ch_auth_key=None)
    missing = await AbuseIPDBProvider(settings=settings).enrich("198.51.100.1", "IP")
    assert missing.status == "NOT_CONFIGURED"
    missing_abuse = await ThreatFoxProvider(settings=settings).enrich("198.51.100.1", "IP")
    assert missing_abuse.status == "NOT_CONFIGURED"


@pytest.mark.anyio
async def test_virustotal_url_uses_documented_base64_identifier():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvcGF0aD94PTE"
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 4}}}},
        )

    settings = Settings(_env_file=None, virustotal_api_key="test-vt-key")
    provider = VirusTotalProvider(settings=settings, transport=httpx.MockTransport(handler))
    result = await provider.enrich("https://example.invalid/path?x=1", "URL")
    assert result.status == "SUCCESS"
    assert result.verdict == "CLEAN"


@pytest.mark.anyio
async def test_cti_invalid_credentials():
    settings = Settings(_env_file=None, abuseipdb_api_key="invalid-test-key")
    provider = AbuseIPDBProvider(
        settings=settings,
        transport=httpx.MockTransport(lambda _: httpx.Response(401, json={"errors": []})),
    )
    result = await provider.enrich("198.51.100.1", "IP")
    assert result.status == "AUTHENTICATION_ERROR"


def test_connector_url_ssrf_control(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="private connector"):
        validate_connector_url("https://internal.example", allow_private=False)
    assert validate_connector_url("http://localhost:9200", allow_private=True) == "http://localhost:9200"
    with pytest.raises(ValueError, match="embedded"):
        validate_connector_url("https://user:password@example.com")


def test_ioc_enrichment_uses_persistent_one_hour_cache(
    client: TestClient,
    auth: dict[str, str],
    demo_event: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
):
    event = client.post("/api/v1/events", headers=auth, json=demo_event).json()
    incident = client.get(f"/api/v1/incidents/{event['incident_ids'][0]}", headers=auth).json()
    ioc_id = next(item["id"] for item in incident["iocs"] if item["ioc_type"] == "DOMAIN")
    calls = 0

    async def fake_enrich(indicator, indicator_type, providers):
        nonlocal calls
        calls += 1
        assert providers == ["ThreatFox"]
        return [
            CTIResult(
                provider="ThreatFox",
                indicator=indicator,
                indicator_type=indicator_type,
                status="SUCCESS",
                verdict="MALICIOUS",
                confidence=0.9,
                summary="deterministic provider transport",
            )
        ]

    monkeypatch.setattr("app.api.routes.enrich_indicator", fake_enrich)
    payload = {"ioc_id": ioc_id, "providers": ["ThreatFox"]}
    first = client.post("/api/v1/threat-intelligence/enrich", headers=auth, json=payload)
    second = client.post("/api/v1/threat-intelligence/enrich", headers=auth, json=payload)
    assert first.status_code == second.status_code == 200
    assert first.json()[0]["status"] == "SUCCESS"
    assert second.json()[0]["status"] == "CACHED"
    assert second.json()[0]["cached"] is True
    assert calls == 1


def test_connector_inventory_is_truthful(client: TestClient, auth: dict[str, str]):
    response = client.get("/api/v1/connectors", headers=auth)
    assert response.status_code == 200
    rows = {item["name"]: item for item in response.json()}
    assert len(rows) == 20
    assert rows["Sigma"]["status"] == "HEALTHY"
    assert rows["Velociraptor"]["status"] == "NOT_CONFIGURED"
    assert rows["YARA"]["status"] in {"HEALTHY", "UNAVAILABLE"}
    assert rows["ThreatFox"]["mode"] == "REAL"
    assert rows["ThreatFox"]["status"] == "API_KEY_REQUIRED"
    assert rows["ThreatFox"]["enabled"] is True

    disabled = client.patch("/api/v1/connectors/ThreatFox", headers=auth, json={"enabled": False})
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "DISABLED"
    assert disabled.json()["enabled"] is False
    checked = client.post("/api/v1/connectors/ThreatFox/check", headers=auth)
    assert checked.status_code == 200
    assert checked.json()["status"] == "DISABLED"
    enabled = client.patch("/api/v1/connectors/ThreatFox", headers=auth, json={"enabled": True})
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True
