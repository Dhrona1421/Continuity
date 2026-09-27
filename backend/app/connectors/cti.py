from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import Settings, get_settings


@dataclass
class CTIResult:
    provider: str
    indicator: str
    indicator_type: str
    status: str
    verdict: str = "UNKNOWN"
    confidence: float = 0.0
    summary: str = "No provider result"
    reference: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    mock: bool = False
    queried_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    cached: bool = False

    def view(self) -> dict[str, Any]:
        return asdict(self)


class CTIProvider:
    name = "provider"
    supported_types: set[str] = set()
    requires_key: str | None = None

    def __init__(self, settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings or get_settings()
        self.transport = transport

    def configured(self) -> bool:
        return not self.requires_key or bool(getattr(self.settings, self.requires_key))

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_error: Exception | None = None
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(7.0), transport=self.transport, follow_redirects=False
        ) as client:
            for attempt in range(2):
                try:
                    response = await client.request(method, url, **kwargs)
                    if response.status_code == 429:
                        return response
                    if response.status_code >= 500 and attempt == 0:
                        await asyncio.sleep(0.05)
                        continue
                    return response
                except (httpx.TimeoutException, httpx.NetworkError) as exc:
                    last_error = exc
                    if attempt == 0:
                        await asyncio.sleep(0.05)
        assert last_error is not None
        raise last_error

    async def enrich(self, indicator: str, indicator_type: str) -> CTIResult:
        raise NotImplementedError

    def unavailable(self, indicator: str, indicator_type: str, error: str) -> CTIResult:
        return CTIResult(
            provider=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            status="UNAVAILABLE",
            summary="Provider request did not complete",
            error=error[:500],
        )

    def unsupported(self, indicator: str, indicator_type: str) -> CTIResult:
        return CTIResult(
            provider=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            status="UNSUPPORTED",
            summary=f"{self.name} does not support {indicator_type} in this adapter",
        )


class ThreatFoxProvider(CTIProvider):
    name = "ThreatFox"
    supported_types = {"IP", "DOMAIN", "URL", "HASH"}
    requires_key = "abuse_ch_auth_key"

    async def enrich(self, indicator: str, indicator_type: str) -> CTIResult:
        if indicator_type not in self.supported_types:
            return self.unsupported(indicator, indicator_type)
        if not self.configured():
            result = self.unavailable(indicator, indicator_type, "abuse.ch Auth-Key not configured")
            result.status = "NOT_CONFIGURED"
            return result
        query = (
            {"query": "search_hash", "hash": indicator}
            if indicator_type == "HASH"
            else {"query": "search_ioc", "search_term": indicator, "exact_match": True}
        )
        try:
            response = await self._request(
                "POST",
                "https://threatfox-api.abuse.ch/api/v1/",
                headers={"Auth-Key": self.settings.abuse_ch_auth_key or ""},
                json=query,
            )
            if response.status_code in {401, 403}:
                result = self.unavailable(indicator, indicator_type, "invalid credentials")
                result.status = "AUTHENTICATION_ERROR"
                return result
            if response.status_code == 429:
                return self.unavailable(indicator, indicator_type, "rate limited")
            response.raise_for_status()
            body = response.json()
            rows = body.get("data") if isinstance(body, dict) else None
            found = isinstance(rows, list) and len(rows) > 0
            return CTIResult(
                provider=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                status="SUCCESS",
                verdict="MALICIOUS" if found else "UNKNOWN",
                confidence=0.9 if found else 0,
                summary=f"ThreatFox returned {len(rows) if found else 0} matching record(s)",
                reference="https://threatfox.abuse.ch/",
                attributes={"matches": rows[:5] if found else []},
            )
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            return self.unavailable(indicator, indicator_type, str(exc))


class URLhausProvider(CTIProvider):
    name = "URLhaus"
    supported_types = {"URL"}
    requires_key = "abuse_ch_auth_key"

    async def enrich(self, indicator: str, indicator_type: str) -> CTIResult:
        if indicator_type not in self.supported_types:
            return self.unsupported(indicator, indicator_type)
        if not self.configured():
            result = self.unavailable(indicator, indicator_type, "abuse.ch Auth-Key not configured")
            result.status = "NOT_CONFIGURED"
            return result
        try:
            response = await self._request(
                "POST",
                "https://urlhaus-api.abuse.ch/v1/url/",
                headers={"Auth-Key": self.settings.abuse_ch_auth_key or ""},
                data={"url": indicator},
            )
            if response.status_code in {401, 403}:
                result = self.unavailable(indicator, indicator_type, "invalid credentials")
                result.status = "AUTHENTICATION_ERROR"
                return result
            if response.status_code == 429:
                return self.unavailable(indicator, indicator_type, "rate limited")
            response.raise_for_status()
            body = response.json()
            found = body.get("query_status") == "ok"
            return CTIResult(
                provider=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                status="SUCCESS",
                verdict="MALICIOUS" if found else "UNKNOWN",
                confidence=0.9 if found else 0,
                summary=f"URLhaus query status: {body.get('query_status', 'unknown')}",
                reference=body.get("urlhaus_reference"),
                attributes={"url_status": body.get("url_status"), "threat": body.get("threat")},
            )
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            return self.unavailable(indicator, indicator_type, str(exc))


class AbuseIPDBProvider(CTIProvider):
    name = "AbuseIPDB"
    supported_types = {"IP"}
    requires_key = "abuseipdb_api_key"

    async def enrich(self, indicator: str, indicator_type: str) -> CTIResult:
        if indicator_type not in self.supported_types:
            return self.unsupported(indicator, indicator_type)
        if not self.configured():
            result = self.unavailable(indicator, indicator_type, "API key not configured")
            result.status = "NOT_CONFIGURED"
            return result
        try:
            response = await self._request(
                "GET",
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.settings.abuseipdb_api_key or "", "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90},
            )
            if response.status_code in {401, 403}:
                result = self.unavailable(indicator, indicator_type, "invalid credentials")
                result.status = "AUTHENTICATION_ERROR"
                return result
            if response.status_code == 429:
                return self.unavailable(indicator, indicator_type, "rate limited")
            response.raise_for_status()
            data = response.json()["data"]
            score = int(data.get("abuseConfidenceScore", 0))
            return CTIResult(
                provider=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                status="SUCCESS",
                verdict="MALICIOUS" if score >= 75 else "SUSPICIOUS" if score >= 25 else "CLEAN",
                confidence=score / 100,
                summary=f"Abuse confidence score: {score}/100",
                reference=f"https://www.abuseipdb.com/check/{quote(indicator, safe='')}",
                attributes={"countryCode": data.get("countryCode"), "usageType": data.get("usageType")},
            )
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            return self.unavailable(indicator, indicator_type, str(exc))


class MalwareBazaarProvider(CTIProvider):
    name = "MalwareBazaar"
    supported_types = {"HASH"}
    requires_key = "abuse_ch_auth_key"

    async def enrich(self, indicator: str, indicator_type: str) -> CTIResult:
        if indicator_type not in self.supported_types:
            return self.unsupported(indicator, indicator_type)
        if not self.configured():
            result = self.unavailable(indicator, indicator_type, "abuse.ch Auth-Key not configured")
            result.status = "NOT_CONFIGURED"
            return result
        try:
            response = await self._request(
                "POST",
                "https://mb-api.abuse.ch/api/v1/",
                headers={"Auth-Key": self.settings.abuse_ch_auth_key or ""},
                data={"query": "get_info", "hash": indicator},
            )
            if response.status_code in {401, 403}:
                result = self.unavailable(indicator, indicator_type, "invalid credentials")
                result.status = "AUTHENTICATION_ERROR"
                return result
            if response.status_code == 429:
                return self.unavailable(indicator, indicator_type, "rate limited")
            response.raise_for_status()
            body = response.json()
            rows = body.get("data")
            found = body.get("query_status") == "ok" and isinstance(rows, list) and rows
            return CTIResult(
                provider=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                status="SUCCESS",
                verdict="MALICIOUS" if found else "UNKNOWN",
                confidence=0.95 if found else 0,
                summary=f"MalwareBazaar query status: {body.get('query_status', 'unknown')}",
                reference="https://bazaar.abuse.ch/",
                attributes={"matches": rows[:3] if found else []},
            )
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            return self.unavailable(indicator, indicator_type, str(exc))


class VirusTotalProvider(CTIProvider):
    name = "VirusTotal"
    supported_types = {"IP", "DOMAIN", "URL", "HASH"}
    requires_key = "virustotal_api_key"

    async def enrich(self, indicator: str, indicator_type: str) -> CTIResult:
        if indicator_type not in self.supported_types:
            return self.unsupported(indicator, indicator_type)
        if not self.configured():
            result = self.unavailable(indicator, indicator_type, "API key not configured")
            result.status = "NOT_CONFIGURED"
            return result
        kind = {"IP": "ip_addresses", "DOMAIN": "domains", "URL": "urls", "HASH": "files"}[indicator_type]
        identifier = (
            base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            if indicator_type == "URL"
            else quote(indicator, safe="")
        )
        try:
            response = await self._request(
                "GET",
                f"https://www.virustotal.com/api/v3/{kind}/{identifier}",
                headers={"x-apikey": self.settings.virustotal_api_key or ""},
            )
            if response.status_code in {401, 403}:
                result = self.unavailable(indicator, indicator_type, "invalid credentials")
                result.status = "AUTHENTICATION_ERROR"
                return result
            if response.status_code == 429:
                return self.unavailable(indicator, indicator_type, "rate limited")
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            total = sum(int(value) for value in stats.values()) or 1
            return CTIResult(
                provider=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                status="SUCCESS",
                verdict="MALICIOUS" if malicious > 0 else "CLEAN",
                confidence=malicious / total,
                summary=f"{malicious}/{total} engines marked this indicator malicious",
                reference=f"https://www.virustotal.com/gui/search/{quote(indicator, safe='')}",
                attributes={"analysis_stats": stats},
            )
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            return self.unavailable(indicator, indicator_type, str(exc))


PROVIDERS = {
    provider.name: provider
    for provider in (ThreatFoxProvider, URLhausProvider, AbuseIPDBProvider, MalwareBazaarProvider, VirusTotalProvider)
}


async def enrich_indicator(
    indicator: str,
    indicator_type: str,
    provider_names: list[str] | None = None,
    *,
    settings: Settings | None = None,
) -> list[CTIResult]:
    names = provider_names or [
        name for name, provider in PROVIDERS.items() if indicator_type in provider.supported_types
    ]
    providers = [PROVIDERS[name](settings=settings) for name in names]
    return await asyncio.gather(*(provider.enrich(indicator, indicator_type) for provider in providers))
