from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from urllib.parse import urlparse

import httpx


class ConnectorStatus(StrEnum):
    DISABLED = "DISABLED"
    API_KEY_REQUIRED = "API_KEY_REQUIRED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    DEGRADED = "DEGRADED"
    HEALTHY = "HEALTHY"


@dataclass
class HealthResult:
    status: ConnectorStatus
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    error: str | None = None
    latency_ms: float | None = None


def validate_connector_url(url: str, allow_private: bool = False) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("connector URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("credentials must not be embedded in connector URLs")
    if not allow_private:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443)}
        except socket.gaierror as exc:
            raise ValueError("connector hostname could not be resolved") from exc
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError("private connector targets are disabled")
    return url.rstrip("/")


class HttpConnector:
    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        allow_private: bool = False,
        verify_tls: bool = True,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = validate_connector_url(base_url, allow_private)
        self.headers = headers or {}
        self.verify_tls = verify_tls
        self.timeout = timeout

    async def request(
        self, method: str, path: str = "", *, json: object = None, data: object = None, params: dict | None = None
    ) -> httpx.Response:
        if method.upper() not in {"GET", "POST", "HEAD"}:
            raise ValueError("connector method is not allowlisted")
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout), verify=self.verify_tls, follow_redirects=False
        ) as client:
            return await client.request(
                method,
                f"{self.base_url}/{path.lstrip('/')}",
                headers=self.headers,
                json=json,
                data=data,
                params=params,
            )
