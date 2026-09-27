from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WebRequestCreate(BaseModel):
    request_id: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    source_ip: str = Field(max_length=64)
    target_host: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._:-]+$")
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    path: str = Field(min_length=1, max_length=4096)
    query_string: str | None = Field(default=None, max_length=8192)
    status_code: int = Field(ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0, le=1_000_000_000)
    latency_ms: float | None = Field(default=None, ge=0, le=3_600_000)
    user_agent: str | None = Field(default=None, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str | None = Field(default=None, max_length=4096)
    session_id: str | None = Field(default=None, max_length=512)
    username: str | None = Field(default=None, max_length=255)
    upstream_signals: list[str] = Field(default_factory=list, max_length=35)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_ip")
    @classmethod
    def valid_source_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from exc

    @field_validator("path")
    @classmethod
    def valid_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must start with /")
        return value

    @field_validator("upstream_signals")
    @classmethod
    def unique_signals(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(item.strip() for item in value if item.strip()))


class WebRequestView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    request_id: str
    timestamp: datetime
    source_ip: str
    target_host: str
    method: str
    path: str
    query_string: str | None
    status_code: int
    response_bytes: int | None
    latency_ms: float | None
    user_agent: str | None
    safe_headers: dict[str, str]
    session_hash: str | None
    username: str | None
    upstream_signals: list[str]
    request_metadata: dict[str, Any]
    security_event_id: str | None


class AttackView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    attack_type: str
    family: str
    severity: str
    confidence: float
    classification: str
    status: str
    source_ip: str
    target_host: str
    endpoint: str
    request_count: int
    first_seen: datetime
    last_seen: datetime
    rule_id: str
    alert_id: str | None
    incident_id: str | None
    primary_event_id: str
    related_event_ids: list[str]
    evidence: list[dict[str, Any]]
    mitre_techniques: list[str]
    response_status: str


class AttackUpdate(BaseModel):
    classification: Literal["SUSPICIOUS", "LIKELY_ATTACK", "CONFIRMED_ATTACK", "FALSE_POSITIVE"] | None = None
    status: Literal["DETECTED", "ANALYZING", "INVESTIGATING", "FALSE_POSITIVE", "RESOLVED"] | None = None


class WebIngestResult(BaseModel):
    duplicate: bool
    request: WebRequestView
    attacks: list[AttackView]
    incident_ids: list[str]
