from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
IncidentStatus = Literal[
    "NEW",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINMENT_PENDING",
    "CONTAINED",
    "RECOVERING",
    "RESOLVED",
    "CLOSED",
]
ActionType = Literal[
    "COLLECT_EVIDENCE",
    "QUARANTINE_FILE",
    "TERMINATE_PROCESS",
    "BLOCK_IOC",
    "BLOCK_SOURCE",
    "RATE_LIMIT_SOURCE",
    "ISOLATE_ENDPOINT",
]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token scheme, not a credential
    expires_in: int
    user: dict[str, Any]


class UserView(ORMModel):
    id: str
    email: str
    role: str
    is_active: bool


class EventCreate(BaseModel):
    event_id: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    source: str = Field(min_length=1, max_length=100)
    source_type: str = Field(min_length=1, max_length=50)
    host: str | None = Field(default=None, max_length=255)
    user: str | None = Field(default=None, max_length=255)
    process: str | None = Field(default=None, max_length=512)
    parent_process: str | None = Field(default=None, max_length=512)
    command_line: str | None = Field(default=None, max_length=8192)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    src_port: int | None = Field(default=None, ge=1, le=65535)
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    domain: str | None = Field(default=None, max_length=512)
    url: str | None = Field(default=None, max_length=4096)
    hash: str | None = Field(default=None, max_length=128)
    file: str | None = Field(default=None, max_length=4096)
    event_type: str = Field(min_length=1, max_length=100)
    severity: Severity = "INFO"
    raw_reference: str | None = Field(default=None, max_length=4096)
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] | None = None

    @field_validator("event_id", "source", "source_type", "event_type")
    @classmethod
    def strip_required(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value


class EventView(ORMModel):
    id: str
    event_id: str
    timestamp: datetime
    source: str
    source_type: str
    host: str | None
    username: str | None
    process: str | None
    command_line: str | None
    src_ip: str | None
    dst_ip: str | None
    domain: str | None
    url: str | None
    file_hash: str | None
    event_type: str
    severity: str
    raw_reference: str | None
    event_metadata: dict[str, Any]


class IngestResult(BaseModel):
    duplicate: bool
    event: EventView
    alerts_created: int
    incident_ids: list[str]


class AlertView(ORMModel):
    id: str
    event_id: str
    incident_id: str | None
    rule_id: str
    title: str
    severity: str
    confidence: float
    source: str
    mitre_techniques: list[str]
    evidence_reference: str | None
    created_at: datetime


class IOCView(ORMModel):
    id: str
    ioc_type: str
    value: str
    confidence: float
    verdict: str
    source: str
    enrichment: list[dict[str, Any]]


class EvidenceView(ORMModel):
    id: str
    evidence_type: str
    source: str
    status: str
    reference: str | None
    sha256: str | None
    summary: str
    details: dict[str, Any]
    collected_at: datetime


class TimelineView(ORMModel):
    id: str
    timestamp: datetime
    event_type: str
    source: str
    summary: str
    reference_id: str | None
    details: dict[str, Any]


class ResponseActionView(ORMModel):
    id: str
    incident_id: str
    action_type: str
    target: str
    requested_by: str
    approved_by: str | None
    idempotency_key: str
    approval_required: bool
    approval_status: str
    dry_run: bool
    execution_status: str
    execution_result: dict[str, Any] | None
    requested_at: datetime
    executed_at: datetime | None


class IncidentView(ORMModel):
    id: str
    title: str
    description: str
    severity: str
    risk_score: float
    risk_level: str
    risk_reasons: list[str]
    status: str
    owner_id: str | None
    created_at: datetime
    updated_at: datetime
    alerts: list[AlertView] = []
    iocs: list[IOCView] = []
    evidence: list[EvidenceView] = []
    timeline: list[TimelineView] = []
    response_actions: list[ResponseActionView] = []


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    owner_id: str | None = None


class ResponseRequest(BaseModel):
    incident_id: str
    action_type: ActionType
    target: str = Field(min_length=1, max_length=512)
    idempotency_key: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    policy_id: str | None = None


class ApprovalRequest(BaseModel):
    decision: Literal["APPROVED", "DENIED"]
    reason: str = Field(min_length=3, max_length=500)


class EvidenceCollectRequest(BaseModel):
    evidence_type: Literal["ENDPOINT_TRIAGE", "YARA_SCAN", "NETWORK_CONTEXT"]
    target: str = Field(min_length=1, max_length=512)


class CTIEnrichmentRequest(BaseModel):
    ioc_id: str
    providers: list[Literal["ThreatFox", "URLhaus", "AbuseIPDB", "MalwareBazaar", "VirusTotal"]] = Field(
        default_factory=list, max_length=5
    )


class CTIResultView(BaseModel):
    provider: str
    indicator: str
    indicator_type: str
    status: str
    verdict: str
    confidence: float
    summary: str
    reference: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    mock: bool = False
    queried_at: str
    cached: bool = False


class ConnectorUpdate(BaseModel):
    enabled: bool


class ConnectorView(BaseModel):
    name: str
    connector_type: str
    status: str
    mode: str
    configured: bool
    enabled: bool = True
    last_checked_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    capabilities: list[str]
    notes: str


class AuditView(ORMModel):
    id: str
    actor_id: str | None
    action: str
    target_type: str
    target_id: str | None
    result: str
    source_ip: str | None
    correlation_id: str | None
    details: dict[str, Any]
    timestamp: datetime
