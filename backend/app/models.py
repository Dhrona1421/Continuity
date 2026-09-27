from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def new_id() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(20), default="VIEWER", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class ConnectorState(Base):
    __tablename__ = "connector_states"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    connector_type: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="NOT_CONFIGURED")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(100), index=True)
    source_type: Mapped[str] = mapped_column(String(50), index=True)
    host: Mapped[str | None] = mapped_column(String(255), index=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    process: Mapped[str | None] = mapped_column(String(512))
    parent_process: Mapped[str | None] = mapped_column(String(512))
    command_line: Mapped[str | None] = mapped_column(Text)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    domain: Mapped[str | None] = mapped_column(String(512), index=True)
    url: Mapped[str | None] = mapped_column(Text)
    file_hash: Mapped[str | None] = mapped_column(String(128), index=True)
    file_path: Mapped[str | None] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="INFO", index=True)
    raw_reference: Mapped[str | None] = mapped_column(Text)
    event_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    alerts: Mapped[list[Alert]] = relationship(back_populates="event", cascade="all, delete-orphan")


class WebRequest(Base):
    __tablename__ = "web_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    target_host: Mapped[str] = mapped_column(String(255), index=True)
    method: Mapped[str] = mapped_column(String(12), index=True)
    path: Mapped[str] = mapped_column(Text)
    query_string: Mapped[str | None] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    response_bytes: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    user_agent: Mapped[str | None] = mapped_column(Text)
    safe_headers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    body_excerpt: Mapped[str | None] = mapped_column(Text)
    session_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    upstream_signals: Mapped[list[str]] = mapped_column(JSON, default=list)
    request_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    security_event_id: Mapped[str | None] = mapped_column(ForeignKey("security_events.id"), unique=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(30), default="experimental")
    source: Mapped[str] = mapped_column(String(100), default="sigma")
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    rule_body: Mapped[dict[str, Any]] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    risk_level: Mapped[str] = mapped_column(String(20), default="LOW", index=True)
    risk_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default="NEW", index=True)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    correlation_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    alerts: Mapped[list[Alert]] = relationship(back_populates="incident")
    iocs: Mapped[list[IOC]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    evidence: Mapped[list[Evidence]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    timeline: Mapped[list[TimelineEvent]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    response_actions: Mapped[list[ResponseAction]] = relationship(back_populates="incident")


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"), index=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(100))
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence_reference: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    event: Mapped[SecurityEvent] = relationship(back_populates="alerts")
    incident: Mapped[Incident | None] = relationship(back_populates="alerts")


class AttackDetection(Base):
    __tablename__ = "attack_detections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    attack_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    attack_type: Mapped[str] = mapped_column(String(80), index=True)
    family: Mapped[str] = mapped_column(String(60), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    classification: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), default="DETECTED", index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    target_host: Mapped[str] = mapped_column(String(255), index=True)
    endpoint: Mapped[str] = mapped_column(Text)
    request_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id"), unique=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True)
    primary_event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"), index=True)
    related_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    response_status: Mapped[str] = mapped_column(String(30), default="NOT_REQUESTED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("incident_id", "ioc_type", "value", name="uq_incident_ioc"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    ioc_type: Mapped[str] = mapped_column(String(30), index=True)
    value: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0)
    verdict: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    source: Mapped[str] = mapped_column(String(100), default="event")
    enrichment: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    incident: Mapped[Incident] = relationship(back_populates="iocs")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(50))
    source: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(30), default="COLLECTED")
    reference: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    collected_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    incident: Mapped[Incident] = relationship(back_populates="evidence")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    event_type: Mapped[str] = mapped_column(String(50))
    source: Mapped[str] = mapped_column(String(100))
    summary: Mapped[str] = mapped_column(Text)
    reference_id: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    incident: Mapped[Incident] = relationship(back_populates="timeline")


class ResponsePolicy(Base):
    __tablename__ = "response_policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    preapproved_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    require_approval_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    authorized_targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    min_risk_level: Mapped[str] = mapped_column(String(20), default="LOW")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(50))
    target: Mapped[str] = mapped_column(String(512))
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    policy_id: Mapped[str] = mapped_column(ForeignKey("response_policies.id"))
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_status: Mapped[str] = mapped_column(String(20), default="PENDING")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    execution_status: Mapped[str] = mapped_column(String(20), default="PENDING")
    execution_result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    incident: Mapped[Incident] = relationship(back_populates="response_actions")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    target_type: Mapped[str] = mapped_column(String(50))
    target_id: Mapped[str | None] = mapped_column(String(255))
    result: Mapped[str] = mapped_column(String(30))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    correlation_id: Mapped[str | None] = mapped_column(String(64), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    format: Mapped[str] = mapped_column(String(20))
    file_name: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    generated_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class MemoryExperience(Base):
    """Structured experience provenance; only Hindsight-confirmed documents are recallable."""

    __tablename__ = "memory_experiences"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), unique=True, index=True)
    document_id: Mapped[str] = mapped_column(String(100), unique=True)
    experience: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class InvestigationRecommendation(Base):
    __tablename__ = "investigation_recommendations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    content: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class DetectionCoverage(Base):
    __tablename__ = "detection_coverage"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scenario_id: Mapped[str] = mapped_column(String(100), unique=True)
    technique_id: Mapped[str] = mapped_column(String(30), index=True)
    tactic: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(20))
    expected_detection: Mapped[str] = mapped_column(String(255))
    observed_alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id"))
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
