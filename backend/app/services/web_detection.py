from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote_plus

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    IOC,
    Alert,
    AttackDetection,
    DetectionRule,
    Incident,
    SecurityEvent,
    TimelineEvent,
    WebRequest,
)
from app.schemas import EventCreate
from app.services.correlation import LEVEL_ORDER, recalculate_risk
from app.services.ingestion import ingest_event
from app.web_catalog import ATTACK_BY_SLUG, WEB_ATTACK_CATALOG, WebAttackDefinition, resolve_attack_signal
from app.web_schemas import WebRequestCreate

SAFE_HEADER_NAMES = {
    "host",
    "content-type",
    "origin",
    "referer",
    "x-forwarded-host",
    "x-http-method-override",
    "transfer-encoding",
    "content-length",
    "cache-control",
    "upgrade",
    "sec-websocket-protocol",
}
SECRET_PATTERN = re.compile(r"(?i)((?:password|passwd|token|secret|api[_-]?key|authorization)\s*[=:]\s*)[^&\s,;]+")
AUTH_PATH_PATTERN = re.compile(r"(?i)/(?:login|signin|auth|session|oauth/token)(?:/|\?|$)")
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def redact(value: str | None) -> str | None:
    if value is None:
        return None
    return SECRET_PATTERN.sub(r"\1[REDACTED]", value)


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): str(value)[:1024] for key, value in headers.items() if key.lower() in SAFE_HEADER_NAMES}


def sync_web_rules(db: Session) -> int:
    for definition in WEB_ATTACK_CATALOG:
        values = {
            "title": definition.name,
            "description": definition.description,
            "severity": definition.severity,
            "confidence": definition.base_confidence,
            "status": "stable" if definition.detection_mode != "CONTEXT_SIGNAL" else "context-required",
            "source": "ghostsoc-web",
            "mitre_techniques": list(definition.mitre),
            "rule_body": {
                "family": definition.family,
                "detection_mode": definition.detection_mode,
                "pattern_count": len(definition.patterns),
                "requires_context": "CONTEXT" in definition.detection_mode
                or "CONFIGURATION" in definition.detection_mode,
            },
        }
        rule = db.get(DetectionRule, definition.rule_id)
        if rule is None:
            db.add(DetectionRule(id=definition.rule_id, **values))
        else:
            for key, value in values.items():
                setattr(rule, key, value)
    db.commit()
    return len(WEB_ATTACK_CATALOG)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _escalate_severity(base: str, confirmed: bool) -> str:
    if not confirmed or base == "CRITICAL":
        return base
    return SEVERITY_ORDER[min(SEVERITY_ORDER.index(base) + 1, len(SEVERITY_ORDER) - 1)]


def _classification(definition: WebAttackDefinition, count: int, signaled: bool) -> tuple[str, float, str]:
    if signaled or count >= 8:
        confidence = max(definition.base_confidence, 0.92 if count >= 8 else 0.9)
        return "CONFIRMED_ATTACK", confidence, _escalate_severity(definition.severity, True)
    if count >= 3:
        return "LIKELY_ATTACK", max(definition.base_confidence, 0.78), definition.severity
    return "SUSPICIOUS", definition.base_confidence, definition.severity


def _scan_text(payload: WebRequestCreate, headers: dict[str, str]) -> str:
    raw = "\n".join(
        value
        for value in (
            payload.path,
            payload.query_string or "",
            payload.body_excerpt or "",
            payload.user_agent or "",
            "\n".join(f"{key}: {value}" for key, value in headers.items()),
        )
        if value
    )
    return unquote_plus(raw)[:32_768]


def _recent_requests(db: Session, timestamp: datetime, seconds: int) -> list[WebRequest]:
    cutoff = _as_utc(timestamp) - timedelta(seconds=seconds)
    return list(db.scalars(select(WebRequest).where(WebRequest.timestamp >= cutoff)).all())


def detect_candidates(
    db: Session, payload: WebRequestCreate, normalized_headers: dict[str, str]
) -> dict[str, list[dict[str, object]]]:
    candidates: dict[str, list[dict[str, object]]] = {}
    text = _scan_text(payload, normalized_headers)
    for definition in WEB_ATTACK_CATALOG:
        for pattern in definition.patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                candidates.setdefault(definition.slug, []).append(
                    {"source": "signature", "reason": definition.description, "field": "request"}
                )
                break
    for signal in payload.upstream_signals:
        definition = resolve_attack_signal(signal)
        if definition:
            candidates.setdefault(definition.slug, []).append(
                {
                    "source": "upstream_signal",
                    "reason": f"Authorized upstream control reported {definition.name}",
                    "signal": signal,
                }
            )

    recent_5m = _recent_requests(db, payload.timestamp, 300)
    auth_failures = [
        item
        for item in recent_5m
        if item.source_ip == payload.source_ip
        and item.status_code in {401, 403, 429}
        and AUTH_PATH_PATTERN.search(item.path)
    ]
    current_auth_failure = payload.status_code in {401, 403, 429} and AUTH_PATH_PATTERN.search(payload.path)
    if current_auth_failure and len(auth_failures) + 1 >= 5:
        candidates.setdefault("brute_force", []).append(
            {
                "source": "behavioral",
                "reason": f"{len(auth_failures) + 1} authentication failures from one source in 5 minutes",
            }
        )
        attempted_users = {item.username for item in auth_failures if item.username}
        if payload.username:
            attempted_users.add(payload.username)
        if len(attempted_users) >= 4:
            candidates.setdefault("password_spraying", []).append(
                {
                    "source": "behavioral",
                    "reason": f"One source attempted {len(attempted_users)} distinct accounts",
                }
            )
    if current_auth_failure and payload.username:
        account_sources = {
            item.source_ip
            for item in recent_5m
            if item.username == payload.username and item.status_code in {401, 403, 429}
        }
        account_sources.add(payload.source_ip)
        if len(account_sources) >= 4:
            candidates.setdefault("credential_stuffing", []).append(
                {
                    "source": "behavioral",
                    "reason": f"Account attempted from {len(account_sources)} distinct sources",
                }
            )
    if payload.session_id:
        digest = hashlib.sha256(payload.session_id.encode()).hexdigest()
        session_sources = {item.source_ip for item in recent_5m if item.session_hash == digest}
        session_sources.add(payload.source_ip)
        if len(session_sources) >= 2:
            candidates.setdefault("session_hijacking", []).append(
                {
                    "source": "behavioral",
                    "reason": "One session identifier appeared from multiple source addresses",
                }
            )

    recent_60s = [
        item for item in recent_5m if _as_utc(item.timestamp) >= _as_utc(payload.timestamp) - timedelta(seconds=60)
    ]
    source_endpoint_rate = (
        sum(1 for item in recent_60s if item.source_ip == payload.source_ip and item.path == payload.path) + 1
    )
    if source_endpoint_rate >= 20:
        candidates.setdefault("api_rate_limit_bypass", []).append(
            {
                "source": "behavioral",
                "reason": f"{source_endpoint_rate} requests to one endpoint in 60 seconds",
            }
        )
    if payload.method in STATE_CHANGING:
        recent_two_seconds = [
            item
            for item in recent_5m
            if item.source_ip == payload.source_ip
            and item.path == payload.path
            and item.method == payload.method
            and _as_utc(item.timestamp) >= _as_utc(payload.timestamp) - timedelta(seconds=2)
        ]
        if len(recent_two_seconds) + 1 >= 5:
            candidates.setdefault("race_condition", []).append(
                {
                    "source": "behavioral",
                    "reason": f"{len(recent_two_seconds) + 1} concurrent state-changing requests",
                }
            )
    return candidates


def _incident_for_web_attack(
    db: Session, event: SecurityEvent, definition: WebAttackDefinition
) -> tuple[Incident, bool]:
    timestamp = _as_utc(event.timestamp)
    bucket = int(timestamp.timestamp()) // (4 * 3600)
    key = f"web:{event.src_ip}:{event.host}:{bucket}"[:255]
    incident = db.scalar(select(Incident).where(Incident.correlation_key == key))
    created = incident is None
    if incident is None:
        incident = Incident(
            title=f"Correlated web attacks from {event.src_ip} against {event.host}",
            description="Web incident correlated by source, target, and four-hour activity window.",
            severity=definition.severity,
            correlation_key=key,
        )
        db.add(incident)
        db.flush()
    if not any(item.ioc_type == "IP" and item.value == event.src_ip for item in incident.iocs):
        incident.iocs.append(IOC(ioc_type="IP", value=event.src_ip or "unknown", source="web-monitor"))
    return incident, created


def _upsert_attack(
    db: Session,
    request: WebRequest,
    event: SecurityEvent,
    definition: WebAttackDefinition,
    evidence: list[dict[str, object]],
) -> AttackDetection:
    timestamp = _as_utc(request.timestamp)
    bucket = int(timestamp.timestamp()) // (15 * 60)
    key = f"{request.source_ip}:{request.target_host}:{definition.slug}:{bucket}"[:255]
    attack = db.scalar(select(AttackDetection).where(AttackDetection.attack_key == key))
    signaled = any(item.get("source") == "upstream_signal" for item in evidence)
    if attack is not None:
        attack.request_count += 1
        attack.last_seen = request.timestamp
        if event.id not in attack.related_event_ids:
            attack.related_event_ids = [*attack.related_event_ids[-199:], event.id]
        attack.evidence = [*attack.evidence[-49:], *evidence]
        classification, confidence, severity = _classification(definition, attack.request_count, signaled)
        attack.classification = classification
        attack.confidence = max(attack.confidence, confidence)
        attack.severity = severity
        alert = db.get(Alert, attack.alert_id) if attack.alert_id else None
        if alert:
            alert.confidence = attack.confidence
            alert.severity = attack.severity
        incident = db.get(Incident, attack.incident_id) if attack.incident_id else None
        if incident:
            if LEVEL_ORDER.get(attack.severity, 0) > LEVEL_ORDER.get(incident.severity, 0):
                incident.severity = attack.severity
            incident.timeline.append(
                TimelineEvent(
                    event_type="ATTACK_ACTIVITY_UPDATED",
                    source="ghostsoc-web-detection",
                    summary=f"{definition.name} activity increased to {attack.request_count} requests",
                    reference_id=attack.id,
                    timestamp=request.timestamp,
                    details={"classification": classification, "confidence": confidence},
                )
            )
        db.commit()
        if incident:
            recalculate_risk(db, incident)
        db.refresh(attack)
        return attack

    classification, confidence, severity = _classification(definition, 1, signaled)
    incident, incident_created = _incident_for_web_attack(db, event, definition)
    if LEVEL_ORDER.get(severity, 0) > LEVEL_ORDER.get(incident.severity, 0):
        incident.severity = severity
    attack = AttackDetection(
        attack_key=key,
        attack_type=definition.name,
        family=definition.family,
        severity=severity,
        confidence=confidence,
        classification=classification,
        source_ip=request.source_ip,
        target_host=request.target_host,
        endpoint=request.path,
        first_seen=request.timestamp,
        last_seen=request.timestamp,
        rule_id=definition.rule_id,
        incident_id=incident.id,
        primary_event_id=event.id,
        related_event_ids=[event.id],
        evidence=evidence,
        mitre_techniques=list(definition.mitre),
    )
    db.add(attack)
    db.flush()
    fingerprint = hashlib.sha256(f"web-attack:{key}".encode()).hexdigest()
    alert = Alert(
        event_id=event.id,
        incident_id=incident.id,
        rule_id=definition.rule_id,
        title=definition.name,
        severity=severity,
        confidence=confidence,
        source="ghostsoc-web",
        fingerprint=fingerprint,
        mitre_techniques=list(definition.mitre),
        evidence_reference=f"web-request:{request.request_id}",
    )
    try:
        with db.begin_nested():
            db.add(alert)
            alert.incident = incident
            db.flush()
    except IntegrityError:
        alert = db.scalar(select(Alert).where(Alert.fingerprint == fingerprint))
        if alert is None:
            raise
    attack.alert_id = alert.id
    incident.timeline.append(
        TimelineEvent(
            event_type="WEB_INCIDENT_CREATED" if incident_created else "WEB_ATTACK_CORRELATED",
            source="ghostsoc-web-detection",
            summary=f"{definition.name} classified as {classification.replace('_', ' ').lower()}",
            reference_id=attack.id,
            timestamp=request.timestamp,
            details={
                "rule_id": definition.rule_id,
                "family": definition.family,
                "confidence": confidence,
                "request_id": request.request_id,
            },
        )
    )
    db.commit()
    recalculate_risk(db, incident)
    db.refresh(attack)
    return attack


def ingest_web_request(db: Session, payload: WebRequestCreate) -> tuple[WebRequest, bool, list[AttackDetection]]:
    existing = db.scalar(select(WebRequest).where(WebRequest.request_id == payload.request_id))
    if existing:
        return existing, True, []
    normalized_headers = safe_headers(payload.headers)
    candidates = detect_candidates(db, payload, normalized_headers)
    redacted_query = redact(payload.query_string)
    redacted_body = redact(payload.body_excerpt)
    session_hash = hashlib.sha256(payload.session_id.encode()).hexdigest() if payload.session_id else None
    event_payload = EventCreate(
        event_id=f"web:{payload.request_id}",
        timestamp=payload.timestamp,
        source="web-monitor",
        source_type="web",
        host=payload.target_host,
        user=payload.username,
        src_ip=payload.source_ip,
        domain=payload.target_host,
        url=f"https://{payload.target_host}{payload.path}" + (f"?{redacted_query}" if redacted_query else ""),
        event_type="web_request",
        severity="INFO",
        raw_reference=f"web-request:{payload.request_id}",
        metadata={
            "method": payload.method,
            "path": payload.path,
            "status_code": payload.status_code,
            "upstream_signals": payload.upstream_signals,
            **payload.metadata,
        },
        raw_payload={
            "method": payload.method,
            "path": payload.path,
            "query_string": redacted_query,
            "status_code": payload.status_code,
            "safe_headers": normalized_headers,
            "body_excerpt": redacted_body,
        },
    )
    event, _, _, _ = ingest_event(db, event_payload)
    request = WebRequest(
        request_id=payload.request_id,
        timestamp=payload.timestamp,
        source_ip=payload.source_ip,
        target_host=payload.target_host,
        method=payload.method,
        path=payload.path,
        query_string=redacted_query,
        status_code=payload.status_code,
        response_bytes=payload.response_bytes,
        latency_ms=payload.latency_ms,
        user_agent=payload.user_agent,
        safe_headers=normalized_headers,
        body_excerpt=redacted_body,
        session_hash=session_hash,
        username=payload.username,
        upstream_signals=payload.upstream_signals,
        request_metadata=payload.metadata,
        security_event_id=event.id,
    )
    db.add(request)
    db.commit()
    db.refresh(request)
    attacks = [
        _upsert_attack(db, request, event, ATTACK_BY_SLUG[slug], evidence) for slug, evidence in candidates.items()
    ]
    return request, False, attacks
