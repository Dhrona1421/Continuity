from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, func, select
from sqlalchemy.orm import selectinload

from app.api.dependencies import DbSession, require_permission
from app.connectors.registry import list_connectors
from app.core.config import get_settings
from app.models import (
    IOC,
    Alert,
    AttackDetection,
    AuditLog,
    DetectionCoverage,
    Evidence,
    Incident,
    InvestigationRecommendation,
    MemoryExperience,
    Report,
    ResponseAction,
    SecurityEvent,
    TimelineEvent,
    User,
    WebRequest,
)
from app.schemas import ResponseRequest
from app.services.audit import record_audit
from app.services.correlation import recalculate_risk
from app.services.realtime import live_broker
from app.services.reporting import generate_report
from app.services.response import create_action
from app.services.search import index_event
from app.services.web_detection import ingest_web_request
from app.web_catalog import WEB_ATTACK_CATALOG
from app.web_schemas import AttackUpdate, AttackView, WebIngestResult, WebRequestCreate, WebRequestView

router = APIRouter(prefix="/api/v1")


def _request_view(item: WebRequest) -> dict[str, object]:
    return WebRequestView.model_validate(item).model_dump(mode="json")


def _attack_view(item: AttackDetection) -> dict[str, object]:
    return AttackView.model_validate(item).model_dump(mode="json")


@router.get("/web/attack-catalog", tags=["web-security"])
def attack_catalog(
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> dict[str, object]:
    families: dict[str, int] = {}
    for definition in WEB_ATTACK_CATALOG:
        families[definition.family] = families.get(definition.family, 0) + 1
    return {
        "total": len(WEB_ATTACK_CATALOG),
        "families": families,
        "definitions": [definition.view() for definition in WEB_ATTACK_CATALOG],
        "truth_note": (
            "Context-dependent categories require explicit application/WAF signals; "
            "access-log signatures alone are not treated as proof of exploitation."
        ),
    }


@router.post("/web/requests", response_model=WebIngestResult, status_code=201, tags=["web-security"])
async def create_web_request(
    payload: WebRequestCreate,
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> WebIngestResult:
    if payload.target_host not in get_settings().web_allowed_hosts:
        raise HTTPException(status_code=403, detail="Web target is not in GHOSTSOC_WEB_ALLOWED_HOSTS")
    web_request, duplicate, attacks = ingest_web_request(db, payload)
    search_status = "SKIPPED_DUPLICATE"
    if not duplicate:
        event = db.get(SecurityEvent, web_request.security_event_id)
        search_status = await index_event(event) if event else "EVENT_NOT_FOUND"
        await live_broker.publish("web_request", _request_view(web_request))
        for attack in attacks:
            await live_broker.publish("attack", _attack_view(attack))
        record_audit(
            db,
            actor_id=user.id,
            action="WEB_REQUEST_INGEST",
            target_type="web_request",
            target_id=web_request.id,
            result="SUCCESS",
            correlation_id=getattr(request.state, "correlation_id", None),
            details={
                "attack_count": len(attacks),
                "source": web_request.source_ip,
                "target": web_request.target_host,
                "search_index": search_status,
            },
        )
    return WebIngestResult(
        duplicate=duplicate,
        request=WebRequestView.model_validate(web_request),
        attacks=[AttackView.model_validate(item) for item in attacks],
        incident_ids=sorted({item.incident_id for item in attacks if item.incident_id}),
    )


@router.get("/web/requests", response_model=list[WebRequestView], tags=["web-security"])
def web_requests(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    source_ip: str | None = Query(default=None, max_length=64),
    endpoint: str | None = Query(default=None, max_length=4096),
    method: str | None = Query(default=None, pattern="^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$"),
    status_code: int | None = Query(default=None, ge=100, le=599),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> list[WebRequest]:
    query = select(WebRequest).order_by(WebRequest.timestamp.desc()).offset(offset).limit(limit)
    if source_ip:
        query = query.where(WebRequest.source_ip == source_ip)
    if endpoint:
        query = query.where(WebRequest.path.ilike(f"%{endpoint}%"))
    if method:
        query = query.where(WebRequest.method == method)
    if status_code:
        query = query.where(WebRequest.status_code == status_code)
    return list(db.scalars(query).all())


@router.get("/web/attacks", response_model=list[AttackView], tags=["web-security"])
def attacks(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    attack_type: str | None = Query(default=None, max_length=80),
    family: str | None = Query(default=None, max_length=60),
    severity: str | None = Query(default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    source_ip: str | None = Query(default=None, max_length=64),
    endpoint: str | None = Query(default=None, max_length=4096),
    status: str | None = Query(default=None, max_length=30),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> list[AttackDetection]:
    query = select(AttackDetection).order_by(AttackDetection.last_seen.desc()).offset(offset).limit(limit)
    if attack_type:
        query = query.where(AttackDetection.attack_type.ilike(f"%{attack_type}%"))
    if family:
        query = query.where(AttackDetection.family == family)
    if severity:
        query = query.where(AttackDetection.severity == severity)
    if source_ip:
        query = query.where(AttackDetection.source_ip == source_ip)
    if endpoint:
        query = query.where(AttackDetection.endpoint.ilike(f"%{endpoint}%"))
    if status:
        query = query.where(AttackDetection.status == status)
    return list(db.scalars(query).all())


@router.patch("/web/attacks/{attack_id}", response_model=AttackView, tags=["web-security"])
async def update_attack(
    attack_id: str,
    payload: AttackUpdate,
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("MANAGE_INCIDENTS"))],
) -> AttackDetection:
    attack = db.get(AttackDetection, attack_id)
    if attack is None:
        raise HTTPException(status_code=404, detail="Attack detection not found")
    changes = payload.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(status_code=422, detail="At least one attack field must be supplied")
    for key, value in changes.items():
        setattr(attack, key, value)
    incident = db.get(Incident, attack.incident_id) if attack.incident_id else None
    if attack.classification == "FALSE_POSITIVE":
        attack.status = "FALSE_POSITIVE"
        alert = db.get(Alert, attack.alert_id) if attack.alert_id else None
        if alert:
            alert.confidence = 0
    if incident:
        incident.timeline.append(
            TimelineEvent(
                event_type="ATTACK_CLASSIFICATION_UPDATED",
                source="ghostsoc-web-analysis",
                summary=f"Attack classification updated: {attack.classification} / {attack.status}",
                reference_id=attack.id,
                details=changes,
            )
        )
    record_audit(
        db,
        actor_id=user.id,
        action="ATTACK_UPDATE",
        target_type="attack_detection",
        target_id=attack.id,
        result="SUCCESS",
        correlation_id=getattr(request.state, "correlation_id", None),
        details=changes,
        commit=False,
    )
    db.commit()
    if incident:
        recalculate_risk(db, incident)
    db.refresh(attack)
    await live_broker.publish("attack", _attack_view(attack))
    return attack


@router.get("/web/attacks/{attack_id}", tags=["web-security"])
def attack_detail(
    attack_id: str,
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> dict[str, object]:
    attack = db.get(AttackDetection, attack_id)
    if attack is None:
        raise HTTPException(status_code=404, detail="Attack detection not found")
    incident = (
        db.scalar(
            select(Incident)
            .options(
                selectinload(Incident.alerts),
                selectinload(Incident.iocs),
                selectinload(Incident.evidence),
                selectinload(Incident.timeline),
                selectinload(Incident.response_actions),
            )
            .where(Incident.id == attack.incident_id)
        )
        if attack.incident_id
        else None
    )
    requests = list(
        db.scalars(select(WebRequest).where(WebRequest.security_event_id.in_(attack.related_event_ids))).all()
    )
    audit_targets = [attack.id, attack.alert_id, attack.incident_id]
    if incident:
        audit_targets.extend(item.id for item in incident.response_actions)
    audit = list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.target_id.in_([item for item in audit_targets if item]))
            .order_by(AuditLog.timestamp.desc())
            .limit(100)
        ).all()
    )
    return {
        "attack": _attack_view(attack),
        "requests": [_request_view(item) for item in requests],
        "alert": (
            {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "evidence_reference": alert.evidence_reference,
            }
            if attack.alert_id and (alert := db.get(Alert, attack.alert_id))
            else None
        ),
        "incident": (
            {
                "id": incident.id,
                "title": incident.title,
                "status": incident.status,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "risk_level": incident.risk_level,
                "risk_reasons": incident.risk_reasons,
                "alerts": [
                    {
                        "id": item.id,
                        "title": item.title,
                        "severity": item.severity,
                        "confidence": item.confidence,
                        "rule_id": item.rule_id,
                        "evidence_reference": item.evidence_reference,
                    }
                    for item in incident.alerts
                ],
                "iocs": [
                    {
                        "id": item.id,
                        "type": item.ioc_type,
                        "value": item.value,
                        "verdict": item.verdict,
                        "enrichment": item.enrichment,
                    }
                    for item in incident.iocs
                ],
                "evidence": [
                    {
                        "id": item.id,
                        "type": item.evidence_type,
                        "source": item.source,
                        "summary": item.summary,
                        "status": item.status,
                    }
                    for item in incident.evidence
                ],
                "timeline": [
                    {
                        "id": item.id,
                        "timestamp": item.timestamp.isoformat(),
                        "type": item.event_type,
                        "source": item.source,
                        "summary": item.summary,
                        "details": item.details,
                    }
                    for item in sorted(
                        incident.timeline,
                        key=lambda row: row.timestamp if row.timestamp.tzinfo else row.timestamp.replace(tzinfo=UTC),
                    )
                ],
                "responses": [
                    {
                        "id": item.id,
                        "action_type": item.action_type,
                        "target": item.target,
                        "approval": item.approval_status,
                        "status": item.execution_status,
                        "dry_run": item.dry_run,
                        "result": item.execution_result,
                    }
                    for item in incident.response_actions
                ],
            }
            if incident
            else None
        ),
        "audit": [
            {
                "id": item.id,
                "timestamp": item.timestamp.isoformat(),
                "action": item.action,
                "result": item.result,
                "correlation_id": item.correlation_id,
            }
            for item in audit
        ],
    }


def _top_rows(db: DbSession, column, since: datetime, limit: int = 5) -> list[dict[str, object]]:
    rows = db.execute(
        select(column, func.sum(AttackDetection.request_count).label("count"))
        .where(AttackDetection.last_seen >= since)
        .group_by(column)
        .order_by(func.sum(AttackDetection.request_count).desc())
        .limit(limit)
    ).all()
    return [{"value": row[0], "count": int(row[1] or 0)} for row in rows]


@router.get("/web/summary", tags=["web-security"])
def web_summary(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> dict[str, object]:
    now = datetime.now(UTC)
    minute = now - timedelta(seconds=60)
    day = now - timedelta(hours=24)
    requests_60 = db.scalar(select(func.count()).select_from(WebRequest).where(WebRequest.timestamp >= minute)) or 0
    events_60 = db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.timestamp >= minute)) or 0
    requests_24 = db.scalar(select(func.count()).select_from(WebRequest).where(WebRequest.timestamp >= day)) or 0
    detected_requests = (
        db.scalar(select(func.sum(AttackDetection.request_count)).where(AttackDetection.last_seen >= day)) or 0
    )
    attacks_24 = (
        db.scalar(select(func.count()).select_from(AttackDetection).where(AttackDetection.last_seen >= day)) or 0
    )
    blocked = (
        db.scalar(
            select(func.count())
            .select_from(ResponseAction)
            .where(
                ResponseAction.dry_run.is_(False),
                ResponseAction.execution_status == "SUCCESS",
                ResponseAction.executed_at >= day,
            )
        )
        or 0
    )
    simulated = (
        db.scalar(
            select(func.count())
            .select_from(ResponseAction)
            .where(ResponseAction.execution_status == "DRY_RUN", ResponseAction.executed_at >= day)
        )
        or 0
    )
    severity_rows = db.execute(
        select(AttackDetection.severity, func.count())
        .where(AttackDetection.last_seen >= day)
        .group_by(AttackDetection.severity)
    ).all()
    risk_rows = db.execute(select(Incident.risk_level, func.count()).group_by(Incident.risk_level)).all()
    connectors = list_connectors(db)
    connector_health: dict[str, int] = {}
    for connector in connectors:
        status = str(connector["status"])
        connector_health[status] = connector_health.get(status, 0) + 1
    opensearch_status = next(
        (str(item["status"]) for item in connectors if item["name"] == "OpenSearch"),
        "UNKNOWN",
    )
    active_states = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT_PENDING"]
    return {
        "window": "24h",
        "mode": "SIMULATION"
        if any(item.source_ip.startswith("198.51.100.") for item in db.scalars(select(AttackDetection).limit(20)))
        else "LIVE",
        "metrics": {
            "requests_per_sec": round(requests_60 / 60, 2),
            "events_per_sec": round(events_60 / 60, 2),
            "requests": int(requests_24),
            "attacks": int(attacks_24),
            "active_incidents": db.scalar(
                select(func.count()).select_from(Incident).where(Incident.status.in_(active_states))
            )
            or 0,
            "critical": dict(severity_rows).get("CRITICAL", 0),
            "high": dict(severity_rows).get("HIGH", 0),
            "medium": dict(severity_rows).get("MEDIUM", 0),
            "blocked_confirmed": int(blocked),
            "responses_simulated": int(simulated),
            "detection_rate": round(min(100, detected_requests / requests_24 * 100), 1) if requests_24 else 0,
            "block_rate": round(blocked / attacks_24 * 100, 1) if attacks_24 else 0,
        },
        "severity_distribution": {key: int(value) for key, value in severity_rows},
        "risk_distribution": {key: int(value) for key, value in risk_rows},
        "top_sources": _top_rows(db, AttackDetection.source_ip, day),
        "top_attack_types": _top_rows(db, AttackDetection.attack_type, day),
        "top_targets": _top_rows(db, AttackDetection.endpoint, day),
        "affected_hosts": _top_rows(db, AttackDetection.target_host, day),
        "connector_health": connector_health,
        "system_health": {
            "database": "HEALTHY",
            "stream": "HEALTHY",
            "opensearch": opensearch_status,
        },
    }


@router.get("/web/replay", tags=["web-security"])
def persisted_replay(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> dict[str, object]:
    latest_attack = db.scalar(select(AttackDetection).order_by(AttackDetection.last_seen.desc()).limit(1))
    if latest_attack is None or latest_attack.incident_id is None:
        return {"incident_id": None, "events": []}
    incident = db.get(Incident, latest_attack.incident_id)
    if incident is None:
        return {"incident_id": None, "events": []}
    timeline = sorted(
        incident.timeline,
        key=lambda item: item.timestamp if item.timestamp.tzinfo else item.timestamp.replace(tzinfo=UTC),
    )
    return {
        "incident_id": incident.id,
        "events": [
            {
                "sequence": index,
                "timestamp": item.timestamp.isoformat(),
                "label": item.summary,
                "type": item.event_type,
                "source": item.source,
                "details": item.details,
                "simulated": bool(item.details.get("simulated")) or "demo" in item.source.lower(),
            }
            for index, item in enumerate(timeline)
        ],
    }


@router.get("/live/history", tags=["live-monitor"])
def live_history(
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, object]]:
    return live_broker.recent(limit)


@router.get("/live/stream", tags=["live-monitor"])
async def live_stream(
    request: Request,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> StreamingResponse:
    async def stream():
        connected = {
            "type": "connected",
            "timestamp": datetime.now(UTC).isoformat(),
            "data": {"status": "LIVE", "transport": "SSE"},
        }
        yield f"event: connected\ndata: {json.dumps(connected, separators=(',', ':'))}\n\n"
        async for message in live_broker.subscribe():
            if await request.is_disconnected():
                break
            payload = json.dumps(message, separators=(",", ":"), default=str)
            yield f"event: {message['type']}\ndata: {payload}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/demo/web-run", tags=["demo", "web-security"])
async def run_web_demo(
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("EXECUTE_RESPONSE"))],
) -> dict[str, object]:
    settings = get_settings()
    if not settings.demo_mode or not settings.dry_run:
        raise HTTPException(status_code=403, detail="Controlled web demo requires demo mode and dry-run")
    now = datetime.now(UTC)
    source = "198.51.100.23"
    target = "demo-web.local"
    sequence = [
        {"method": "GET", "path": "/", "query": None, "status": 200, "signals": []},
        {"method": "GET", "path": "/api/login", "query": "id=1%27+OR+%271%27%3D%271--", "status": 400, "signals": []},
        {
            "method": "GET",
            "path": "/search",
            "query": "q=%3Cscript%3Ealert(1)%3C/script%3E",
            "status": 400,
            "signals": [],
        },
        {"method": "GET", "path": "/download", "query": "file=../../../../etc/passwd", "status": 403, "signals": []},
        {"method": "POST", "path": "/login", "query": None, "status": 401, "signals": [], "username": "admin"},
        {"method": "POST", "path": "/login", "query": None, "status": 401, "signals": [], "username": "finance"},
        {"method": "POST", "path": "/login", "query": None, "status": 401, "signals": [], "username": "support"},
        {"method": "POST", "path": "/login", "query": None, "status": 401, "signals": [], "username": "operator"},
        {"method": "POST", "path": "/login", "query": None, "status": 401, "signals": [], "username": "backup"},
        {
            "method": "POST",
            "path": "/graphql",
            "query": None,
            "status": 400,
            "signals": ["graphql_attack"],
            "body": "query IntrospectionQuery { __schema { types { name } } }",
        },
        {
            "method": "GET",
            "path": "/fetch",
            "query": "url=http://169.254.169.254/latest/meta-data/",
            "status": 403,
            "signals": [],
        },
    ]
    created_requests: list[str] = []
    attack_ids: list[str] = []
    incident_ids: set[str] = set()
    for index, item in enumerate(sequence):
        payload = WebRequestCreate(
            request_id=f"web-demo-{now.strftime('%Y%m%d%H%M%S%f')}-{index}",
            timestamp=now + timedelta(milliseconds=index * 250),
            source_ip=source,
            target_host=target,
            method=item["method"],
            path=item["path"],
            query_string=item.get("query"),
            status_code=item["status"],
            response_bytes=512 + index * 13,
            latency_ms=18 + index * 2,
            user_agent="GhostSOC-Controlled-Web-Replay/1.0",
            headers={"host": target, "content-type": "application/json"},
            body_excerpt=item.get("body"),
            username=item.get("username"),
            upstream_signals=item["signals"],
            metadata={"demo": True, "simulated": True, "sequence": index},
        )
        web_request, _, attacks_found = ingest_web_request(db, payload)
        created_requests.append(web_request.id)
        event = db.get(SecurityEvent, web_request.security_event_id)
        if event:
            await index_event(event)
        await live_broker.publish("web_request", _request_view(web_request))
        for attack in attacks_found:
            attack_ids.append(attack.id)
            if attack.incident_id:
                incident_ids.add(attack.incident_id)
            await live_broker.publish("attack", _attack_view(attack))
        await live_broker.publish(
            "replay_step",
            {
                "sequence": index,
                "label": "Request ingested" if not attacks_found else "Detection triggered",
                "request_id": web_request.id,
                "attacks": [item.attack_type for item in attacks_found],
                "simulated": True,
            },
        )
        await asyncio.sleep(0.08)
    reports: dict[str, dict[str, str]] = {}
    action_id: str | None = None
    for incident_id in incident_ids:
        incident = db.get(Incident, incident_id)
        if incident is None:
            continue
        source_ioc = next((item for item in incident.iocs if item.ioc_type == "IP" and item.value == source), None)
        if source_ioc:
            source_ioc.enrichment = [
                {
                    "provider": "GhostSOC Controlled Web Fixture",
                    "indicator": source,
                    "indicator_type": "IP",
                    "status": "SUCCESS",
                    "verdict": "SIMULATED_MALICIOUS",
                    "confidence": 0.95,
                    "summary": "Reserved documentation address used by the controlled replay",
                    "reference": "demo:web-security",
                    "mock": True,
                }
            ]
            source_ioc.verdict = "SIMULATED"
            source_ioc.confidence = 0.95
        evidence = Evidence(
            incident_id=incident.id,
            evidence_type="WEB_REQUEST_SET",
            source="GhostSOC Web Replay — SIMULATED",
            status="COLLECTED",
            reference=f"web-demo:{now.isoformat()}",
            sha256=hashlib.sha256("|".join(created_requests).encode()).hexdigest(),
            summary=f"{len(created_requests)} controlled web requests retained as normalized references",
            details={"request_ids": created_requests, "simulated": True, "external_tool_executed": False},
            collected_by=user.id,
        )
        db.add(evidence)
        action, _ = create_action(
            db,
            ResponseRequest(
                incident_id=incident.id,
                action_type="RATE_LIMIT_SOURCE",
                target=source,
                idempotency_key=f"web-demo:{now.strftime('%Y%m%d%H%M%S%f')}:rate-limit",
            ),
            user,
        )
        action_id = action.id
        for attack in db.scalars(select(AttackDetection).where(AttackDetection.incident_id == incident.id)):
            attack.response_status = action.execution_status
        incident.timeline.append(
            TimelineEvent(
                event_type="RESPONSE_VERIFICATION",
                source="ghostsoc-web-demo",
                summary="Dry-run rate-limit policy validated; no network control was changed",
                reference_id=action.id,
                details={"status": "DRY_RUN", "executed": False, "simulated": True},
            )
        )
        for attack in db.scalars(select(AttackDetection).where(AttackDetection.incident_id == incident.id)):
            definition = next((item for item in WEB_ATTACK_CATALOG if item.name == attack.attack_type), None)
            if definition:
                scenario_id = f"web-demo-{attack.id}"
                if not db.scalar(select(DetectionCoverage).where(DetectionCoverage.scenario_id == scenario_id)):
                    db.add(
                        DetectionCoverage(
                            scenario_id=scenario_id,
                            technique_id=definition.mitre[0],
                            tactic="Initial Access",
                            status="PASS",
                            expected_detection=definition.rule_id,
                            observed_alert_id=attack.alert_id,
                        )
                    )
        db.commit()
        db.refresh(incident)
        for report_format in ("pdf", "json", "csv", "zip"):
            report, _ = generate_report(db, incident, report_format, user)
            reports[report_format] = {"id": report.id, "sha256": report.sha256}
    record_audit(
        db,
        actor_id=user.id,
        action="WEB_DEMO_RUN",
        target_type="web_security_replay",
        target_id=next(iter(incident_ids), None),
        result="SUCCESS",
        correlation_id=getattr(request.state, "correlation_id", None),
        details={
            "simulated": True,
            "requests": len(created_requests),
            "attacks": len(set(attack_ids)),
            "external_actions_executed": False,
        },
    )
    await live_broker.publish(
        "demo_complete",
        {
            "requests": len(created_requests),
            "attacks": len(set(attack_ids)),
            "incidents": list(incident_ids),
            "action_id": action_id,
            "response_status": "DRY_RUN",
            "simulated": True,
        },
    )
    return {
        "status": "SUCCESS",
        "mode": "SIMULATED",
        "requests": len(created_requests),
        "attack_detections": len(set(attack_ids)),
        "incident_ids": sorted(incident_ids),
        "response_action_id": action_id,
        "response_status": "DRY_RUN",
        "external_actions_executed": False,
        "reports": reports,
    }


@router.post("/demo/web-reset", tags=["demo", "web-security"])
async def reset_web_demo(
    db: DbSession,
    user: Annotated[User, Depends(require_permission("MANAGE_CONNECTORS"))],
) -> dict[str, object]:
    if not get_settings().demo_mode:
        raise HTTPException(status_code=403, detail="Demo mode is disabled")
    demo_requests = [item for item in db.scalars(select(WebRequest)).all() if item.request_metadata.get("demo") is True]
    request_ids = [item.id for item in demo_requests]
    event_ids = [item.security_event_id for item in demo_requests if item.security_event_id]
    attacks_to_remove = (
        list(db.scalars(select(AttackDetection).where(AttackDetection.primary_event_id.in_(event_ids))).all())
        if event_ids
        else []
    )
    incident_ids = {item.incident_id for item in attacks_to_remove if item.incident_id}
    alert_ids = {item.alert_id for item in attacks_to_remove if item.alert_id}
    report_files = (
        list(db.scalars(select(Report.file_name).where(Report.incident_id.in_(incident_ids))).all())
        if incident_ids
        else []
    )
    for model, condition in (
        (Report, Report.incident_id.in_(incident_ids)),
        (InvestigationRecommendation, InvestigationRecommendation.incident_id.in_(incident_ids)),
        (MemoryExperience, MemoryExperience.incident_id.in_(incident_ids)),
        (ResponseAction, ResponseAction.incident_id.in_(incident_ids)),
        (Evidence, Evidence.incident_id.in_(incident_ids)),
        (TimelineEvent, TimelineEvent.incident_id.in_(incident_ids)),
        (IOC, IOC.incident_id.in_(incident_ids)),
        (DetectionCoverage, DetectionCoverage.observed_alert_id.in_(alert_ids)),
        (AttackDetection, AttackDetection.id.in_([item.id for item in attacks_to_remove])),
        (Alert, Alert.id.in_(alert_ids)),
        (Incident, Incident.id.in_(incident_ids)),
        (WebRequest, WebRequest.id.in_(request_ids)),
        (SecurityEvent, SecurityEvent.id.in_(event_ids)),
    ):
        if request_ids:
            db.execute(delete(model).where(condition))
    record_audit(
        db,
        actor_id=user.id,
        action="WEB_DEMO_RESET",
        target_type="web_security_replay",
        target_id=None,
        result="SUCCESS",
        details={"requests_removed": len(request_ids), "incidents_removed": len(incident_ids)},
        commit=False,
    )
    db.commit()
    root = get_settings().report_dir.resolve()
    removed_files = 0
    for name in report_files:
        path = (root / name).resolve()
        if path.parent == root and path.name.startswith("GhostSOC-Incident-") and path.is_file():
            path.unlink()
            removed_files += 1
    await live_broker.publish(
        "demo_reset",
        {"scope": "web-security", "requests_removed": len(request_ids), "simulated": True},
    )
    return {
        "status": "RESET",
        "requests_removed": len(request_ids),
        "attacks_removed": len(attacks_to_remove),
        "incidents_removed": len(incident_ids),
        "report_files_removed": removed_files,
    }
