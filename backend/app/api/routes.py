from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.orm import selectinload

from app.api.dependencies import CurrentUser, DbSession, require_permission
from app.connectors.cti import PROVIDERS, enrich_indicator
from app.connectors.registry import check_connector, list_connectors, set_connector_enabled
from app.connectors.telemetry import normalize_cowrie, normalize_suricata, normalize_sysmon, normalize_zeek
from app.core.config import get_settings
from app.core.security import ROLE_PERMISSIONS, create_access_token, has_permission, verify_password
from app.mitre import technique_view
from app.models import (
    IOC,
    Alert,
    AttackDetection,
    AuditLog,
    DetectionCoverage,
    DetectionRule,
    Evidence,
    Incident,
    InvestigationRecommendation,
    MemoryExperience,
    Report,
    ResponseAction,
    ResponsePolicy,
    SecurityEvent,
    TimelineEvent,
    User,
    WebRequest,
)
from app.schemas import (
    AlertView,
    ApprovalRequest,
    AuditView,
    ConnectorUpdate,
    ConnectorView,
    CTIEnrichmentRequest,
    CTIResultView,
    EventCreate,
    EventView,
    EvidenceCollectRequest,
    EvidenceView,
    IncidentUpdate,
    IncidentView,
    IngestResult,
    LoginRequest,
    ResponseActionView,
    ResponseRequest,
    TokenResponse,
    UserView,
)
from app.services.audit import record_audit
from app.services.correlation import recalculate_risk
from app.services.ingestion import ingest_event
from app.services.investigation import collect_evidence
from app.services.realtime import live_broker
from app.services.reporting import FORMATS, generate_report
from app.services.response import create_action, decide_action
from app.services.search import index_event

router = APIRouter(prefix="/api/v1")


def _correlation_id(request: Request) -> str | None:
    return getattr(request.state, "correlation_id", None)


def _incident_query():
    return select(Incident).options(
        selectinload(Incident.alerts),
        selectinload(Incident.iocs),
        selectinload(Incident.evidence),
        selectinload(Incident.timeline),
        selectinload(Incident.response_actions),
    )


@router.get("/health", tags=["system"])
def health() -> dict[str, object]:
    return {"status": "healthy", "service": "ghostsoc-api", "version": "0.1.0"}


@router.get("/ready", tags=["system"])
def readiness(db: DbSession) -> dict[str, object]:
    checks: dict[str, str] = {}
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "HEALTHY"
    except Exception:
        checks["database"] = "UNAVAILABLE"
    settings = get_settings()
    checks["opensearch"] = "CONFIGURED" if settings.opensearch_url else "NOT_CONFIGURED"
    ready = checks["database"] == "HEALTHY"
    return {"status": "ready" if ready else "not_ready", "checks": checks,
            "runtime": {"demo_mode": settings.demo_mode, "dry_run": settings.dry_run}}


@router.get("/auth/demo-access", tags=["auth"])
def demo_access(db: DbSession) -> dict[str, object]:
    settings = get_settings()
    if not (settings.demo_auto_access and settings.demo_mode and settings.dry_run):
        raise HTTPException(status_code=404, detail="Demo auto-access is disabled")
    user = db.scalar(select(User).where(User.email == settings.bootstrap_admin_email.lower()))
    if user is None or not user.is_active:
        raise HTTPException(status_code=503, detail="Demo administrator is unavailable")
    return {
        "enabled": True,
        "mode": "DEMO_DRY_RUN",
        "warning": "Authentication bypass is enabled only for this controlled demo instance",
        "user": UserView.model_validate(user).model_dump(),
    }


@router.post("/auth/login", response_model=TokenResponse, tags=["auth"])
def login(payload: LoginRequest, request: Request, response: Response, db: DbSession) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    valid = user is not None and user.is_active and verify_password(payload.password, user.password_hash)
    if not valid:
        record_audit(
            db,
            actor_id=user.id if user else None,
            action="LOGIN",
            target_type="session",
            target_id=None,
            result="DENIED",
            source_ip=request.client.host if request.client else None,
            correlation_id=_correlation_id(request),
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    record_audit(
        db,
        actor_id=user.id,
        action="LOGIN",
        target_type="session",
        target_id=user.id,
        result="SUCCESS",
        source_ip=request.client.host if request.client else None,
        correlation_id=_correlation_id(request),
    )
    settings = get_settings()
    access_token = create_access_token(user.id, user.role)
    response.set_cookie(
        key="ghostsoc_session",
        value=access_token,
        max_age=settings.access_token_minutes * 60,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="none" if settings.session_cookie_secure else "lax",
        path="/api/v1",
    )
    if settings.session_cookie_partitioned:
        response.headers["set-cookie"] += "; Partitioned"
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.access_token_minutes * 60,
        user=UserView.model_validate(user).model_dump(),
    )


@router.post("/auth/logout", tags=["auth"])
def logout(response: Response, user: CurrentUser) -> dict[str, str]:
    settings = get_settings()
    response.delete_cookie(
        key="ghostsoc_session",
        path="/api/v1",
        secure=settings.session_cookie_secure,
        samesite="none" if settings.session_cookie_secure else "lax",
    )
    if settings.session_cookie_partitioned:
        response.headers["set-cookie"] += "; Partitioned"
    return {"status": "SIGNED_OUT", "user_id": user.id}


@router.get("/auth/me", response_model=UserView, tags=["auth"])
def me(user: CurrentUser) -> User:
    return user


@router.get("/auth/permissions", tags=["auth"])
def permissions(user: CurrentUser) -> dict[str, object]:
    return {"role": user.role, "permissions": sorted(ROLE_PERMISSIONS.get(user.role, set()))}


@router.post("/events", response_model=IngestResult, status_code=201, tags=["events"])
async def create_event(
    payload: EventCreate,
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> IngestResult:
    event, duplicate, alert_count, incidents = ingest_event(db, payload)
    search_status = "SKIPPED_DUPLICATE" if duplicate else await index_event(event)
    record_audit(
        db,
        actor_id=user.id,
        action="EVENT_INGEST",
        target_type="security_event",
        target_id=event.id,
        result="DUPLICATE" if duplicate else "SUCCESS",
        correlation_id=_correlation_id(request),
        details={"source": event.source, "search_index": search_status},
    )
    return IngestResult(
        duplicate=duplicate,
        event=EventView.model_validate(event),
        alerts_created=alert_count,
        incident_ids=incidents,
    )


@router.post("/events/telemetry/{source_type}", response_model=IngestResult, status_code=201, tags=["events"])
async def create_telemetry_event(
    source_type: Literal["sysmon", "suricata", "zeek", "cowrie"],
    payload: dict,
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> IngestResult:
    normalizers = {
        "sysmon": normalize_sysmon,
        "suricata": normalize_suricata,
        "zeek": normalize_zeek,
        "cowrie": normalize_cowrie,
    }
    try:
        normalized = normalizers[source_type](payload)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"Telemetry normalization failed: {exc}") from exc
    return await create_event(normalized, request, db, user)


@router.get("/events", response_model=list[EventView], tags=["events"])
def events(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    host: str | None = Query(default=None, max_length=255),
    source: str | None = Query(default=None, max_length=100),
    severity: str | None = Query(default=None, pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$"),
    ip: str | None = Query(default=None, max_length=64),
    event_type: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[SecurityEvent]:
    query = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit)
    if host:
        query = query.where(SecurityEvent.host == host)
    if source:
        query = query.where(SecurityEvent.source == source)
    if severity:
        query = query.where(SecurityEvent.severity == severity)
    if ip:
        query = query.where(or_(SecurityEvent.src_ip == ip, SecurityEvent.dst_ip == ip))
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    return list(db.scalars(query).all())


@router.get("/hunt", tags=["hunt"])
def hunt(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    q: str = Query(min_length=2, max_length=255),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, object]:
    pattern = f"%{q}%"
    event_query = (
        select(SecurityEvent)
        .where(
            or_(
                SecurityEvent.host.ilike(pattern),
                SecurityEvent.username.ilike(pattern),
                SecurityEvent.src_ip.ilike(pattern),
                SecurityEvent.dst_ip.ilike(pattern),
                SecurityEvent.domain.ilike(pattern),
                SecurityEvent.file_hash.ilike(pattern),
                SecurityEvent.event_type.ilike(pattern),
            )
        )
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
    )
    incident_query = (
        select(Incident)
        .where(or_(Incident.title.ilike(pattern), Incident.description.ilike(pattern)))
        .order_by(Incident.updated_at.desc())
        .limit(limit)
    )
    return {
        "query": q,
        "events": [EventView.model_validate(item) for item in db.scalars(event_query).all()],
        "incidents": [
            {"id": item.id, "title": item.title, "status": item.status, "risk_level": item.risk_level}
            for item in db.scalars(incident_query).all()
        ],
    }


@router.get("/hosts", tags=["hosts"])
def hosts(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> list[dict[str, object]]:
    rows = list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.host.is_not(None))
            .order_by(SecurityEvent.timestamp.desc())
            .limit(5000)
        ).all()
    )
    result: dict[str, dict[str, object]] = {}
    for event in rows:
        if event.host not in result:
            result[event.host] = {
                "host": event.host,
                "last_seen": event.timestamp,
                "event_count": 0,
                "sources": set(),
                "highest_severity": "INFO",
            }
        host = result[event.host]
        host["event_count"] += 1
        host["sources"].add(event.source_type)
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if order.get(event.severity, 0) > order.get(str(host["highest_severity"]), 0):
            host["highest_severity"] = event.severity
    return [{**item, "sources": sorted(item["sources"])} for item in result.values()]


@router.get("/iocs", tags=["threat-intelligence"])
def iocs(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    limit: int = Query(default=200, ge=1, le=500),
) -> list[dict[str, object]]:
    return [
        {
            "id": item.id,
            "incident_id": item.incident_id,
            "type": item.ioc_type,
            "value": item.value,
            "verdict": item.verdict,
            "confidence": item.confidence,
            "source": item.source,
            "providers": [result.get("provider") for result in item.enrichment],
            "created_at": item.created_at,
        }
        for item in db.scalars(select(IOC).order_by(IOC.created_at.desc()).limit(limit)).all()
    ]


@router.get("/timeline", tags=["timeline"])
def timeline(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    incident_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=500),
) -> list[dict[str, object]]:
    query = select(TimelineEvent).order_by(TimelineEvent.timestamp.desc()).limit(limit)
    if incident_id:
        query = query.where(TimelineEvent.incident_id == incident_id)
    return [
        {
            "id": item.id,
            "incident_id": item.incident_id,
            "timestamp": item.timestamp,
            "event_type": item.event_type,
            "source": item.source,
            "summary": item.summary,
            "reference_id": item.reference_id,
        }
        for item in db.scalars(query).all()
    ]


@router.get("/mitre", tags=["mitre"])
def mitre(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> list[dict[str, object]]:
    technique_ids = sorted(
        {technique for rule in db.scalars(select(DetectionRule)).all() for technique in rule.mitre_techniques}
    )
    alerts_by_technique = {technique: 0 for technique in technique_ids}
    incidents_by_technique = {technique: set() for technique in technique_ids}
    for alert in db.scalars(select(Alert)).all():
        for technique in alert.mitre_techniques:
            alerts_by_technique[technique] = alerts_by_technique.get(technique, 0) + 1
            if alert.incident_id:
                incidents_by_technique.setdefault(technique, set()).add(alert.incident_id)
    return [
        {
            **technique_view(technique),
            "related_alerts": alerts_by_technique.get(technique, 0),
            "related_incidents": len(incidents_by_technique.get(technique, set())),
        }
        for technique in technique_ids
    ]


@router.get("/users", response_model=list[UserView], tags=["users"])
def users(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("MANAGE_CONNECTORS"))],
) -> list[User]:
    return list(db.scalars(select(User).order_by(User.email)).all())


@router.get("/response-policies", tags=["response"])
def response_policies(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> list[dict[str, object]]:
    return [
        {
            "id": policy.id,
            "name": policy.name,
            "enabled": policy.enabled,
            "allowed_actions": policy.allowed_actions,
            "preapproved_actions": policy.preapproved_actions,
            "require_approval_actions": policy.require_approval_actions,
            "authorized_targets": policy.authorized_targets,
            "min_risk_level": policy.min_risk_level,
        }
        for policy in db.scalars(select(ResponsePolicy).order_by(ResponsePolicy.name)).all()
    ]


@router.get("/incidents/{incident_id}/response-context", tags=["response"])
def incident_response_context(
    incident_id: str,
    db: DbSession,
    user: CurrentUser,
) -> dict[str, object]:
    incident = db.scalar(_incident_query().where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    policy = db.scalar(
        select(ResponsePolicy).where(ResponsePolicy.enabled.is_(True)).order_by(ResponsePolicy.created_at)
    )
    if policy is None:
        raise HTTPException(status_code=503, detail="No enabled response policy")
    event_ids = [item.event_id for item in incident.alerts]
    events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))).all()) if event_ids else []
    event_hosts = {item.host for item in events if item.host}
    authorized_hosts = sorted(event_hosts.intersection(policy.authorized_targets))
    ip_iocs = [item for item in incident.iocs if item.ioc_type == "IP"]
    hash_iocs = [
        item for item in incident.iocs if item.ioc_type == "HASH" and len(item.value.removeprefix("sha256:")) == 64
    ]
    all_iocs = list(incident.iocs)
    definitions = {
        "COLLECT_EVIDENCE": ("Collect evidence", "Collect authorized endpoint evidence.", "LOW"),
        "RATE_LIMIT_SOURCE": (
            "Rate-limit source",
            "Apply a bounded source rate limit through a verified adapter.",
            "MEDIUM",
        ),
        "BLOCK_SOURCE": (
            "Block source",
            "Block a confirmed malicious source through a verified network control.",
            "HIGH",
        ),
        "BLOCK_IOC": ("Block IOC", "Block an IOC already attached to this incident.", "HIGH"),
        "QUARANTINE_FILE": (
            "Quarantine file",
            "Quarantine a SHA-256 identified artifact through an endpoint adapter.",
            "HIGH",
        ),
        "TERMINATE_PROCESS": (
            "Terminate process",
            "Terminate a validated process target through an endpoint adapter.",
            "HIGH",
        ),
        "ISOLATE_ENDPOINT": (
            "Isolate endpoint",
            "Isolate an authorized endpoint through a verified endpoint adapter.",
            "CRITICAL",
        ),
    }

    def target_view(value: str, label: str, target_type: str, source: str) -> dict[str, str]:
        return {"value": value, "label": label, "type": target_type, "source": source}

    actions: list[dict[str, object]] = []
    for action_type in policy.allowed_actions:
        if action_type in {"COLLECT_EVIDENCE", "ISOLATE_ENDPOINT"}:
            targets = [target_view(value, value, "ENDPOINT", "incident event + policy") for value in authorized_hosts]
        elif action_type in {"RATE_LIMIT_SOURCE", "BLOCK_SOURCE"}:
            targets = [target_view(item.value, item.value, "SOURCE_IP", f"IOC {item.id[:8]}") for item in ip_iocs]
        elif action_type == "BLOCK_IOC":
            targets = [target_view(item.value, item.value, item.ioc_type, f"IOC {item.id[:8]}") for item in all_iocs]
        elif action_type == "QUARANTINE_FILE":
            targets = [target_view(item.value, item.value, "SHA256", f"IOC {item.id[:8]}") for item in hash_iocs]
        else:
            targets = []
        label, description, impact = definitions[action_type]
        actions.append(
            {
                "action_type": action_type,
                "label": label,
                "description": description,
                "impact": impact,
                "preapproved": action_type in policy.preapproved_actions,
                "approval_required": action_type in policy.require_approval_actions,
                "enabled": bool(targets),
                "disabled_reason": None if targets else "No policy-authorized incident target is available",
                "targets": targets,
            }
        )
    return {
        "incident": {
            "id": incident.id,
            "risk_level": incident.risk_level,
            "risk_score": incident.risk_score,
            "status": incident.status,
        },
        "mode": "DRY_RUN" if get_settings().dry_run else "REAL_ADAPTER_REQUIRED",
        "policy": {
            "id": policy.id,
            "name": policy.name,
            "min_risk_level": policy.min_risk_level,
            "allowed_actions": policy.allowed_actions,
        },
        "permissions": {
            "can_request": has_permission(user.role, "EXECUTE_RESPONSE"),
            "can_approve": has_permission(user.role, "APPROVE_RESPONSE"),
        },
        "actions": actions,
        "response_actions": [
            ResponseActionView.model_validate(item).model_dump(mode="json")
            for item in sorted(incident.response_actions, key=lambda item: item.requested_at, reverse=True)
        ],
        "guardrails": [
            {"name": "Authentication", "status": "PASS", "detail": f"Actor {user.email}"},
            {
                "name": "Authorization",
                "status": "PASS" if has_permission(user.role, "EXECUTE_RESPONSE") else "DENIED",
                "detail": user.role,
            },
            {"name": "Policy", "status": "PASS", "detail": policy.name},
            {"name": "Allowlist", "status": "PASS", "detail": "Typed actions and server-provided targets only"},
            {
                "name": "Execution mode",
                "status": "DRY_RUN" if get_settings().dry_run else "REQUIRES_ADAPTER",
                "detail": "No arbitrary command execution",
            },
        ],
        "truth_note": "DRY_RUN validates policy and target only; it does not change an endpoint, firewall, or proxy.",
    }


@router.get("/reports", tags=["reports"])
def reports(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("EXPORT_REPORTS"))],
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, object]]:
    return [
        {
            "id": report.id,
            "incident_id": report.incident_id,
            "format": report.format,
            "file_name": report.file_name,
            "sha256": report.sha256,
            "generated_at": report.generated_at,
            "download_url": f"/api/v1/reports/{report.id}/download",
        }
        for report in db.scalars(select(Report).order_by(Report.generated_at.desc()).limit(limit)).all()
    ]


@router.get("/alerts", response_model=list[AlertView], tags=["alerts"])
def alerts(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    limit: int = Query(default=100, ge=1, le=500),
) -> list[Alert]:
    return list(db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(limit)).all())


@router.get("/detections", tags=["detections"])
def detections(
    db: DbSession, _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))]
) -> list[dict[str, object]]:
    return [
        {
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "severity": rule.severity,
            "confidence": rule.confidence,
            "status": rule.status,
            "source": rule.source,
            "mitre_techniques": [technique_view(item) for item in rule.mitre_techniques],
            "enabled": rule.enabled,
        }
        for rule in db.scalars(select(DetectionRule).order_by(DetectionRule.id)).all()
    ]


@router.get("/incidents", tags=["incidents"])
def incidents(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    status_filter: str | None = Query(default=None, alias="status", max_length=30),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, object]]:
    query = select(Incident).order_by(Incident.updated_at.desc()).limit(limit)
    if status_filter:
        query = query.where(Incident.status == status_filter)
    return [
        {
            "id": item.id,
            "title": item.title,
            "severity": item.severity,
            "risk_score": item.risk_score,
            "risk_level": item.risk_level,
            "status": item.status,
            "owner_id": item.owner_id,
            "updated_at": item.updated_at,
        }
        for item in db.scalars(query).all()
    ]


@router.get("/incidents/{incident_id}", response_model=IncidentView, tags=["incidents"])
def incident_detail(
    incident_id: str,
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> Incident:
    incident = db.scalar(_incident_query().where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.timeline.sort(
        key=lambda item: item.timestamp if item.timestamp.tzinfo else item.timestamp.replace(tzinfo=UTC)
    )
    return incident


@router.post("/incidents/{incident_id}/recommendation", tags=["incidents"])
def investigation_recommendation(
    incident_id: str,
    db: DbSession,
    _: Annotated[User, Depends(require_permission("RUN_INVESTIGATION"))],
    without_memory: bool = False,
) -> dict[str, object]:
    incident = db.scalar(_incident_query().where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    from app.services.agent import recommend
    return recommend(db, incident, without_memory=without_memory)


@router.patch("/incidents/{incident_id}", response_model=IncidentView, tags=["incidents"])
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("MANAGE_INCIDENTS"))],
) -> Incident:
    incident = db.scalar(_incident_query().where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    changes = payload.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(incident, key, value)
    incident.timeline.append(
        TimelineEvent(
            event_type="INCIDENT_UPDATED",
            source="ghostsoc-api",
            summary="Incident fields updated",
            reference_id=incident.id,
            details=changes,
        )
    )
    record_audit(
        db,
        actor_id=user.id,
        action="INCIDENT_UPDATE",
        target_type="incident",
        target_id=incident.id,
        result="SUCCESS",
        correlation_id=_correlation_id(request),
        details=changes,
        commit=False,
    )
    db.commit()
    db.refresh(incident)
    if incident.status in {"RESOLVED", "CLOSED"}:
        from app.services.hindsight import retain as retain_experience
        retain_experience(db, incident, timeout_seconds=3)  # bounded best effort, after incident commit
    return incident


@router.post("/incidents/{incident_id}/evidence", response_model=EvidenceView, tags=["evidence"])
def collect_incident_evidence(
    incident_id: str,
    payload: EvidenceCollectRequest,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("RUN_INVESTIGATION"))],
) -> Evidence:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return collect_evidence(db, incident, payload.evidence_type, payload.target, user)


@router.post("/threat-intelligence/enrich", response_model=list[CTIResultView], tags=["threat-intelligence"])
async def enrich_ioc(
    payload: CTIEnrichmentRequest,
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> list[dict[str, object]]:
    ioc = db.get(IOC, payload.ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    names = payload.providers or [
        name for name, provider in PROVIDERS.items() if ioc.ioc_type in provider.supported_types
    ]
    cutoff = datetime.now(UTC) - timedelta(hours=1)
    cached_by_provider: dict[str, dict[str, object]] = {}
    for item in reversed(ioc.enrichment):
        provider = str(item.get("provider", ""))
        queried_at = item.get("queried_at")
        if provider not in names or provider in cached_by_provider or not isinstance(queried_at, str):
            continue
        try:
            observed = datetime.fromisoformat(queried_at.replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=UTC)
        except ValueError:
            continue
        if observed >= cutoff and item.get("status") in {"SUCCESS", "CACHED"}:
            cached_by_provider[provider] = {**item, "status": "CACHED", "cached": True}
    remaining = [name for name in names if name not in cached_by_provider]
    results = await enrich_indicator(ioc.value, ioc.ioc_type, remaining) if remaining else []
    new_views = [result.view() for result in results]
    new_by_provider = {str(item["provider"]): item for item in new_views}
    views = [cached_by_provider.get(name) or new_by_provider[name] for name in names]
    ioc.enrichment = [*ioc.enrichment, *new_views]
    malicious = [item for item in views if item["verdict"] == "MALICIOUS"]
    if malicious:
        ioc.verdict = "MALICIOUS"
        ioc.confidence = max(float(item["confidence"]) for item in malicious)
    db.commit()
    recalculate_risk(db, ioc.incident)
    return views


@router.get("/connectors", response_model=list[ConnectorView], tags=["connectors"])
def connectors(
    db: DbSession, _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))]
) -> list[dict[str, object]]:
    return list_connectors(db)


@router.patch("/connectors/{name}", response_model=ConnectorView, tags=["connectors"])
def connector_update(
    name: str,
    payload: ConnectorUpdate,
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("MANAGE_CONNECTORS"))],
) -> dict[str, object]:
    try:
        connector = set_connector_enabled(db, name, payload.enabled)
    except KeyError:
        raise HTTPException(status_code=404, detail="Connector not found") from None
    record_audit(
        db,
        actor_id=user.id,
        action="CONNECTOR_ENABLE" if payload.enabled else "CONNECTOR_DISABLE",
        target_type="connector",
        target_id=name,
        result="SUCCESS",
        correlation_id=_correlation_id(request),
        details={"enabled": payload.enabled},
    )
    return connector


@router.post("/connectors/{name}/check", tags=["connectors"])
async def connector_check(
    name: str,
    db: DbSession,
    _: Annotated[User, Depends(require_permission("MANAGE_CONNECTORS"))],
) -> dict[str, object]:
    try:
        return await check_connector(db, name)
    except KeyError:
        raise HTTPException(status_code=404, detail="Connector not found") from None


@router.post("/response-actions", response_model=ResponseActionView, status_code=201, tags=["response"])
async def response_request(
    payload: ResponseRequest,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("EXECUTE_RESPONSE"))],
) -> ResponseAction:
    action, duplicate = create_action(db, payload, user)
    await live_broker.publish(
        "response",
        {
            **ResponseActionView.model_validate(action).model_dump(mode="json"),
            "duplicate": duplicate,
        },
    )
    return action


@router.post("/response-actions/{action_id}/approval", response_model=ResponseActionView, tags=["response"])
async def response_approval(
    action_id: str,
    payload: ApprovalRequest,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("APPROVE_RESPONSE"))],
) -> ResponseAction:
    action = db.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    action = decide_action(db, action, user, payload.decision, payload.reason)
    from app.services.hindsight import retain as retain_experience
    retain_experience(db, action.incident, timeout_seconds=3)  # bounded best effort after approval
    await live_broker.publish(
        "response",
        ResponseActionView.model_validate(action).model_dump(mode="json"),
    )
    return action


@router.get("/response-actions", response_model=list[ResponseActionView], tags=["response"])
def response_actions(
    db: DbSession, _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))]
) -> list[ResponseAction]:
    return list(db.scalars(select(ResponseAction).order_by(ResponseAction.requested_at.desc())).all())


@router.get("/audit", response_model=list[AuditView], tags=["audit"])
def audit_logs(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_AUDIT"))],
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)).all())


@router.post("/incidents/{incident_id}/reports/{report_format}", tags=["reports"])
def create_report(
    incident_id: str,
    report_format: str,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("EXPORT_REPORTS"))],
) -> dict[str, object]:
    if report_format.lower() not in FORMATS:
        raise HTTPException(status_code=422, detail=f"Format must be one of {sorted(FORMATS)}")
    incident = db.scalar(_incident_query().where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    report, _ = generate_report(db, incident, report_format, user)
    record_audit(
        db,
        actor_id=user.id,
        action="REPORT_GENERATE",
        target_type="report",
        target_id=report.id,
        result="SUCCESS",
        details={"format": report.format, "incident_id": incident.id},
    )
    return {
        "id": report.id,
        "format": report.format,
        "file_name": report.file_name,
        "sha256": report.sha256,
        "download_url": f"/api/v1/reports/{report.id}/download",
    }


@router.get("/reports/{report_id}/download", tags=["reports"])
def download_report(
    report_id: str,
    db: DbSession,
    _: Annotated[User, Depends(require_permission("EXPORT_REPORTS"))],
) -> FileResponse:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    root = get_settings().report_dir.resolve()
    path = (root / report.file_name).resolve()
    if path.parent != root or not path.is_file():
        raise HTTPException(status_code=404, detail="Report file not found")
    media_types = {
        "PDF": "application/pdf",
        "JSON": "application/json",
        "CSV": "text/csv",
        "ZIP": "application/zip",
    }
    return FileResponse(path, media_type=media_types[report.format], filename=report.file_name)


@router.get("/coverage", tags=["coverage"])
def coverage(db: DbSession, _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))]) -> dict[str, object]:
    rows = list(db.scalars(select(DetectionCoverage).order_by(DetectionCoverage.executed_at.desc())).all())
    tactics: dict[str, dict[str, int]] = {}
    for row in rows:
        stats = tactics.setdefault(row.tactic, {"PASS": 0, "PARTIAL": 0, "MISS": 0})
        stats[row.status] += 1
    summary = []
    for tactic, stats in tactics.items():
        total = sum(stats.values())
        percent = round((stats["PASS"] + stats["PARTIAL"] * 0.5) / total * 100) if total else 0
        summary.append({"tactic": tactic, "coverage_percent": percent, **stats})
    return {
        "scope": "Controlled tests executed in this GhostSOC instance only",
        "summary": summary,
        "tests": [
            {
                "scenario_id": row.scenario_id,
                "technique_id": row.technique_id,
                "tactic": row.tactic,
                "status": row.status,
                "expected_detection": row.expected_detection,
                "observed_alert_id": row.observed_alert_id,
                "executed_at": row.executed_at,
            }
            for row in rows
        ],
    }


@router.get("/dashboard", tags=["dashboard"])
def dashboard(db: DbSession, _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))]) -> dict[str, object]:
    active_states = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT_PENDING"]
    recent_events = list(db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(8)).all())
    recent_incidents = list(db.scalars(select(Incident).order_by(Incident.updated_at.desc()).limit(6)).all())
    coverage_data = coverage(db, _)
    now = datetime.now(UTC)
    minute = now - timedelta(seconds=60)
    day = now - timedelta(hours=24)
    active_incidents = (
        db.scalar(select(func.count()).select_from(Incident).where(Incident.status.in_(active_states))) or 0
    )
    critical_incidents = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(active_states), Incident.severity == "CRITICAL")
        )
        or 0
    )
    high_incidents = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(active_states), Incident.severity == "HIGH")
        )
        or 0
    )
    events_minute = (
        db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.timestamp >= minute)) or 0
    )
    requests_minute = db.scalar(select(func.count()).select_from(WebRequest).where(WebRequest.timestamp >= minute)) or 0
    live_attacks = (
        db.scalar(
            select(func.count())
            .select_from(AttackDetection)
            .where(AttackDetection.last_seen >= now - timedelta(minutes=15))
        )
        or 0
    )
    detected_attacks = (
        db.scalar(select(func.count()).select_from(AttackDetection).where(AttackDetection.last_seen >= day)) or 0
    )
    confirmed_responses = (
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
    return {
        "metrics": {
            "active_threats": active_incidents,
            "critical_incidents": critical_incidents,
            "high_incidents": high_incidents,
            "critical_alerts": db.scalar(select(func.count()).select_from(Alert).where(Alert.severity == "CRITICAL"))
            or 0,
            "hosts": db.scalar(
                select(func.count(func.distinct(SecurityEvent.host))).where(SecurityEvent.host.is_not(None))
            )
            or 0,
            "events": db.scalar(select(func.count()).select_from(SecurityEvent)) or 0,
            "events_per_sec": round(events_minute / 60, 2),
            "requests_per_sec": round(requests_minute / 60, 2),
            "live_attacks": live_attacks,
            "detected_attacks": detected_attacks,
            "contained_confirmed": confirmed_responses,
            "active_investigations": db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(Incident.status.in_(["TRIAGED", "INVESTIGATING", "CONTAINMENT_PENDING"]))
            )
            or 0,
        },
        "events": [EventView.model_validate(item) for item in recent_events],
        "incidents": [
            {
                "id": item.id,
                "title": item.title,
                "severity": item.severity,
                "risk_level": item.risk_level,
                "risk_score": item.risk_score,
                "status": item.status,
                "updated_at": item.updated_at,
            }
            for item in recent_incidents
        ],
        "coverage": coverage_data["summary"],
    }


@router.post("/demo/run", tags=["demo"])
def run_demo(
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_permission("APPROVE_RESPONSE"))],
) -> dict[str, object]:
    settings = get_settings()
    if not settings.demo_mode:
        raise HTTPException(status_code=403, detail="Demo mode is disabled")
    # Packaged resource works in the installed wheel, local source and Docker image.
    fixture = files("app").joinpath("data/powershell-event.json")
    payload_data = json.loads(fixture.read_text(encoding="utf-8"))
    # Permit repetition without reset while preserving source-fixture identity in metadata.
    payload_data["event_id"] = f"demo-sysmon-{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"
    payload_data["timestamp"] = datetime.now(UTC).isoformat()
    event, _, alert_count, incident_ids = ingest_event(db, EventCreate.model_validate(payload_data))
    if not incident_ids:
        raise HTTPException(status_code=500, detail="Demo detection did not produce an incident")
    incident = db.scalar(_incident_query().where(Incident.id == incident_ids[0]))
    if incident is None:
        raise HTTPException(status_code=500, detail="Demo incident not found")
    cti_ioc = next((item for item in incident.iocs if item.ioc_type == "DOMAIN"), incident.iocs[0])
    demo_cti = {
        "provider": "GhostSOC Controlled Fixture",
        "indicator": cti_ioc.value,
        "indicator_type": cti_ioc.ioc_type,
        "status": "SUCCESS",
        "verdict": "MALICIOUS",
        "confidence": 0.95,
        "summary": "Deterministic demo-only enrichment; no external provider was called",
        "reference": "fixture:demo/powershell-event.json",
        "attributes": {"controlled_fixture": True},
        "mock": True,
    }
    cti_ioc.enrichment = [demo_cti]
    cti_ioc.verdict = "MALICIOUS"
    cti_ioc.confidence = 0.95
    db.commit()
    incident = recalculate_risk(db, incident)
    alert = incident.alerts[0]
    coverage_row = DetectionCoverage(
        scenario_id=f"demo-{event.id}",
        technique_id="T1059.001",
        tactic="Execution",
        status="PASS",
        expected_detection="GS-SIGMA-001",
        observed_alert_id=alert.id,
    )
    db.add(coverage_row)
    db.commit()
    evidence_ids = [
        collect_evidence(db, incident, evidence_type, "demo-endpoint-01", user).id
        for evidence_type in ("ENDPOINT_TRIAGE", "YARA_SCAN", "NETWORK_CONTEXT")
    ]
    key_prefix = f"demo:{event.id}"
    collect_action, _ = create_action(
        db,
        ResponseRequest(
            incident_id=incident.id,
            action_type="COLLECT_EVIDENCE",
            target="demo-endpoint-01",
            idempotency_key=f"{key_prefix}:collect",
        ),
        user,
    )
    isolate_action, _ = create_action(
        db,
        ResponseRequest(
            incident_id=incident.id,
            action_type="ISOLATE_ENDPOINT",
            target="demo-endpoint-01",
            idempotency_key=f"{key_prefix}:isolate",
        ),
        user,
    )
    isolate_action = decide_action(db, isolate_action, user, "APPROVED", "Approved controlled demo isolation")
    incident = db.scalar(_incident_query().where(Incident.id == incident.id))
    reports = {}
    for report_format in ("pdf", "json", "csv", "zip"):
        report, _ = generate_report(db, incident, report_format, user)
        reports[report_format] = {"id": report.id, "sha256": report.sha256}
    record_audit(
        db,
        actor_id=user.id,
        action="DEMO_RUN",
        target_type="incident",
        target_id=incident.id,
        result="SUCCESS",
        correlation_id=_correlation_id(request),
        details={"fixture": "powershell-event.json", "safe_simulation": True},
    )
    return {
        "status": "SUCCESS",
        "safe_simulation": True,
        "external_actions_executed": False,
        "incident_id": incident.id,
        "steps": {
            "event_ingestion": event.id,
            "normalization": "PASS",
            "detection": f"PASS ({alert_count} alert)",
            "alert": alert.id,
            "mitre": "T1059.001",
            "cti": "DEMO_MOCK clearly attributed",
            "correlation": incident.correlation_key,
            "incident": incident.id,
            "risk": {"level": incident.risk_level, "score": incident.risk_score},
            "evidence": evidence_ids,
            "response_policy": "Safe default",
            "dry_run": collect_action.execution_status,
            "approval": isolate_action.approval_status,
            "containment": isolate_action.execution_status,
            "audit": "RECORDED",
            "reports": reports,
        },
    }


@router.post("/demo/reset", tags=["demo"])
def reset_demo(
    db: DbSession,
    user: Annotated[User, Depends(require_permission("MANAGE_CONNECTORS"))],
) -> dict[str, object]:
    settings = get_settings()
    if not settings.demo_mode:
        raise HTTPException(status_code=403, detail="Demo mode is disabled")
    report_files = list(db.scalars(select(Report.file_name)).all())
    # Explicit deletion order preserves users, policies, rules, connector health, and non-demo configuration.
    for model in (
        Report,
        InvestigationRecommendation,
        MemoryExperience,
        ResponseAction,
        Evidence,
        TimelineEvent,
        IOC,
        DetectionCoverage,
        AttackDetection,
        Alert,
        Incident,
        WebRequest,
        SecurityEvent,
    ):
        db.execute(delete(model))
    record_audit(
        db,
        actor_id=user.id,
        action="DEMO_RESET",
        target_type="demo_data",
        target_id=None,
        result="SUCCESS",
        commit=False,
    )
    db.commit()
    root = settings.report_dir.resolve()
    removed = 0
    for name in report_files:
        path = (root / name).resolve()
        if path.parent == root and path.name.startswith("GhostSOC-Incident-") and path.is_file():
            path.unlink()
            removed += 1
    return {"status": "RESET", "report_files_removed": removed}
