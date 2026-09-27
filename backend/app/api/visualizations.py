from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from app.api.dependencies import DbSession, require_permission
from app.models import (
    IOC,
    Alert,
    AttackDetection,
    Incident,
    ResponseAction,
    SecurityEvent,
    User,
    WebRequest,
)

router = APIRouter(prefix="/api/v1")
SEVERITY_VALUE = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RANGES = {
    "15m": (timedelta(minutes=15), timedelta(minutes=1)),
    "1h": (timedelta(hours=1), timedelta(minutes=5)),
    "24h": (timedelta(hours=24), timedelta(hours=1)),
    "7d": (timedelta(days=7), timedelta(hours=6)),
}


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _max_severity(left: str, right: str) -> str:
    return right if SEVERITY_VALUE.get(right, 0) > SEVERITY_VALUE.get(left, 0) else left


def _range(value: str) -> tuple[datetime, timedelta]:
    duration, bucket = RANGES[value]
    return datetime.now(UTC) - duration, bucket


def _bucket(value: datetime, start: datetime, bucket: timedelta) -> int:
    return max(0, int((_utc(value) - start).total_seconds() // bucket.total_seconds()))


@router.get("/visualizations/trends", tags=["visualizations"])
def security_trends(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    time_range: Literal["15m", "1h", "24h", "7d"] = Query(default="24h", alias="range"),
) -> dict[str, object]:
    start, bucket_size = _range(time_range)
    now = datetime.now(UTC)
    count = max(1, int((now - start).total_seconds() // bucket_size.total_seconds()) + 1)
    buckets = [
        {
            "timestamp": (start + bucket_size * index).isoformat(),
            "events": 0,
            "attacks": 0,
            "incidents": 0,
            "responses": 0,
        }
        for index in range(count)
    ]
    events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.timestamp >= start)).all())
    attacks = list(db.scalars(select(AttackDetection).where(AttackDetection.last_seen >= start)).all())
    incidents = list(db.scalars(select(Incident).where(Incident.created_at >= start)).all())
    responses = list(db.scalars(select(ResponseAction).where(ResponseAction.requested_at >= start)).all())
    for item in events:
        buckets[min(_bucket(item.timestamp, start, bucket_size), count - 1)]["events"] += 1
    for item in attacks:
        buckets[min(_bucket(item.last_seen, start, bucket_size), count - 1)]["attacks"] += item.request_count
    for item in incidents:
        buckets[min(_bucket(item.created_at, start, bucket_size), count - 1)]["incidents"] += 1
    for item in responses:
        buckets[min(_bucket(item.requested_at, start, bucket_size), count - 1)]["responses"] += 1
    severity: dict[str, int] = defaultdict(int)
    attack_types: dict[str, int] = defaultdict(int)
    confidence_bands = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for item in attacks:
        severity[item.severity] += 1
        attack_types[item.attack_type] += item.request_count
        band = "HIGH" if item.confidence >= 0.8 else "MEDIUM" if item.confidence >= 0.5 else "LOW"
        confidence_bands[band] += 1
    response_states: dict[str, int] = defaultdict(int)
    for item in responses:
        response_states[item.execution_status] += 1
    return {
        "range": time_range,
        "bucket_seconds": int(bucket_size.total_seconds()),
        "series": buckets,
        "severity_distribution": dict(severity),
        "attack_type_distribution": sorted(
            ({"label": key, "value": value} for key, value in attack_types.items()),
            key=lambda item: item["value"],
            reverse=True,
        )[:10],
        "confidence_distribution": confidence_bands,
        "response_distribution": dict(response_states),
        "generated_at": now.isoformat(),
    }


def _node(
    nodes: dict[str, dict[str, Any]],
    node_id: str,
    label: str,
    node_type: str,
    *,
    status: str = "OBSERVED",
    severity: str = "INFO",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    if node_id not in nodes:
        nodes[node_id] = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "status": status,
            "severity": severity,
            "risk": severity,
            "event_count": 0,
            "alert_count": 0,
            "connections": set(),
            "last_activity": timestamp.isoformat() if timestamp else None,
            "incident_ids": set(),
            "details": {},
        }
    item = nodes[node_id]
    item["severity"] = _max_severity(item["severity"], severity)
    item["risk"] = item["severity"]
    if timestamp and (
        item["last_activity"] is None or _utc(timestamp) > _utc(datetime.fromisoformat(item["last_activity"]))
    ):
        item["last_activity"] = timestamp.isoformat()
    return item


def _edge(
    edges: dict[str, dict[str, Any]],
    source: str,
    target: str,
    *,
    protocol: str,
    port: int | None,
    timestamp: datetime,
) -> dict[str, Any]:
    edge_id = hashlib.sha256(f"{source}|{target}|{protocol}|{port}".encode()).hexdigest()[:20]
    if edge_id not in edges:
        edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "protocol": protocol,
            "port": port,
            "event_count": 0,
            "traffic_bytes": 0,
            "last_activity": timestamp.isoformat(),
            "severity": "INFO",
            "status": "OBSERVED",
            "alert_count": 0,
            "attack_types": set(),
            "incident_ids": set(),
        }
    return edges[edge_id]


def _ip_type(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        return "endpoint" if address.is_private else "external_source"
    except ValueError:
        return "host"


@router.get("/visualizations/network", tags=["visualizations"])
def network_topology(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    range: Literal["15m", "1h", "24h", "7d"] = "24h",
) -> dict[str, object]:
    start, _ = _range(range)
    requests = list(
        db.scalars(
            select(WebRequest).where(WebRequest.timestamp >= start).order_by(WebRequest.timestamp.desc()).limit(5000)
        ).all()
    )
    attacks = list(db.scalars(select(AttackDetection).where(AttackDetection.last_seen >= start)).all())
    network_events = list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.timestamp >= start, SecurityEvent.src_ip.is_not(None))
            .order_by(SecurityEvent.timestamp.desc())
            .limit(5000)
        ).all()
    )
    attack_lookup: dict[tuple[str, str], list[AttackDetection]] = defaultdict(list)
    for attack in attacks:
        attack_lookup[(attack.source_ip, attack.target_host)].append(attack)
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    for request in requests:
        source_id = f"ip:{request.source_ip}"
        target_id = f"host:{request.target_host}"
        related = attack_lookup.get((request.source_ip, request.target_host), [])
        severity = "INFO"
        for attack in related:
            severity = _max_severity(severity, attack.severity)
        source = _node(
            nodes,
            source_id,
            request.source_ip,
            "external_source",
            status="SUSPICIOUS" if related else "OBSERVED",
            severity=severity,
            timestamp=request.timestamp,
        )
        target = _node(
            nodes,
            target_id,
            request.target_host,
            "web_server",
            status="UNDER_ATTACK" if related else "ONLINE",
            severity=severity,
            timestamp=request.timestamp,
        )
        edge = _edge(edges, source_id, target_id, protocol="HTTPS", port=443, timestamp=request.timestamp)
        edge["event_count"] += 1
        edge["traffic_bytes"] += request.response_bytes or 0
        edge["last_activity"] = max(edge["last_activity"], request.timestamp.isoformat())
        source["event_count"] += 1
        target["event_count"] += 1
        source["connections"].add(target_id)
        target["connections"].add(source_id)
        for attack in related:
            edge["severity"] = _max_severity(edge["severity"], attack.severity)
            edge["status"] = "SUSPICIOUS"
            edge["attack_types"].add(attack.attack_type)
            edge["alert_count"] = max(edge["alert_count"], len(related))
            source["alert_count"] = max(source["alert_count"], len(related))
            target["alert_count"] = max(target["alert_count"], len(related))
            if attack.incident_id:
                edge["incident_ids"].add(attack.incident_id)
                source["incident_ids"].add(attack.incident_id)
                target["incident_ids"].add(attack.incident_id)
    for event in network_events:
        if not event.dst_ip:
            continue
        source_label = event.host or event.src_ip or "unknown"
        source_id = f"asset:{source_label}"
        target_id = f"ip:{event.dst_ip}"
        source = _node(
            nodes,
            source_id,
            source_label,
            "endpoint" if event.host else _ip_type(event.src_ip or ""),
            severity=event.severity,
            timestamp=event.timestamp,
        )
        target = _node(
            nodes,
            target_id,
            event.dst_ip,
            _ip_type(event.dst_ip),
            severity=event.severity,
            timestamp=event.timestamp,
        )
        edge = _edge(
            edges,
            source_id,
            target_id,
            protocol=str(event.event_metadata.get("proto") or "TCP").upper(),
            port=event.dst_port,
            timestamp=event.timestamp,
        )
        edge["event_count"] += 1
        edge["severity"] = _max_severity(edge["severity"], event.severity)
        source["event_count"] += 1
        target["event_count"] += 1
        source["connections"].add(target_id)
        target["connections"].add(source_id)
    serialized_nodes = []
    for item in nodes.values():
        item["connections"] = len(item["connections"])
        item["incident_ids"] = sorted(item["incident_ids"])
        item["details"] = {
            "events": item["event_count"],
            "alerts": item["alert_count"],
            "connections": item["connections"],
        }
        serialized_nodes.append(item)
    serialized_edges = []
    for item in edges.values():
        item["attack_types"] = sorted(item["attack_types"])
        item["incident_ids"] = sorted(item["incident_ids"])
        serialized_edges.append(item)
    return {
        "range": range,
        "nodes": serialized_nodes,
        "edges": serialized_edges,
        "summary": {
            "nodes": len(serialized_nodes),
            "connections": len(serialized_edges),
            "suspicious_connections": sum(1 for item in serialized_edges if item["status"] == "SUSPICIOUS"),
            "events": sum(item["event_count"] for item in serialized_edges),
        },
        "generated_at": datetime.now(UTC).isoformat(),
    }


@router.get("/visualizations/attack-graph", tags=["visualizations"])
def attack_graph(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    range: Literal["15m", "1h", "24h", "7d"] = "24h",
    incident_id: str | None = None,
) -> dict[str, object]:
    start, _ = _range(range)
    query = select(AttackDetection).where(AttackDetection.last_seen >= start)
    if incident_id:
        query = query.where(AttackDetection.incident_id == incident_id)
    attacks = list(db.scalars(query.order_by(AttackDetection.last_seen.desc()).limit(250)).all())
    nodes: dict[str, dict[str, Any]] = {}
    edge_counts: dict[tuple[str, str, str], dict[str, Any]] = {}
    for attack in attacks:
        source_id = f"source:{attack.source_ip}"
        attack_id = f"attack:{attack.attack_type}"
        endpoint_id = f"endpoint:{attack.target_host}:{attack.endpoint}"
        target_id = f"target:{attack.target_host}"
        incident_node_id = f"incident:{attack.incident_id}" if attack.incident_id else None
        _node(
            nodes,
            source_id,
            attack.source_ip,
            "source",
            status=attack.classification,
            severity=attack.severity,
            timestamp=attack.last_seen,
        )
        _node(
            nodes,
            attack_id,
            attack.attack_type,
            "attack",
            status=attack.classification,
            severity=attack.severity,
            timestamp=attack.last_seen,
        )
        _node(
            nodes,
            endpoint_id,
            attack.endpoint,
            "endpoint",
            status="TARGETED",
            severity=attack.severity,
            timestamp=attack.last_seen,
        )
        _node(
            nodes,
            target_id,
            attack.target_host,
            "target",
            status="UNDER_ATTACK",
            severity=attack.severity,
            timestamp=attack.last_seen,
        )
        if incident_node_id:
            incident = db.get(Incident, attack.incident_id)
            _node(
                nodes,
                incident_node_id,
                f"Incident {attack.incident_id[:8]}",
                "incident",
                status=incident.status if incident else "UNKNOWN",
                severity=incident.severity if incident else attack.severity,
                timestamp=attack.last_seen,
            )
            for node_id in (source_id, attack_id, endpoint_id, target_id, incident_node_id):
                nodes[node_id]["incident_ids"].add(attack.incident_id)
        for source, target, relationship in (
            (source_id, attack_id, "generated"),
            (attack_id, endpoint_id, "targeted"),
            (endpoint_id, target_id, "served_by"),
            (attack_id, incident_node_id, "correlated_to") if incident_node_id else (None, None, None),
        ):
            if source is None:
                continue
            key = (source, target, relationship)
            edge = edge_counts.setdefault(
                key,
                {
                    "id": hashlib.sha256("|".join(key).encode()).hexdigest()[:20],
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                    "event_count": 0,
                    "severity": attack.severity,
                    "last_activity": attack.last_seen.isoformat(),
                },
            )
            edge["event_count"] += attack.request_count
            edge["severity"] = _max_severity(edge["severity"], attack.severity)
    for item in nodes.values():
        item["connections"] = 0
        item["incident_ids"] = sorted(item["incident_ids"])
    for edge in edge_counts.values():
        if edge["source"] in nodes:
            nodes[edge["source"]]["connections"] += 1
        if edge["target"] in nodes:
            nodes[edge["target"]]["connections"] += 1
    return {
        "range": range,
        "nodes": list(nodes.values()),
        "edges": list(edge_counts.values()),
        "summary": {"attacks": len(attacks), "nodes": len(nodes), "relationships": len(edge_counts)},
    }


@router.get("/visualizations/incidents/{incident_id}", tags=["visualizations"])
def incident_graph(
    incident_id: str,
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
) -> dict[str, object]:
    incident = db.scalar(
        select(Incident)
        .options(
            selectinload(Incident.alerts),
            selectinload(Incident.iocs),
            selectinload(Incident.evidence),
            selectinload(Incident.timeline),
            selectinload(Incident.response_actions),
        )
        .where(Incident.id == incident_id)
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    attacks = list(db.scalars(select(AttackDetection).where(AttackDetection.incident_id == incident.id)).all())
    event_ids = {alert.event_id for alert in incident.alerts}
    for attack in attacks:
        event_ids.update(attack.related_event_ids)
    if attacks:
        sources = {item.source_ip for item in attacks}
        targets = {item.target_host for item in attacks}
        start = min(_utc(item.first_seen) for item in attacks) - timedelta(minutes=5)
        end = max(_utc(item.last_seen) for item in attacks) + timedelta(minutes=5)
        related_requests = db.scalars(
            select(WebRequest).where(
                WebRequest.source_ip.in_(sources),
                WebRequest.target_host.in_(targets),
                WebRequest.timestamp >= start,
                WebRequest.timestamp <= end,
            )
        ).all()
        event_ids.update(item.security_event_id for item in related_requests if item.security_event_id)
    events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))).all()) if event_ids else []
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    root = f"incident:{incident.id}"
    nodes.append(
        {
            "id": root,
            "label": incident.title,
            "type": "incident",
            "status": incident.status,
            "severity": incident.severity,
            "risk": incident.risk_level,
            "details": {
                "risk_score": incident.risk_score,
                "risk_reasons": incident.risk_reasons,
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
            },
        }
    )

    def add_node(
        node_id: str, label: str, node_type: str, relationship: str, details: dict[str, Any], severity: str = "INFO"
    ):
        if not any(item["id"] == node_id for item in nodes):
            nodes.append(
                {
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "status": details.get("status", "OBSERVED"),
                    "severity": severity,
                    "risk": severity,
                    "details": details,
                }
            )
        edge_key = f"{root}|{node_id}|{relationship}"
        if not any(item["id"] == hashlib.sha256(edge_key.encode()).hexdigest()[:20] for item in edges):
            edges.append(
                {
                    "id": hashlib.sha256(edge_key.encode()).hexdigest()[:20],
                    "source": root,
                    "target": node_id,
                    "relationship": relationship,
                    "event_count": details.get("event_count", 1),
                    "severity": severity,
                }
            )

    for ioc in incident.iocs:
        add_node(
            f"ioc:{ioc.id}",
            ioc.value,
            "source" if ioc.ioc_type == "IP" else "ioc",
            "has_ioc",
            {
                "ioc_type": ioc.ioc_type,
                "verdict": ioc.verdict,
                "confidence": ioc.confidence,
                "enrichment": ioc.enrichment,
            },
            "HIGH" if ioc.verdict in {"MALICIOUS", "SIMULATED"} else "INFO",
        )
    alert_groups: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    for alert in incident.alerts:
        alert_groups[(alert.rule_id, alert.title)].append(alert)
    for (rule_id, title), grouped_alerts in alert_groups.items():
        severity = "INFO"
        for alert in grouped_alerts:
            severity = _max_severity(severity, alert.severity)
        add_node(
            f"alert-rule:{rule_id}",
            title,
            "alert",
            "has_alert",
            {
                "rule_id": rule_id,
                "event_count": len(grouped_alerts),
                "confidence": max(item.confidence for item in grouped_alerts),
                "evidence_references": [item.evidence_reference for item in grouped_alerts],
                "event_ids": [item.event_id for item in grouped_alerts],
            },
            severity,
        )
        for technique in {technique for item in grouped_alerts for technique in item.mitre_techniques}:
            add_node(
                f"mitre:{technique}",
                technique,
                "mitre",
                "mapped_to",
                {"technique_id": technique},
                "INFO",
            )
    host_counts: dict[str, int] = defaultdict(int)
    user_counts: dict[str, int] = defaultdict(int)
    for event in events:
        if event.host:
            host_counts[event.host] += 1
        if event.username:
            user_counts[event.username] += 1
    for host, count in host_counts.items():
        add_node(f"host:{host}", host, "host", "affected_host", {"event_count": count}, incident.severity)
    for username, count in user_counts.items():
        add_node(f"user:{username}", username, "user", "related_user", {"event_count": count})
    if events:
        add_node(
            f"events:{incident.id}",
            f"{len(events)} related events",
            "event_group",
            "contains_events",
            {"event_count": len(events), "event_ids": [item.id for item in events]},
            incident.severity,
        )
    for evidence in incident.evidence:
        add_node(
            f"evidence:{evidence.id}",
            evidence.summary,
            "evidence",
            "has_evidence",
            {"source": evidence.source, "sha256": evidence.sha256, "reference": evidence.reference},
        )
    for response in incident.response_actions:
        add_node(
            f"response:{response.id}",
            response.action_type.replace("_", " "),
            "response",
            "has_response",
            {
                "target": response.target,
                "status": response.execution_status,
                "dry_run": response.dry_run,
                "result": response.execution_result,
            },
            "INFO" if response.dry_run else "HIGH",
        )
    return {
        "incident_id": incident.id,
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "nodes": len(nodes),
            "relationships": len(edges),
            "events": len(events),
            "alerts": len(incident.alerts),
            "iocs": len(incident.iocs),
        },
    }


@router.get("/search/global", tags=["search"])
def global_search(
    db: DbSession,
    user: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
    q: str = Query(min_length=2, max_length=200),
    limit: int = Query(default=30, ge=1, le=100),
) -> dict[str, object]:
    term = f"%{q}%"
    results: list[dict[str, object]] = []

    def add(
        result_type: str,
        identifier: str,
        title: str,
        subtitle: str,
        page: str,
        severity: str = "INFO",
        status: str | None = None,
    ):
        if len(results) < limit:
            results.append(
                {
                    "type": result_type,
                    "id": identifier,
                    "title": title,
                    "subtitle": subtitle,
                    "page": page,
                    "severity": severity,
                    "status": status,
                }
            )

    for item in db.scalars(
        select(Incident)
        .where(or_(Incident.title.ilike(term), Incident.description.ilike(term), Incident.id.ilike(term)))
        .order_by(Incident.updated_at.desc())
        .limit(limit)
    ):
        add(
            "INCIDENT",
            item.id,
            item.title,
            f"Risk {item.risk_level} · {item.status}",
            "Incidents",
            item.severity,
            item.status,
        )
    for item in db.scalars(
        select(AttackDetection)
        .where(
            or_(
                AttackDetection.attack_type.ilike(term),
                AttackDetection.source_ip.ilike(term),
                AttackDetection.target_host.ilike(term),
                AttackDetection.endpoint.ilike(term),
                AttackDetection.rule_id.ilike(term),
            )
        )
        .order_by(AttackDetection.last_seen.desc())
        .limit(limit)
    ):
        add(
            "ATTACK",
            item.id,
            item.attack_type,
            f"{item.source_ip} → {item.target_host}{item.endpoint}",
            "Attacks",
            item.severity,
            item.classification,
        )
    for item in db.scalars(
        select(Alert)
        .where(or_(Alert.title.ilike(term), Alert.rule_id.ilike(term)))
        .order_by(Alert.created_at.desc())
        .limit(limit)
    ):
        add("ALERT", item.id, item.title, item.rule_id, "Alerts", item.severity)
    for item in db.scalars(
        select(IOC)
        .where(or_(IOC.value.ilike(term), IOC.ioc_type.ilike(term)))
        .order_by(IOC.created_at.desc())
        .limit(limit)
    ):
        add(
            "IOC",
            item.id,
            item.value,
            f"{item.ioc_type} · {item.verdict}",
            "Threat Intelligence",
            "HIGH" if item.verdict == "MALICIOUS" else "INFO",
            item.verdict,
        )
    for item in db.scalars(
        select(SecurityEvent)
        .where(
            or_(
                SecurityEvent.event_id.ilike(term),
                SecurityEvent.host.ilike(term),
                SecurityEvent.username.ilike(term),
                SecurityEvent.src_ip.ilike(term),
                SecurityEvent.dst_ip.ilike(term),
                SecurityEvent.domain.ilike(term),
                SecurityEvent.file_hash.ilike(term),
                SecurityEvent.event_type.ilike(term),
            )
        )
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
    ):
        add("EVENT", item.id, item.event_type, item.host or item.src_ip or item.source, "Live Monitor", item.severity)
    if user.role == "ADMIN":
        for item in db.scalars(select(User).where(User.email.ilike(term)).limit(limit)):
            add("USER", item.id, item.email, item.role, "Settings", "INFO", "ACTIVE" if item.is_active else "DISABLED")
    unique: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for item in results:
        key = (str(item["type"]), str(item["id"]))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return {"query": q, "count": len(unique), "results": unique[:limit]}
