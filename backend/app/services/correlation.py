from __future__ import annotations

from datetime import UTC

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import IOC, Alert, Incident, SecurityEvent, TimelineEvent

SEVERITY_SCORE = {"INFO": 5, "LOW": 20, "MEDIUM": 40, "HIGH": 70, "CRITICAL": 90}
LEVEL_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _risk(alerts: list[Alert], iocs: list[IOC]) -> tuple[float, str, list[str]]:
    if not alerts:
        return 0, "LOW", ["No detection alerts"]
    reasons: list[str] = []
    top = max(alerts, key=lambda alert: SEVERITY_SCORE.get(alert.severity, 0))
    score = SEVERITY_SCORE.get(top.severity, 20) * 0.55
    reasons.append(f"Highest alert severity: {top.severity}")
    confidence = max(alert.confidence for alert in alerts)
    score += confidence * 25
    reasons.append(f"Detection confidence: {confidence:.0%}")
    if len(alerts) > 1:
        score += min(10, (len(alerts) - 1) * 3)
        reasons.append(f"{len(alerts)} correlated alerts")
    malicious = sum(1 for ioc in iocs if ioc.verdict == "MALICIOUS")
    if malicious:
        score += min(20, malicious * 10)
        reasons.append(f"{malicious} malicious IOC enrichment result(s)")
    score = round(min(100, score), 1)
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level, reasons


def _correlation_key(event: SecurityEvent, alert: Alert) -> str:
    host_or_ioc = event.host or event.src_ip or event.domain or event.file_hash or "unknown"
    technique = alert.mitre_techniques[0] if alert.mitre_techniques else alert.rule_id
    timestamp = event.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    four_hour_bucket = int(timestamp.timestamp()) // (4 * 3600)
    return f"{host_or_ioc}:{technique}:{four_hour_bucket}"[:255]


def _extract_iocs(event: SecurityEvent) -> list[tuple[str, str]]:
    candidates = [
        ("IP", event.src_ip),
        ("IP", event.dst_ip),
        ("DOMAIN", event.domain),
        ("URL", event.url),
        ("HASH", event.file_hash),
    ]
    result: list[tuple[str, str]] = []
    for ioc_type, value in candidates:
        if value and (ioc_type, value) not in result:
            result.append((ioc_type, value))
    return result


def correlate_alert(db: Session, alert: Alert, event: SecurityEvent) -> Incident:
    key = _correlation_key(event, alert)
    incident = db.scalar(select(Incident).where(Incident.correlation_key == key))
    created = False
    if incident is None:
        incident = Incident(
            title=f"{alert.title} on {event.host or event.src_ip or 'unknown asset'}",
            description="Incident created by deterministic host/IOC, technique and four-hour correlation.",
            severity=alert.severity,
            correlation_key=key,
        )
        try:
            with db.begin_nested():
                db.add(incident)
                db.flush()
            created = True
        except IntegrityError:
            incident = db.scalar(select(Incident).where(Incident.correlation_key == key))
            if incident is None:
                raise
    alert.incident = incident
    if LEVEL_ORDER.get(alert.severity, 0) > LEVEL_ORDER.get(incident.severity, 0):
        incident.severity = alert.severity
    for ioc_type, value in _extract_iocs(event):
        exists = next((item for item in incident.iocs if item.ioc_type == ioc_type and item.value == value), None)
        if not exists:
            incident.iocs.append(IOC(ioc_type=ioc_type, value=value, source=event.source))
    incident.timeline.append(
        TimelineEvent(
            event_type="INCIDENT_CREATED" if created else "ALERT_CORRELATED",
            source="ghostsoc-correlation",
            summary=f"Alert {alert.id} {'created' if created else 'joined'} incident",
            reference_id=alert.id,
            timestamp=event.timestamp,
            details={"correlation_key": key, "rule_id": alert.rule_id},
        )
    )
    db.flush()
    score, level, reasons = _risk(list(incident.alerts), list(incident.iocs))
    incident.risk_score = score
    incident.risk_level = level
    incident.risk_reasons = reasons
    db.commit()
    db.refresh(incident)
    return incident


def recalculate_risk(db: Session, incident: Incident) -> Incident:
    score, level, reasons = _risk(list(incident.alerts), list(incident.iocs))
    incident.risk_score = score
    incident.risk_level = level
    incident.risk_reasons = reasons
    db.commit()
    db.refresh(incident)
    return incident
