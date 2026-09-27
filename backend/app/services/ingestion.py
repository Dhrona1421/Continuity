from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import SecurityEvent
from app.schemas import EventCreate
from app.services.correlation import correlate_alert
from app.services.detection import detect_event


def ingest_event(db: Session, payload: EventCreate) -> tuple[SecurityEvent, bool, int, list[str]]:
    values = payload.model_dump()
    values["username"] = values.pop("user")
    values["file_hash"] = values.pop("hash")
    values["file_path"] = values.pop("file")
    values["event_metadata"] = values.pop("metadata")
    event = SecurityEvent(**values)
    try:
        with db.begin_nested():
            db.add(event)
            db.flush()
    except IntegrityError:
        existing = db.scalar(select(SecurityEvent).where(SecurityEvent.event_id == payload.event_id))
        if existing is None:
            raise
        return existing, True, 0, sorted({a.incident_id for a in existing.alerts if a.incident_id})
    db.commit()
    db.refresh(event)
    alerts = detect_event(db, event)
    incidents = [correlate_alert(db, alert, event) for alert in alerts]
    return event, False, len(alerts), sorted({incident.id for incident in incidents})
