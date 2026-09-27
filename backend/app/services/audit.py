from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AuditLog


def record_audit(
    db: Session,
    *,
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str | None,
    result: str,
    correlation_id: str | None = None,
    source_ip: str | None = None,
    details: dict[str, object] | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        result=result,
        correlation_id=correlation_id,
        source_ip=source_ip,
        details=details or {},
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry
