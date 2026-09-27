from __future__ import annotations

import re
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Incident, ResponseAction, ResponsePolicy, TimelineEvent, User
from app.schemas import ResponseRequest
from app.services.audit import record_audit

ALLOWED_ACTIONS = {
    "COLLECT_EVIDENCE",
    "QUARANTINE_FILE",
    "TERMINATE_PROCESS",
    "BLOCK_IOC",
    "BLOCK_SOURCE",
    "RATE_LIMIT_SOURCE",
    "ISOLATE_ENDPOINT",
}
PROCESS_TARGET = re.compile(r"^(?P<host>[A-Za-z0-9._-]{1,255}):(?P<pid>[1-9][0-9]{0,9})$")
HASH_TARGET = re.compile(r"^(?:sha256:)?[A-Fa-f0-9]{64}$")
RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _validate_target(incident: Incident, action_type: str, target: str, policy: ResponsePolicy) -> None:
    if "\x00" in target or any(char in target for char in (";", "|", "`", "\n", "\r")):
        raise HTTPException(status_code=422, detail="Target contains prohibited characters")
    authorized = set(policy.authorized_targets) | set(get_settings().authorized_targets)
    if action_type in {"COLLECT_EVIDENCE", "ISOLATE_ENDPOINT"}:
        if target not in authorized:
            raise HTTPException(status_code=422, detail="Endpoint target is not authorized by policy")
    elif action_type == "TERMINATE_PROCESS":
        match = PROCESS_TARGET.fullmatch(target)
        if not match or match.group("host") not in authorized:
            raise HTTPException(status_code=422, detail="Process target must be authorized-host:pid")
    elif action_type in {"BLOCK_IOC", "BLOCK_SOURCE", "RATE_LIMIT_SOURCE"}:
        if not any(item.value == target for item in incident.iocs):
            raise HTTPException(status_code=422, detail="Target must be an IOC attached to the incident")
    elif action_type == "QUARANTINE_FILE":
        if not HASH_TARGET.fullmatch(target):
            raise HTTPException(status_code=422, detail="File target must be a SHA-256 artifact identifier")


def _execute_dry_run(action: ResponseAction) -> None:
    action.execution_status = "RUNNING"
    action.execution_result = {
        "mode": "DRY_RUN",
        "adapter": "safe-simulator",
        "executed": False,
        "verified": True,
        "message": f"Validated {action.action_type} for {action.target}; no external change made",
    }
    action.execution_status = "DRY_RUN"
    action.executed_at = datetime.now(UTC)


def create_action(db: Session, request: ResponseRequest, user: User) -> tuple[ResponseAction, bool]:
    existing = db.scalar(select(ResponseAction).where(ResponseAction.idempotency_key == request.idempotency_key))
    if existing:
        if (
            existing.incident_id != request.incident_id
            or existing.action_type != request.action_type
            or existing.target != request.target
        ):
            raise HTTPException(status_code=409, detail="Idempotency key already used for another request")
        return existing, True
    if request.action_type not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=422, detail="Action type is not allowlisted")
    incident = db.get(Incident, request.incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    policy = (
        db.get(ResponsePolicy, request.policy_id)
        if request.policy_id
        else db.scalar(
            select(ResponsePolicy).where(ResponsePolicy.enabled.is_(True)).order_by(ResponsePolicy.created_at)
        )
    )
    if policy is None or not policy.enabled:
        raise HTTPException(status_code=422, detail="No enabled response policy")
    if request.action_type not in policy.allowed_actions:
        raise HTTPException(status_code=403, detail="Response policy does not allow this action")
    if RISK_ORDER.get(incident.risk_level, 0) < RISK_ORDER.get(policy.min_risk_level, 0):
        raise HTTPException(
            status_code=403,
            detail=f"Incident risk {incident.risk_level} is below policy minimum {policy.min_risk_level}",
        )
    _validate_target(incident, request.action_type, request.target, policy)
    preapproved = request.action_type in policy.preapproved_actions
    approval_required = request.action_type in policy.require_approval_actions and not preapproved
    action = ResponseAction(
        incident_id=incident.id,
        action_type=request.action_type,
        target=request.target,
        requested_by=user.id,
        policy_id=policy.id,
        idempotency_key=request.idempotency_key,
        approval_required=approval_required,
        approval_status="PENDING" if approval_required else "APPROVED",
        dry_run=get_settings().dry_run,
        execution_status="PENDING",
    )
    try:
        with db.begin_nested():
            db.add(action)
            db.flush()
    except IntegrityError:
        existing = db.scalar(select(ResponseAction).where(ResponseAction.idempotency_key == request.idempotency_key))
        if existing:
            return existing, True
        raise
    if not approval_required:
        if action.dry_run:
            _execute_dry_run(action)
        else:
            action.execution_status = "FAILED"
            action.execution_result = {
                "executed": False,
                "verified": False,
                "error": "No real response adapter is configured; refusing execution",
            }
    else:
        incident.status = "CONTAINMENT_PENDING"
    incident.timeline.append(
        TimelineEvent(
            event_type="RESPONSE_REQUESTED",
            source="ghostsoc-response",
            summary=f"{request.action_type} requested for validated target",
            reference_id=action.id,
            details={"dry_run": action.dry_run, "approval_required": approval_required},
        )
    )
    record_audit(
        db,
        actor_id=user.id,
        action="RESPONSE_REQUEST",
        target_type="response_action",
        target_id=action.id,
        result="SUCCESS",
        details={"action_type": action.action_type, "dry_run": action.dry_run},
        commit=False,
    )
    db.commit()
    db.refresh(action)
    return action, False


def decide_action(db: Session, action: ResponseAction, user: User, decision: str, reason: str) -> ResponseAction:
    if not action.approval_required:
        raise HTTPException(status_code=409, detail="Action does not require approval")
    if action.approval_status != "PENDING" or action.execution_status != "PENDING":
        raise HTTPException(status_code=409, detail="Action has already been decided or executed")
    action.approval_status = decision
    action.approved_by = user.id
    if decision == "DENIED":
        action.execution_status = "CANCELLED"
    elif action.dry_run:
        _execute_dry_run(action)
    else:
        action.execution_status = "FAILED"
        action.execution_result = {
            "executed": False,
            "verified": False,
            "error": "No real response adapter is configured; refusing execution",
        }
    incident = action.incident
    result = action.execution_result or {}
    if (
        action.execution_status == "SUCCESS"
        and not action.dry_run
        and result.get("executed") is True
        and result.get("verified") is True
    ):
        incident.status = "CONTAINED"
    elif action.execution_status == "DRY_RUN":
        incident.status = "INVESTIGATING"
    incident.timeline.append(
        TimelineEvent(
            event_type="RESPONSE_DECIDED",
            source="ghostsoc-response",
            summary=f"Action {decision.lower()}: {reason}",
            reference_id=action.id,
            details={"execution_status": action.execution_status, "dry_run": action.dry_run},
        )
    )
    record_audit(
        db,
        actor_id=user.id,
        action="RESPONSE_APPROVAL",
        target_type="response_action",
        target_id=action.id,
        result=decision,
        details={"reason": reason, "execution_status": action.execution_status},
        commit=False,
    )
    db.commit()
    db.refresh(action)
    return action
