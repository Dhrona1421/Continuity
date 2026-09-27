"""Authorized organizational memory API. No response execution path."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.dependencies import DbSession, require_permission
from app.core.config import get_settings
from app.models import Incident, InvestigationRecommendation, MemoryExperience, User
from app.services import hindsight
from app.services.audit import record_audit

router = APIRouter(prefix="/api/v1", tags=["security-memory"])


class LessonInput(BaseModel):
    lesson: str = Field(min_length=3, max_length=1000)
    condition: str = Field(default="", max_length=1000)
    recommended_behavior: str = Field(default="", max_length=1000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    source_incident: str | None = None


class RetainInput(BaseModel):
    incident_id: str
    outcome: str = Field(min_length=3, max_length=2000)
    root_cause: str | None = Field(default=None, max_length=2000)
    initial_hypothesis: str | None = Field(default=None, max_length=1000)
    investigation_steps: list[str] = Field(default_factory=list, max_length=30)
    failed_paths: list[str] = Field(default_factory=list, max_length=30)
    successful_paths: list[str] = Field(default_factory=list, max_length=30)
    important_evidence: list[str] = Field(default_factory=list, max_length=30)
    reasoning: str = Field(default="", max_length=2000)
    side_effects: list[str] = Field(default_factory=list, max_length=20)
    response_result: str = Field(default="No verified external action", max_length=2000)
    lessons: list[LessonInput] = Field(default_factory=list, max_length=20)


class RecallInput(BaseModel):
    incident_id: str
    limit: int = Field(default=5, ge=1, le=10)


class SearchInput(BaseModel):
    query: str = Field(min_length=2, max_length=1000)
    limit: int = Field(default=10, ge=1, le=20)

    @model_validator(mode="after")
    def validate_query(self):
        self.query = self.query.strip()
        if len(self.query) < 2:
            raise ValueError("query must contain at least two non-space characters")
        return self


class LearnInput(BaseModel):
    incident_id: str
    recommendation_id: str | None = None
    decision: Literal["accepted", "modified", "rejected"]
    reason: str = Field(min_length=3, max_length=2000)
    modification: str | None = Field(default=None, max_length=2000)
    outcome: str | None = Field(default=None, max_length=2000)
    lesson: LessonInput | None = None

    @model_validator(mode="after")
    def validate_decision(self):
        if self.decision == "modified" and not self.modification:
            raise ValueError("modification is required for a modified decision")
        return self


class UpdateInput(BaseModel):
    memory_id: str
    expected_version: int = Field(ge=1)
    annotation: str = Field(min_length=3, max_length=2000)
    correction_reason: str = Field(min_length=3, max_length=500)


def incident_or_404(db: DbSession, incident_id: str) -> Incident:
    incident = db.scalar(select(Incident).options(
        selectinload(Incident.alerts), selectinload(Incident.iocs), selectinload(Incident.evidence),
        selectinload(Incident.timeline), selectinload(Incident.response_actions),
    ).where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/incidents/{incident_id}/experience")
def incident_experience(
    incident_id: str,
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
):
    """Source-authored experience for this incident, never presented as recalled history."""
    incident_or_404(db, incident_id)
    row = db.scalar(select(MemoryExperience).where(MemoryExperience.incident_id == incident_id))
    if row is None:
        return {"status": "not_recorded", "provider_status": "not_recorded", "experience": None}
    return {"status": "recorded", "provider_status": row.status.lower(), "experience": row.experience}


@router.get("/memory/status")
def memory_status(
    db: DbSession,
    _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))],
):
    """Report configuration and the timestamped last retain outcome, not a live health claim."""
    settings = get_settings()
    latest = db.scalar(select(MemoryExperience).order_by(MemoryExperience.updated_at.desc()).limit(1))
    last_operation = "not_recorded"
    if latest is not None:
        last_operation = {"RETAINED": "retained", "UNAVAILABLE": "unavailable"}.get(
            latest.status, latest.status.lower())
    return {
        "provider": "Hindsight",
        "configured": bool(settings.hindsight_url and settings.hindsight_api_key),
        "last_operation": last_operation,
        "updated_at": latest.updated_at if latest is not None else None,
    }


@router.post("/memory/retain")
def retain(payload: RetainInput, db: DbSession,
           user: Annotated[User, Depends(require_permission("MANAGE_INCIDENTS"))]):
    incident = incident_or_404(db, payload.incident_id)
    for lesson in payload.lessons:
        if lesson.source_incident not in (None, incident.id):
            raise HTTPException(status_code=422, detail="Lesson source must be the current incident")
        lesson.source_incident = incident.id
    changes = {"incident": {"outcome": payload.outcome, "root_cause": payload.root_cause},
               "investigation": {"initial_hypothesis": payload.initial_hypothesis,
                                 "steps": payload.investigation_steps, "failed_paths": payload.failed_paths,
                                 "successful_paths": payload.successful_paths,
                                 "important_evidence": payload.important_evidence, "reasoning": payload.reasoning},
               "response": {"side_effects": payload.side_effects, "result": payload.response_result},
               "lessons": [lesson.model_dump() for lesson in payload.lessons]}
    result = hindsight.retain(db, incident, amendments=changes)
    record_audit(db, actor_id=user.id, action="MEMORY_RETAIN", target_type="incident",
                 target_id=incident.id, result=result["status"].upper())
    return result


@router.post("/memory/recall")
def recall(payload: RecallInput, db: DbSession,
           _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))]):
    return hindsight.recall(db, incident_or_404(db, payload.incident_id), payload.limit)


@router.post("/memory/search")
def search_memory(payload: SearchInput, db: DbSession,
                  _: Annotated[User, Depends(require_permission("VIEW_EVENTS"))]):
    """Query Hindsight; source records are shown only when provider provenance matches."""
    return hindsight.search(db, payload.query.strip(), payload.limit)


@router.post("/memory/learn")
def learn(payload: LearnInput, db: DbSession,
          user: Annotated[User, Depends(require_permission("RUN_INVESTIGATION"))]):
    incident = incident_or_404(db, payload.incident_id)
    if payload.recommendation_id:
        recommendation = db.get(InvestigationRecommendation, payload.recommendation_id)
        if recommendation is None or recommendation.incident_id != incident.id:
            raise HTTPException(status_code=422, detail="Recommendation does not belong to incident")
    if payload.lesson and payload.lesson.source_incident not in (None, incident.id):
        raise HTTPException(status_code=422, detail="Lesson source must be the current incident")
    feedback = payload.model_dump(exclude_none=True)
    if feedback.get("lesson"):
        feedback["lesson"]["source_incident"] = incident.id
    feedback["analyst_id"] = user.id
    if payload.recommendation_id:
        feedback["recommendation_steps"] = recommendation.content.get("steps", [])[:15]
    result = hindsight.learn(db, incident, feedback)
    record_audit(db, actor_id=user.id, action="MEMORY_LEARN", target_type="incident",
                 target_id=incident.id, result=result["status"].upper(), details={"decision": payload.decision})
    return result


@router.post("/memory/update")
def update(payload: UpdateInput, db: DbSession,
           user: Annotated[User, Depends(require_permission("MANAGE_INCIDENTS"))]):
    row = db.get(MemoryExperience, payload.memory_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Memory source not found")
    changes = {"lessons": [{"lesson": payload.annotation, "condition": "Analyst correction",
                            "recommended_behavior": payload.annotation, "confidence": None,
                            "source_incident": row.incident_id, "reason": payload.correction_reason}]}
    result = hindsight.update(db, row, changes, payload.expected_version)
    record_audit(db, actor_id=user.id, action="MEMORY_UPDATE", target_type="incident",
                 target_id=row.incident_id, result=result["status"].upper())
    return result
