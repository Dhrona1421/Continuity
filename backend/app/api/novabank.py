"""Fictional NovaBank dry-run-only scenario using the existing web ingestion pipeline."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from app.api.dependencies import DbSession, require_permission
from app.core.config import get_settings
from app.models import Incident, User
from app.services.audit import record_audit
from app.services.hindsight import retain
from app.services.web_detection import ingest_web_request
from app.web_schemas import WebRequestCreate

router = APIRouter(prefix="/api/v1", tags=["demo"])

LABEL = "Synthetic security incidents inspired by publicly documented attack patterns and incident-response lessons."


@router.post("/demo/novabank")
def load_novabank(db: DbSession, user: Annotated[User, Depends(require_permission("APPROVE_RESPONSE"))]):
    settings = get_settings()
    if not settings.demo_mode or not settings.dry_run:
        raise HTTPException(status_code=403, detail="NovaBank scenario requires demo mode and dry-run")
    if "demo-web.local" not in settings.web_allowed_hosts:
        raise HTTPException(status_code=422, detail="NovaBank demo requires demo-web.local in web allowed hosts")
    existing = list(db.scalars(select(Incident).where(Incident.title.like("NovaBank ·%"))).all())
    if existing:
        if len(existing) != 3:
            raise HTTPException(status_code=409, detail="Partial NovaBank scenario present; review before retry")
        ordered = sorted(existing, key=lambda item: item.title)
        return {"status": "EXISTING", "incident_ids": [item.id for item in ordered],
                "memory_status": "Check Security Memory panel", "synthetic": True, "label": LABEL}
    titles = ["01 Credential compromise · evidence loss (exercise)",
              "02 Credential compromise · preservation-first review",
              "03 Password spraying · cross-account correlation"]
    ids = []
    for scenario, title in enumerate(titles, 1):
        source = f"198.51.100.{50 + scenario}"  # RFC 5737 documentation-only addresses
        found = set()
        for index, name in enumerate(("finance", "support", "auditor", "operator", "backup"), 1):
            payload = WebRequestCreate(
                request_id=f"novabank-{scenario}-{index}", timestamp=datetime.now(UTC),
                source_ip=source, target_host="demo-web.local", method="POST", path="/login",
                status_code=401, username=f"novabank-{name}",
                metadata={"demo": True, "novabank": True, "scenario": scenario,
                          "simulated": True, "label": LABEL},
            )
            _, _, attacks = ingest_web_request(db, payload)
            found.update(a.incident_id for a in attacks if a.incident_id)
        if len(found) != 1:
            raise HTTPException(status_code=500, detail="Existing behavioral detection did not yield one incident")
        case = db.get(Incident, found.pop())
        case.title = f"NovaBank · {title}"
        case.description = LABEL + " No live account was disabled; response outcomes are a labeled analyst exercise."
        db.commit()
        ids.append(case.id)
    first = db.get(Incident, ids[0])
    memory = retain(db, first, amendments={
        "incident": {"outcome": "Synthetic exercise: analyst reported immediate account disable; "
                                 "forensic session evidence was lost. No external change was performed.",
                     "root_cause": "Synthetic credential-compromise investigation"},
        "investigation": {"initial_hypothesis": "Stolen password only", "steps": ["Reviewed auth alerts"],
                          "failed_paths": ["Immediately disable account before preserving session evidence"],
                          "reasoning": "The simulated sequence lost forensic session context."},
        "response": {"side_effects": ["Synthetic exercise: forensic session evidence lost"],
                     "result": "Simulation only; no account disabled"},
        "lessons": [{"lesson": ("Preserve critical authentication evidence before destructive "
                                 "containment when operationally safe."),
                     "condition": "Credential compromise when evidence preservation is operationally safe",
                     "recommended_behavior": "Preserve auth logs and sessions, then escalate containment for approval",
                     "confidence": None, "source_incident": ids[0], "synthetic": True}],
    })
    record_audit(db, actor_id=user.id, action="NOVABANK_DEMO_LOAD", target_type="demo_data",
                 target_id=ids[0], result="SUCCESS", details={"synthetic": True, "memory_status": memory["status"]})
    return {"status": "LOADED", "incident_ids": ids, "memory_status": memory["status"],
            "synthetic": True, "label": LABEL,
            "note": ("Incident 2 must receive analyst feedback with an observed outcome "
                     "before Incident 3 accumulates it.")}
