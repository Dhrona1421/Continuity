from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Evidence, Incident, TimelineEvent, User


def collect_evidence(db: Session, incident: Incident, evidence_type: str, target: str, user: User) -> Evidence:
    settings = get_settings()
    if target not in settings.authorized_targets:
        raise HTTPException(status_code=422, detail="Evidence target is not authorized")
    if not settings.demo_mode and evidence_type in {"ENDPOINT_TRIAGE", "YARA_SCAN", "NETWORK_CONTEXT"}:
        raise HTTPException(
            status_code=503,
            detail="No verified external collection adapter is configured for this operation",
        )
    source = {
        "ENDPOINT_TRIAGE": "Velociraptor DEMO_MOCK",
        "YARA_SCAN": "YARA DEMO_MOCK" if shutil.which("yara") is None else "YARA local boundary",
        "NETWORK_CONTEXT": "Zeek/Suricata DEMO_MOCK",
    }[evidence_type]
    details = {
        "mode": "DEMO_MOCK",
        "target": target,
        "executed_external_tool": False,
        "authorized": True,
    }
    if evidence_type == "ENDPOINT_TRIAGE":
        details["observations"] = ["powershell.exe process metadata retained", "network IOC retained"]
    elif evidence_type == "YARA_SCAN":
        details["rule"] = "GhostSOC_Demo_Encoded_PowerShell_Artifact"
        details["match"] = True
        details["note"] = "Deterministic demo result; no file content was executed or uploaded"
    else:
        details["flows"] = [{"src": target, "dst": "198.51.100.42", "port": 443}]
    serialized = json.dumps(details, sort_keys=True).encode()
    evidence = Evidence(
        incident_id=incident.id,
        evidence_type=evidence_type,
        source=source,
        status="COLLECTED",
        reference=f"demo-evidence:{incident.id}:{evidence_type}:{int(datetime.now(UTC).timestamp())}",
        sha256=hashlib.sha256(serialized).hexdigest(),
        summary=f"Controlled {evidence_type.lower().replace('_', ' ')} result for {target}",
        details=details,
        collected_by=user.id,
    )
    db.add(evidence)
    incident.timeline.append(
        TimelineEvent(
            event_type="EVIDENCE_COLLECTED",
            source=source,
            summary=evidence.summary,
            reference_id=evidence.id,
            details={"sha256": evidence.sha256, "mode": "DEMO_MOCK"},
        )
    )
    db.commit()
    db.refresh(evidence)
    return evidence
