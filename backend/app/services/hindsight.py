"""Hindsight is the retrieval authority; SQL only keeps structured source provenance.

A row is never shown as recalled history unless Hindsight actually returned its
source document ID. Hindsight turns retained narrative into facts/graph/temporal
memory; this is not an embedding search over a local JSON file.
"""

from __future__ import annotations

import json
import logging
import re
from copy import deepcopy
from datetime import UTC
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Incident, MemoryExperience

logger = logging.getLogger(__name__)


def _ioc_value(ioc) -> str:
    if ioc.ioc_type == "URL":
        try:
            parsed = urlsplit(ioc.value)
            host = parsed.hostname or ""
            port = f":{parsed.port}" if parsed.port else ""
            return urlunsplit((parsed.scheme, host + port, parsed.path, "", ""))[:512]
        except ValueError:
            return "[invalid URL redacted]"
    return ioc.value[:512]


def snapshot(incident: Incident) -> dict[str, Any]:
    """No raw event payloads, secrets or unverified action-success claims."""
    actions = [
        {
            "id": action.id, "type": action.action_type, "target": action.target,
            "approval": action.approval_status, "execution": action.execution_status,
            "executed": bool((action.execution_result or {}).get("executed")),
            "result": (action.execution_result or {}).get("error", ""),
        }
        for action in incident.response_actions
    ]
    return {
        "incident": {
            "id": incident.id, "title": incident.title, "description": incident.description,
            "severity": incident.severity, "status": incident.status,
            "risk_score": incident.risk_score, "risk_level": incident.risk_level,
            "risk_reasons": incident.risk_reasons,
            "techniques": sorted({t for alert in incident.alerts for t in alert.mitre_techniques}),
            "alerts": [{"id": a.id, "rule": a.rule_id, "title": a.title} for a in incident.alerts],
            "iocs": [{"type": i.ioc_type, "value": _ioc_value(i), "verdict": i.verdict} for i in incident.iocs],
            "evidence": [{"id": e.id, "summary": e.summary, "status": e.status, "sha256": e.sha256}
                         for e in incident.evidence],
            "timeline": [{"type": e.event_type, "summary": e.summary, "reference_id": e.reference_id}
                         for e in sorted(incident.timeline, key=lambda e: e.timestamp.replace(tzinfo=UTC)
                         if e.timestamp.tzinfo is None else e.timestamp)],
            "root_cause": None, "outcome": None,
        },
        "investigation": {"initial_hypothesis": None, "steps": [], "successful_paths": [],
                          "failed_paths": [], "important_evidence": [], "reasoning": ""},
        "response": {"actions": actions, "successful_actions": [a for a in actions if a["execution"] == "SUCCESS"
                     and a["executed"]],
                     "failed_actions": [a for a in actions if a["execution"] in ("FAILED", "CANCELLED")],
                     "side_effects": [], "result": "No verified external action"},
        "lessons": [],
        "analyst_feedback": [],
    }


def _url() -> str | None:
    value = get_settings().hindsight_url
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        # Only a deliberate server-side config may reach Hindsight; reject URL userinfo/paths.
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            return None
    except ValueError:
        return None
    return value.rstrip("/")


def _call(method: str, path: str, payload: dict[str, Any], *,
          timeout_seconds: float | None = None) -> dict[str, Any] | None:
    base = _url()
    if base is None:
        return None
    settings = get_settings()
    headers = {"Authorization": f"Bearer {settings.hindsight_api_key}"} if settings.hindsight_api_key else {}
    try:
        with httpx.Client(timeout=timeout_seconds or settings.hindsight_timeout_seconds,
                          follow_redirects=False) as client:
            response = client.request(method, f"{base}{path}", json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
            return result if isinstance(result, dict) else None
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Hindsight unavailable (%s)", type(exc).__name__)
        return None


def _path(suffix: str) -> str:
    return f"/v1/default/banks/{quote(get_settings().hindsight_bank_id, safe='')}/memories{suffix}"


def _narrative(exp: dict[str, Any]) -> str:
    # Explicit headings help Hindsight extract failed paths as strongly as successes.
    return "GhostSOC security experience (structured source record follows).\n" + "\n".join(
        f"{name.upper()}: {json.dumps(exp.get(name), ensure_ascii=True, sort_keys=True, default=str)}"
        for name in ("incident", "investigation", "response", "lessons", "analyst_feedback")
    )


def retain(db: Session, incident: Incident, *, amendments: dict[str, Any] | None = None,
           timeout_seconds: float | None = None) -> dict[str, Any]:
    row = db.scalar(select(MemoryExperience).where(MemoryExperience.incident_id == incident.id))
    experience = snapshot(incident)
    if row:
        # Preserve analyst-authored experience while refreshing source-owned fields.
        previous = deepcopy(row.experience)
        for field in ("investigation", "lessons", "analyst_feedback"):
            experience[field] = previous.get(field, experience[field])
        experience["incident"]["outcome"] = previous.get("incident", {}).get("outcome")
        experience["incident"]["root_cause"] = previous.get("incident", {}).get("root_cause")
        experience["response"]["side_effects"] = previous.get("response", {}).get("side_effects", [])
        if previous.get("response", {}).get("result") != "No verified external action":
            experience["response"]["result"] = previous["response"]["result"]
    if amendments:
        for field, changes in amendments.items():
            if field in ("incident", "investigation", "response") and isinstance(changes, dict):
                experience[field].update(changes)
            elif field in ("lessons", "analyst_feedback") and isinstance(changes, list):
                experience[field].extend(changes)
    if row is None:
        row = MemoryExperience(incident_id=incident.id, document_id=f"ghostsoc-incident-{incident.id}")
        db.add(row)
    else:
        row.version += 1
    row.experience = experience
    row.status = "PENDING"
    db.commit()  # Preserve the source experience even if Hindsight is down.
    result = _call("POST", _path(""), {"items": [{"document_id": row.document_id,
        "context": "security incident experience, including failures and lessons",
        "content": _narrative(experience)}], "async": False}, timeout_seconds=timeout_seconds)
    row.status = "RETAINED" if result and result.get("success") is True and not result.get("async") else "UNAVAILABLE"
    db.commit()
    return {"status": "retained" if row.status == "RETAINED" else "unavailable",
            "memory_id": row.id, "incident_id": incident.id, "version": row.version}


_STOP = {"incident", "on", "for", "from", "with", "the", "and", "attack", "activity",
         "correlated", "web", "novabank", "synthetic", "exercise", "case", "security"}


def _related(current: Incident, past: dict[str, Any]) -> bool:
    source = past.get("incident", {})
    now_techniques = {t for a in current.alerts for t in a.mitre_techniques}
    if now_techniques & set(source.get("techniques", [])):
        return True
    words = lambda text: set(re.findall(r"[a-z]{4,}", text.lower())) - _STOP  # noqa: E731
    current_words = words(current.title)
    past_words = words(str(source.get("title", "")))
    return bool(current_words & past_words)


def recall(db: Session, incident: Incident, limit: int = 5) -> dict[str, Any]:
    query = (f"Past security incidents like {incident.title}. Techniques "
             f"{', '.join(sorted({t for a in incident.alerts for t in a.mitre_techniques}))}. "
             "What evidence mattered, which response failed, why, and what did analysts reject?")
    result = _call("POST", _path("/recall"), {
        "query": query, "budget": "high", "prefer_observations": True,
    })
    if result is None or not isinstance(result.get("results"), list):
        return {"status": "unavailable", "matches": []}
    documents: dict[str, list[str]] = {}
    for fact in result["results"]:
        if not isinstance(fact, dict):
            continue
        doc = fact.get("document_id")
        if isinstance(doc, str):
            documents.setdefault(doc, []).append(str(fact.get("text", ""))[:1000])
    if not documents:
        return {"status": "available", "matches": []}
    rows = db.scalars(select(MemoryExperience).where(
        MemoryExperience.document_id.in_(list(documents)[:100]), MemoryExperience.status == "RETAINED",
        MemoryExperience.incident_id != incident.id)).all()
    by_doc = {row.document_id: row for row in rows}
    matches = [{"memory_id": by_doc[doc].id, "source_incident_id": by_doc[doc].incident_id,
                "document_id": doc, "experience": by_doc[doc].experience, "recalled_facts": facts[:8]}
               for doc, facts in documents.items() if doc in by_doc and _related(incident, by_doc[doc].experience)]
    return {"status": "available", "matches": matches[:limit]}


def search(db: Session, query: str, limit: int = 10) -> dict[str, Any]:
    """Search all Hindsight memory types and attach provenance when available."""
    result = _call("POST", _path("/recall"), {"query": query, "budget": "high"})
    if result is None or not isinstance(result.get("results"), list):
        return {"status": "unavailable", "matches": []}
    hits: list[dict[str, Any]] = []
    for index, fact in enumerate(result["results"]):
        if not isinstance(fact, dict):
            continue
        document_id = fact.get("document_id")
        text = str(fact.get("text", ""))[:1000]
        if text:
            hits.append({"document_id": document_id, "text": text, "type": fact.get("type"),
                         "context": fact.get("context"), "fact_id": fact.get("id") or f"fact-{index}"})
    if not hits:
        return {"status": "available", "matches": []}
    document_ids = list(dict.fromkeys(hit["document_id"] for hit in hits
                                      if isinstance(hit["document_id"], str)))[:100]
    rows = db.scalars(select(MemoryExperience).where(
        MemoryExperience.document_id.in_(document_ids), MemoryExperience.status == "RETAINED",
    )).all() if document_ids else []
    by_document = {row.document_id: row for row in rows}
    matches = []
    for hit in hits:
        source = by_document.get(hit["document_id"]) if hit["document_id"] else None
        matches.append({"memory_id": source.id if source else None, "fact_id": hit["fact_id"],
                        "source_incident_id": source.incident_id if source else None,
                        "document_id": hit["document_id"], "type": hit["type"],
                        "context": hit["context"], "experience": source.experience if source else None,
                        "recalled_facts": [hit["text"]]})
    return {"status": "available", "matches": matches[:limit]}


def learn(db: Session, incident: Incident, feedback: dict[str, Any]) -> dict[str, Any]:
    existing = db.scalar(select(MemoryExperience).where(MemoryExperience.incident_id == incident.id))
    for previous in (existing.experience.get("analyst_feedback", []) if existing else []):
        if all(previous.get(field) == feedback.get(field) for field in
               ("recommendation_id", "decision", "reason", "analyst_id")):
            return retain(db, incident)  # retry provider without duplicating a saved decision
    amendments = {"analyst_feedback": [feedback],
                  "lessons": ([feedback["lesson"]] if feedback.get("lesson") else [])}
    if feedback.get("outcome"):
        amendments["incident"] = {"outcome": feedback["outcome"]}
    return retain(db, incident, amendments=amendments)


def update(db: Session, row: MemoryExperience, changes: dict[str, Any], expected_version: int) -> dict[str, Any]:
    if row.version != expected_version:
        return {"status": "conflict", "memory_id": row.id, "version": row.version}
    incident = db.get(Incident, row.incident_id)
    return retain(db, incident, amendments=changes)
