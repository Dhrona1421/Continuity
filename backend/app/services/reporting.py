from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from datetime import UTC
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import AttackDetection, Incident, Report, User

FORMATS = {"pdf", "json", "csv", "zip"}


def _incident_data(incident: Incident, web_attacks: list[AttackDetection] | None = None) -> dict[str, object]:
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk": {
            "score": incident.risk_score,
            "level": incident.risk_level,
            "reasons": incident.risk_reasons,
        },
        "status": incident.status,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
        "alerts": [
            {
                "id": item.id,
                "title": item.title,
                "severity": item.severity,
                "rule_id": item.rule_id,
                "mitre_techniques": item.mitre_techniques,
                "evidence_reference": item.evidence_reference,
            }
            for item in incident.alerts
        ],
        "iocs": [
            {
                "type": item.ioc_type,
                "value": item.value,
                "verdict": item.verdict,
                "source": item.source,
                "enrichment": item.enrichment,
            }
            for item in incident.iocs
        ],
        "evidence": [
            {
                "id": item.id,
                "type": item.evidence_type,
                "source": item.source,
                "status": item.status,
                "sha256": item.sha256,
                "summary": item.summary,
                "reference": item.reference,
            }
            for item in incident.evidence
        ],
        "timeline": [
            {
                "timestamp": item.timestamp.isoformat(),
                "type": item.event_type,
                "source": item.source,
                "summary": item.summary,
                "reference_id": item.reference_id,
            }
            for item in sorted(
                incident.timeline,
                key=lambda item: (item.timestamp if item.timestamp.tzinfo else item.timestamp.replace(tzinfo=UTC)),
            )
        ],
        "web_attacks": [
            {
                "id": item.id,
                "attack_type": item.attack_type,
                "family": item.family,
                "severity": item.severity,
                "confidence": item.confidence,
                "classification": item.classification,
                "status": item.status,
                "source_ip": item.source_ip,
                "target_host": item.target_host,
                "endpoint": item.endpoint,
                "request_count": item.request_count,
                "rule_id": item.rule_id,
                "mitre_techniques": item.mitre_techniques,
                "response_status": item.response_status,
                "evidence": item.evidence,
            }
            for item in (web_attacks or [])
        ],
        "response_actions": [
            {
                "id": item.id,
                "type": item.action_type,
                "target": item.target,
                "approval": item.approval_status,
                "dry_run": item.dry_run,
                "status": item.execution_status,
                "result": item.execution_result,
            }
            for item in incident.response_actions
        ],
    }


def _json_bytes(data: dict[str, object]) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


def _timeline_csv(data: dict[str, object]) -> bytes:
    text = io.StringIO()
    writer = csv.DictWriter(text, fieldnames=["timestamp", "type", "source", "summary", "reference_id"])
    writer.writeheader()
    writer.writerows(data["timeline"])
    return text.getvalue().encode()


def _iocs_csv(data: dict[str, object]) -> bytes:
    text = io.StringIO()
    writer = csv.DictWriter(text, fieldnames=["type", "value", "verdict", "source"])
    writer.writeheader()
    for ioc in data["iocs"]:
        writer.writerow({key: ioc[key] for key in writer.fieldnames})
    return text.getvalue().encode()


def _pdf_bytes(data: dict[str, object]) -> bytes:
    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4, pageCompression=1)
    width, height = A4
    y = height - 50
    lines = [
        "Continuity Incident Report",
        f"Incident: {data['id']}",
        f"Title: {data['title']}",
        f"Status: {data['status']}",
        f"Severity: {data['severity']}",
        f"Risk: {data['risk']['level']} ({data['risk']['score']})",
        "",
        "Risk reasons:",
        *[f"- {reason}" for reason in data["risk"]["reasons"]],
        "",
        f"Alerts: {len(data['alerts'])}",
        f"Web attack aggregates: {len(data['web_attacks'])}",
        f"IOCs: {len(data['iocs'])}",
        f"Evidence records: {len(data['evidence'])}",
        f"Response actions: {len(data['response_actions'])}",
        "",
        "Timeline:",
        *[f"{item['timestamp']} | {item['type']} | {item['summary']}" for item in data["timeline"]],
    ]
    for line in lines:
        safe_line = str(line)[:110]
        if y < 50:
            pdf.showPage()
            y = height - 50
        pdf.drawString(45, y, safe_line)
        y -= 15
    pdf.save()
    return output.getvalue()


def _zip_bytes(data: dict[str, object]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("incident.json", _json_bytes(data))
        archive.writestr("timeline.csv", _timeline_csv(data))
        archive.writestr("iocs.csv", _iocs_csv(data))
        archive.writestr(
            "mitre-mapping.json",
            json.dumps(
                sorted({tech for alert in data["alerts"] for tech in alert["mitre_techniques"]}),
                indent=2,
            ),
        )
        archive.writestr("response-actions.json", json.dumps(data["response_actions"], indent=2))
        archive.writestr("web-attacks.json", json.dumps(data["web_attacks"], indent=2))
        archive.writestr("incident-report.pdf", _pdf_bytes(data))
        for evidence in data["evidence"]:
            archive.writestr(
                f"evidence/{evidence['id']}.json",
                json.dumps(evidence, indent=2, default=str),
            )
    return output.getvalue()


def generate_report(db: Session, incident: Incident, report_format: str, user: User) -> tuple[Report, Path]:
    report_format = report_format.lower()
    if report_format not in FORMATS:
        raise ValueError(f"unsupported report format: {report_format}")
    web_attacks = list(
        db.scalars(
            select(AttackDetection)
            .where(AttackDetection.incident_id == incident.id)
            .order_by(AttackDetection.last_seen.desc())
        ).all()
    )
    data = _incident_data(incident, web_attacks)
    content = {
        "json": lambda: _json_bytes(data),
        "csv": lambda: _timeline_csv(data),
        "pdf": lambda: _pdf_bytes(data),
        "zip": lambda: _zip_bytes(data),
    }[report_format]()
    directory = get_settings().report_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    filename = f"Continuity-Incident-{incident.id}.{report_format}"
    path = (directory / filename).resolve()
    if path.parent != directory:
        raise ValueError("unsafe report path")
    path.write_bytes(content)
    report = Report(
        incident_id=incident.id,
        format=report_format.upper(),
        file_name=filename,
        sha256=hashlib.sha256(content).hexdigest(),
        generated_by=user.id,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report, path
