from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Alert, DetectionRule, SecurityEvent

logger = logging.getLogger(__name__)
# Bundle the reviewed Sigma-compatible rules with the application so wheel,
# Docker and source installs load exactly the same detection definitions.
RULE_DIR = Path(__file__).resolve().parents[1] / "data" / "rules"
REQUIRED_RULE_KEYS = {"title", "id", "description", "detection", "level"}
FIELD_MAP = {
    "user": "username",
    "hash": "file_hash",
    "file": "file_path",
    "Image": "process",
    "CommandLine": "command_line",
}


class RuleValidationError(ValueError):
    pass


def _extract_techniques(rule: dict[str, Any]) -> list[str]:
    techniques: list[str] = []
    for tag in rule.get("tags", []):
        text = str(tag).lower()
        if text.startswith("attack.t"):
            techniques.append(text.removeprefix("attack.").upper())
    return sorted(set(techniques))


def validate_rule(rule: dict[str, Any], source: str = "unknown") -> None:
    missing = REQUIRED_RULE_KEYS - set(rule)
    if missing:
        raise RuleValidationError(f"{source}: missing required keys {sorted(missing)}")
    detection = rule["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleValidationError(f"{source}: detection.condition is required")
    condition = detection["condition"]
    if not isinstance(condition, str) or any(token in condition for token in ("(", ")", "|")):
        raise RuleValidationError(f"{source}: only named selections joined by 'and'/'or' are supported")
    names = {part.strip() for part in condition.replace(" or ", " and ").split(" and ")}
    if not names or not names.issubset(detection):
        raise RuleValidationError(f"{source}: condition references an unknown selection")


def load_rule_files() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(RULE_DIR.glob("*.yml")):
        with path.open(encoding="utf-8") as handle:
            rule = yaml.safe_load(handle)
        if not isinstance(rule, dict):
            raise RuleValidationError(f"{path.name}: rule must be a mapping")
        validate_rule(rule, path.name)
        rules.append(rule)
    return rules


def sync_rules(db: Session) -> int:
    count = 0
    for body in load_rule_files():
        existing = db.get(DetectionRule, str(body["id"]))
        values = {
            "title": body["title"],
            "description": body["description"],
            "severity": str(body["level"]).upper(),
            "confidence": float(body.get("ghostsoc", {}).get("confidence", 0.5)),
            "status": body.get("status", "experimental"),
            "source": "sigma-compatible",
            "mitre_techniques": _extract_techniques(body),
            "rule_body": body,
        }
        if existing:
            for key, value in values.items():
                setattr(existing, key, value)
        else:
            db.add(DetectionRule(id=str(body["id"]), **values))
        count += 1
    db.commit()
    return count


def _field_value(event: SecurityEvent, field: str) -> object:
    attr = FIELD_MAP.get(field, field)
    if hasattr(event, attr):
        return getattr(event, attr)
    return event.event_metadata.get(field)


def _value_matches(actual: object, expected: object, modifier: str | None) -> bool:
    choices = expected if isinstance(expected, list) else [expected]
    if actual is None:
        return False
    actual_text = str(actual).lower()
    for choice in choices:
        wanted = str(choice).lower()
        if modifier == "contains" and wanted in actual_text:
            return True
        if modifier == "endswith" and actual_text.endswith(wanted):
            return True
        if modifier == "startswith" and actual_text.startswith(wanted):
            return True
        if modifier is None and actual_text == wanted:
            return True
    return False


def _selection_matches(event: SecurityEvent, selection: dict[str, object]) -> bool:
    for expression, expected in selection.items():
        field, _, modifier = expression.partition("|")
        actual = _field_value(event, field)
        if not _value_matches(actual, expected, modifier or None):
            return False
    return True


def rule_matches(event: SecurityEvent, rule: DetectionRule) -> bool:
    detection = rule.rule_body["detection"]
    condition = str(detection["condition"])
    if " or " in condition:
        return any(_selection_matches(event, detection[name.strip()]) for name in condition.split(" or "))
    return all(_selection_matches(event, detection[name.strip()]) for name in condition.split(" and "))


def detect_event(db: Session, event: SecurityEvent) -> list[Alert]:
    alerts: list[Alert] = []
    rules = db.scalars(
        select(DetectionRule).where(
            DetectionRule.enabled.is_(True),
            DetectionRule.source == "sigma-compatible",
        )
    ).all()
    for rule in rules:
        if not rule_matches(event, rule):
            continue
        fingerprint = hashlib.sha256(f"{rule.id}:{event.event_id}".encode()).hexdigest()
        alert = Alert(
            event_id=event.id,
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=rule.confidence,
            source=rule.source,
            fingerprint=fingerprint,
            mitre_techniques=rule.mitre_techniques,
            evidence_reference=event.raw_reference or f"event:{event.id}",
        )
        try:
            with db.begin_nested():
                db.add(alert)
                db.flush()
            alerts.append(alert)
        except IntegrityError:
            logger.info("Duplicate alert suppressed", extra={"target": fingerprint})
    db.commit()
    return alerts
