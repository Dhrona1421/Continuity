from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.schemas import EventCreate


def _timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return datetime.now(UTC)


def normalize_sysmon(record: dict[str, Any]) -> EventCreate:
    data = record.get("EventData", record.get("event_data", {}))
    system = record.get("System", record.get("system", {}))
    event_id = str(system.get("EventRecordID") or record.get("event_id") or "")
    if not event_id:
        raise ValueError("Sysmon record requires EventRecordID or event_id")
    return EventCreate(
        event_id=f"sysmon:{event_id}",
        timestamp=_timestamp(system.get("TimeCreated") or record.get("timestamp")),
        source="sysmon",
        source_type="sysmon",
        host=system.get("Computer") or record.get("host"),
        user=data.get("User"),
        process=data.get("Image"),
        parent_process=data.get("ParentImage"),
        command_line=data.get("CommandLine"),
        src_ip=data.get("SourceIp"),
        dst_ip=data.get("DestinationIp"),
        src_port=int(data["SourcePort"]) if data.get("SourcePort") else None,
        dst_port=int(data["DestinationPort"]) if data.get("DestinationPort") else None,
        hash=data.get("Hashes"),
        file=data.get("TargetFilename") or data.get("Image"),
        event_type="process_creation" if str(system.get("EventID")) == "1" else "sysmon_event",
        severity="INFO",
        raw_reference=f"sysmon:{event_id}",
        metadata={"sysmon_event_id": system.get("EventID")},
        raw_payload=record,
    )


def normalize_suricata(record: dict[str, Any]) -> EventCreate:
    alert = record.get("alert", {})
    severity_num = int(alert.get("severity", 3))
    severity = "CRITICAL" if severity_num == 1 else "HIGH" if severity_num == 2 else "MEDIUM"
    return EventCreate(
        event_id=f"suricata:{record.get('flow_id') or record.get('event_id')}",
        timestamp=_timestamp(record.get("timestamp")),
        source="suricata",
        source_type="suricata",
        src_ip=record.get("src_ip"),
        dst_ip=record.get("dest_ip"),
        src_port=record.get("src_port"),
        dst_port=record.get("dest_port"),
        domain=record.get("dns", {}).get("rrname"),
        event_type="ids_alert" if alert else str(record.get("event_type", "network_event")),
        severity=severity,
        raw_reference=f"suricata-flow:{record.get('flow_id')}",
        metadata={"signature": alert.get("signature"), "signature_id": alert.get("signature_id")},
        raw_payload=record,
    )


def normalize_zeek(record: dict[str, Any]) -> EventCreate:
    uid = str(record.get("uid") or record.get("event_id") or "")
    if not uid:
        raise ValueError("Zeek record requires uid or event_id")
    return EventCreate(
        event_id=f"zeek:{uid}:{record.get('_path', 'event')}",
        timestamp=_timestamp(record.get("ts") or record.get("timestamp")),
        source="zeek",
        source_type="zeek",
        src_ip=record.get("id.orig_h"),
        dst_ip=record.get("id.resp_h"),
        src_port=record.get("id.orig_p"),
        dst_port=record.get("id.resp_p"),
        domain=record.get("query") or record.get("server_name"),
        event_type=str(record.get("_path", "network_event")),
        severity="INFO",
        raw_reference=f"zeek:{uid}",
        metadata={"proto": record.get("proto"), "service": record.get("service")},
        raw_payload=record,
    )


def normalize_cowrie(record: dict[str, Any]) -> EventCreate:
    event_id = str(record.get("eventid") or record.get("event_id") or "")
    session = str(record.get("session") or "unknown")
    if not event_id:
        raise ValueError("Cowrie record requires eventid")
    event_type = "command_input" if event_id == "cowrie.command.input" else event_id
    return EventCreate(
        event_id=f"cowrie:{session}:{record.get('timestamp')}:{event_id}",
        timestamp=_timestamp(record.get("timestamp")),
        source="cowrie",
        source_type="cowrie",
        src_ip=record.get("src_ip"),
        dst_ip=record.get("dst_ip"),
        src_port=record.get("src_port"),
        dst_port=record.get("dst_port"),
        command_line=record.get("input"),
        user=record.get("username"),
        event_type=event_type,
        severity="MEDIUM",
        raw_reference=f"cowrie-session:{session}",
        metadata={"session": session, "controlled_deception": True},
        raw_payload=record,
    )
