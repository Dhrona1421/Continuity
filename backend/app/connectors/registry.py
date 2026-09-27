from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.base import ConnectorStatus, HttpConnector
from app.core.config import Settings, get_settings
from app.models import ConnectorState


@dataclass(frozen=True)
class ConnectorDefinition:
    name: str
    connector_type: str
    mode: str
    capabilities: list[str]
    notes: str
    config_attr: str | None = None
    local_health: str | None = None


DEFINITIONS = [
    ConnectorDefinition(
        "OpenSearch",
        "SIEM_SEARCH",
        "REAL",
        ["health", "index", "search"],
        "HTTP adapter; core persists to PostgreSQL if unavailable.",
        "opensearch_url",
    ),
    ConnectorDefinition(
        "Wazuh",
        "ENDPOINT",
        "REAL_BOUNDARY",
        ["health", "fetch"],
        "Requires an existing Wazuh API and token.",
        "wazuh_url",
    ),
    ConnectorDefinition(
        "Sysmon",
        "TELEMETRY",
        "REAL_LOCAL",
        ["normalize", "ingest"],
        "Sysmon-compatible event normalization is available.",
        local_health="parser",
    ),
    ConnectorDefinition(
        "Sigma",
        "DETECTION",
        "REAL_LOCAL",
        ["load", "validate", "detect"],
        "Validated deterministic Sigma subset; unsupported conditions are rejected.",
        local_health="rules",
    ),
    ConnectorDefinition(
        "MITRE ATT&CK",
        "KNOWLEDGE",
        "REAL_LOCAL",
        ["map", "coverage"],
        "Bundled metadata subset for included rules.",
        local_health="mitre",
    ),
    ConnectorDefinition(
        "Velociraptor",
        "DFIR",
        "REAL_BOUNDARY",
        ["health", "collect"],
        "Typed collection boundary; external service required.",
        "velociraptor_url",
    ),
    ConnectorDefinition(
        "YARA",
        "MALWARE",
        "LOCAL_OPTIONAL",
        ["scan"],
        "Uses installed YARA runtime when present; demo mock otherwise.",
        local_health="yara",
    ),
    ConnectorDefinition(
        "Zeek",
        "NETWORK",
        "REAL_LOCAL",
        ["normalize", "ingest"],
        "JSON log ingestion adapter available.",
        local_health="parser",
    ),
    ConnectorDefinition(
        "Suricata",
        "NETWORK",
        "REAL_LOCAL",
        ["normalize", "ingest"],
        "EVE JSON ingestion adapter available.",
        local_health="parser",
    ),
    ConnectorDefinition(
        "Arkime", "PACKET", "REAL_BOUNDARY", ["health", "search"], "External Arkime service required.", "arkime_url"
    ),
    ConnectorDefinition(
        "MISP", "CTI", "REAL_BOUNDARY", ["health", "enrich"], "External MISP URL and API key required.", "misp_url"
    ),
    ConnectorDefinition(
        "OpenCTI",
        "CTI",
        "REAL_BOUNDARY",
        ["health", "enrich"],
        "External OpenCTI URL and token required.",
        "opencti_url",
    ),
    ConnectorDefinition(
        "ThreatFox",
        "CTI",
        "REAL",
        ["enrich"],
        "abuse.ch Auth-Key required; success follows a parsed provider response.",
        config_attr="abuse_ch_auth_key",
    ),
    ConnectorDefinition(
        "URLhaus",
        "CTI",
        "REAL",
        ["enrich"],
        "abuse.ch Auth-Key required; URL lookup only in this adapter.",
        config_attr="abuse_ch_auth_key",
    ),
    ConnectorDefinition("AbuseIPDB", "CTI", "REAL", ["enrich"], "API key required.", config_attr="abuseipdb_api_key"),
    ConnectorDefinition(
        "MalwareBazaar",
        "CTI",
        "REAL",
        ["enrich"],
        "abuse.ch Auth-Key required for hash lookup.",
        config_attr="abuse_ch_auth_key",
    ),
    ConnectorDefinition("VirusTotal", "CTI", "REAL", ["enrich"], "API key required.", config_attr="virustotal_api_key"),
    ConnectorDefinition(
        "Cowrie",
        "DECEPTION",
        "REAL_LOCAL",
        ["normalize", "ingest"],
        "Controlled Cowrie JSON ingestion.",
        local_health="parser",
    ),
    ConnectorDefinition(
        "Shuffle", "SOAR", "REAL_BOUNDARY", ["health", "trigger"], "Optional external workflow service.", "shuffle_url"
    ),
    ConnectorDefinition(
        "Atomic Red Team",
        "SIMULATION",
        "DOCUMENTED",
        ["fixtures", "coverage"],
        "No test is executed on hosts; authorized fixture mapping only.",
        local_health="fixture",
    ),
]
KEY_REQUIRED_CONNECTORS = {"ThreatFox", "URLhaus", "AbuseIPDB", "MalwareBazaar", "VirusTotal"}


def _configured(definition: ConnectorDefinition, settings: Settings) -> bool:
    if definition.local_health:
        return True
    return bool(getattr(settings, definition.config_attr, None)) if definition.config_attr else False


def list_connectors(db: Session) -> list[dict[str, object]]:
    settings = get_settings()
    states = {state.name: state for state in db.scalars(select(ConnectorState)).all()}
    result = []
    for definition in DEFINITIONS:
        configured = _configured(definition, settings)
        state = states.get(definition.name)
        enabled = (state.configuration or {}).get("enabled", True) if state else True
        default_status = (
            "HEALTHY"
            if definition.local_health
            else "API_KEY_REQUIRED"
            if definition.name in KEY_REQUIRED_CONNECTORS and not configured
            else "NOT_CONFIGURED"
        )
        status = state.status if state else default_status
        if not enabled:
            status = "DISABLED"
        elif definition.local_health == "yara" and shutil.which("yara") is None:
            status = "UNAVAILABLE"
        result.append(
            {
                "name": definition.name,
                "connector_type": definition.connector_type,
                "status": status,
                "mode": definition.mode,
                "configured": configured,
                "enabled": enabled,
                "last_checked_at": state.last_checked_at if state else None,
                "last_success_at": state.last_success_at if state else None,
                "last_error": state.last_error if state else None,
                "capabilities": definition.capabilities,
                "notes": definition.notes,
            }
        )
    return result


async def check_connector(db: Session, name: str) -> dict[str, object]:
    settings = get_settings()
    definition = next((item for item in DEFINITIONS if item.name == name), None)
    if definition is None:
        raise KeyError(name)
    state = db.scalar(select(ConnectorState).where(ConnectorState.name == name))
    started = time.monotonic()
    error: str | None = None
    if state and (state.configuration or {}).get("enabled", True) is False:
        status = ConnectorStatus.DISABLED
        error = "Connector is disabled"
    elif definition.local_health:
        if definition.local_health == "yara" and shutil.which("yara") is None:
            status = ConnectorStatus.UNAVAILABLE
            error = "YARA executable not installed; demo mock remains available"
        else:
            status = ConnectorStatus.HEALTHY
    else:
        value = getattr(settings, definition.config_attr, None) if definition.config_attr else None
        if not value:
            status = (
                ConnectorStatus.API_KEY_REQUIRED
                if definition.name in KEY_REQUIRED_CONNECTORS
                else ConnectorStatus.NOT_CONFIGURED
            )
        elif definition.name in {"ThreatFox", "URLhaus", "AbuseIPDB", "MalwareBazaar", "VirusTotal"}:
            status = ConnectorStatus.DEGRADED
            error = "Credentials are configured; provider health requires an IOC enrichment request"
        else:
            try:
                headers: dict[str, str] = {}
                if definition.name == "Wazuh" and settings.wazuh_token:
                    headers["Authorization"] = f"Bearer {settings.wazuh_token}"
                connector = HttpConnector(str(value), headers=headers, allow_private=settings.allow_private_connectors)
                response = await connector.request("GET")
                if response.status_code in {401, 403}:
                    status = ConnectorStatus.AUTHENTICATION_ERROR
                    error = f"HTTP {response.status_code}"
                elif response.is_success:
                    status = ConnectorStatus.HEALTHY
                else:
                    status = ConnectorStatus.DEGRADED
                    error = f"HTTP {response.status_code}"
            except (httpx.HTTPError, ValueError) as exc:
                status = ConnectorStatus.UNAVAILABLE
                error = str(exc)[:500]
    now = datetime.now(UTC)
    if state is None:
        state = ConnectorState(name=name, connector_type=definition.connector_type)
        db.add(state)
    state.status = status.value
    state.last_checked_at = now
    state.last_error = error
    state.configuration = {
        "configured": _configured(definition, settings),
        "enabled": (state.configuration or {}).get("enabled", True),
    }
    if status == ConnectorStatus.HEALTHY:
        state.last_success_at = now
    db.commit()
    view = next(item for item in list_connectors(db) if item["name"] == name)
    view["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
    return view


def set_connector_enabled(db: Session, name: str, enabled: bool) -> dict[str, object]:
    definition = next((item for item in DEFINITIONS if item.name == name), None)
    if definition is None:
        raise KeyError(name)
    state = db.scalar(select(ConnectorState).where(ConnectorState.name == name))
    if state is None:
        state = ConnectorState(name=name, connector_type=definition.connector_type)
        db.add(state)
    state.configuration = {
        **(state.configuration or {}),
        "configured": _configured(definition, get_settings()),
        "enabled": enabled,
    }
    state.status = (
        "API_KEY_REQUIRED"
        if enabled and definition.name in KEY_REQUIRED_CONNECTORS and not _configured(definition, get_settings())
        else "NOT_CONFIGURED"
        if enabled
        else "DISABLED"
    )
    state.last_error = "Connection check required" if enabled else "Connector disabled by administrator"
    state.last_checked_at = datetime.now(UTC)
    db.commit()
    return next(item for item in list_connectors(db) if item["name"] == name)
