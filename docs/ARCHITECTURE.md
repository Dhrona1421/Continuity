# GhostSOC architecture

## Components

```text
Browser
  │ relative /api requests
  ▼
Non-root Nginx :8080 ──► FastAPI :8000
                            │
               ┌────────────┼─────────────┐
               ▼            ▼             ▼
          PostgreSQL   OpenSearch     Connector adapters
          source of    best-effort    optional/external
          record       event index
```

PostgreSQL is authoritative for identity, events, web requests, aggregated attacks, detections, incidents, evidence, response state, reports, and audit. OpenSearch is an indexing/search adapter: its failure is logged and does not roll back the authoritative event. The SSE broker carries transient notifications only; reconnecting clients reload persisted state.

## Request flow

1. Nginx serves the React bundle and proxies relative `/api` requests.
2. Middleware assigns or validates an `X-Correlation-ID`, applies security headers, and writes structured request logs.
3. JWT authentication resolves an active user. Permissions are checked by the API, not merely hidden in the UI.
4. Pydantic schemas validate bounded request fields.
5. SQLAlchemy persists against PostgreSQL (SQLite is allowed only for deterministic development/tests).
6. API errors use `{ "error": { "code", "message", "correlation_id" } }`.

## Detection and incident flow

```text
source JSON or normalized event
  → source normalizer
  → SecurityEvent (unique external event_id)
  → enabled Sigma-compatible rules
  → Alert (unique rule/event fingerprint)
  → deterministic 4-hour host-or-IOC + technique correlation key
  → Incident + IOC extraction + timeline
  → explainable risk score and reasons
  → optional CTI / evidence
  → policy-controlled dry-run response
  → audit + PDF/JSON/CSV/ZIP
```

Every alert retains an event foreign key and evidence reference. Correlation is deterministic and bounded, not opaque ML. Risk combines severity (55%), confidence (25 points), correlated-alert count, and malicious IOC results; reasons are persisted alongside the score.

## Web security flow

```text
Allowlisted website/WAF record
  → WebRequest validation, header filtering, secret redaction
  → existing normalized SecurityEvent
  → signature / behavioral / context-signal detection family
  → 15-minute AttackDetection aggregation
  → existing Alert
  → source + target + four-hour Incident correlation
  → IOC, risk, evidence, response, audit, reports
  → SSE notification to Live Monitor
```

Different attack types from one source against one target intentionally join one incident. Context-dependent detections require explicit upstream evidence. Live metrics are calculated from persisted records, not constants.

## Visualization and search layer

The visualization APIs derive bounded aggregates from the authoritative tables; they do not persist a second graph schema. SOC trends bucket real events, attacks, incidents, and responses. Network mode aggregates source-to-target communications and traffic. Attack mode aggregates source → attack type → endpoint → target → incident. Investigate mode groups duplicate alert rules and relates the incident to IOCs, users, hosts, event groups, evidence, MITRE techniques, and response actions. Frontend SVG graphs use deterministic layouts, not long-running physics simulation, and cap backend query sizes.

Global search uses parameterized SQLAlchemy filters and returns typed navigation targets for incidents, attacks, alerts, events, IOCs, and—only for administrators—users.

## Persistence model

The Alembic migrations create:

- `users`, `connector_states`
- `security_events`, `detection_rules`, `alerts`
- `incidents`, `iocs`, `evidence`, `timeline_events`
- `response_policies`, `response_actions`
- `audit_logs`, `reports`, `detection_coverage`
- `web_requests`, `attack_detections`

The implementation intentionally avoids parallel event or incident schemas. Artifact/host details are currently normalized on events/evidence rather than duplicated into incomplete inventory tables.

## Connector boundaries

- **Ingestion adapters:** Sysmon, Zeek, Suricata, Cowrie normalize source records.
- **Detection/knowledge:** Sigma-compatible local rules and curated MITRE metadata.
- **Search:** OpenSearch HTTP document indexing.
- **CTI:** provider-neutral async interface with timeout, one bounded retry, rate-limit/auth/malformed-response normalization, and provider attribution.
- **External products:** registry and validated health boundary; product-specific collection/search remains disabled unless a verified adapter exists.

Connector endpoints reject embedded credentials. Public connectors reject resolved private, loopback, link-local, or reserved addresses unless `GHOSTSOC_ALLOW_PRIVATE_CONNECTORS=true`, which is required for an intentional internal SOC deployment.

## Response state machine

```text
PENDING → APPROVED/DENIED
PENDING + approval → RUNNING → SUCCESS/FAILED
PENDING + simulation → DRY_RUN
DENIED → CANCELLED
```

The API accepts seven typed actions, including source blocking and source rate limiting. Target shape and policy authorization are checked per action. A unique idempotency key prevents duplicate execution. Simulation ends in the explicit `DRY_RUN` state with `execution_result.executed=false`; it does not mark the incident contained. `CONTAINED` requires a non-dry-run adapter result with both `executed=true` and `verified=true`. If no verified adapter exists, execution fails closed.

## Trust boundaries

- Browser is untrusted; all permissions and validation run in FastAPI.
- Event content and LLM text never become executable commands.
- Connector content is untrusted and normalized before persistence/use.
- Report paths are generated server-side and verified to remain below the report root.
- External services are optional; a provider result is only `SUCCESS` after a completed response parse.
