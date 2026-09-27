# API conventions

Interactive OpenAPI is served at `/docs`; the schema is at `/openapi.json`.

- Base prefix: `/api/v1`
- Authentication: `Authorization: Bearer <JWT>` for API clients
- Browser dashboard: HTTP-only `ghostsoc_session` cookie; `credentials: include`
- Same-origin header fallback: `X-GhostSOC-Token: <JWT>` where supported
- Logout: `POST /auth/logout` clears the browser session cookie
- JSON request/response except report downloads
- Request trace: `X-Correlation-ID` (validated or server-generated)
- Errors: `{ "error": { "code", "message", "details?", "correlation_id" } }`
- Pagination: current list endpoints use bounded `limit` (maximum 500); cursor pagination is a future scale item.

## Principal routes

| Area | Routes |
|---|---|
| System | `GET /health`, `GET /ready` |
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `GET /auth/permissions`, guarded `GET /auth/demo-access` |
| Events | `POST/GET /events`, `POST /events/telemetry/{sysmon|zeek|suricata|cowrie}` |
| Web security | `POST/GET /web/requests`, `GET /web/summary`, `GET /web/attack-catalog`, `GET/PATCH /web/attacks`, `GET /web/replay` |
| Live monitor | `GET /live/stream` (SSE), `GET /live/history` |
| Visualizations | `GET /visualizations/trends`, `/visualizations/network`, `/visualizations/attack-graph`, `/visualizations/incidents/{id}` |
| Global search | `GET /search/global?q=` across incidents, attacks, alerts, events, IOCs, and users |
| Hunt/inventory | `GET /hunt?q=`, `GET /hosts`, `GET /iocs`, `GET /timeline` |
| Detection | `GET /alerts`, `GET /detections`, `GET /mitre` |
| Incidents | `GET /incidents`, `GET/PATCH /incidents/{id}` |
| Evidence | `POST /incidents/{id}/evidence` |
| CTI | `POST /threat-intelligence/enrich` |
| Connectors | `GET /connectors`, `POST /connectors/{name}/check` |
| Response | `GET /response-policies`, `GET /incidents/{id}/response-context`, `POST/GET /response-actions`, `POST /response-actions/{id}/approval` |
| Users/audit | `GET /users`, `GET /audit` |
| Reports | `GET /reports`, `POST /incidents/{id}/reports/{pdf|json|csv|zip}`, `GET /reports/{id}/download` |
| Coverage/UI | `GET /coverage`, `GET /dashboard` |
| Demo | `POST /demo/run`, `POST /demo/reset`, `POST /demo/web-run`, `POST /demo/web-reset` |

The API intentionally has no command execution, raw SQL, arbitrary Velociraptor query, arbitrary external URL fetch, or unrestricted filesystem route.
