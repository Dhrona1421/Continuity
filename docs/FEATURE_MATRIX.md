# Feature matrix

Status is based on executed automated tests in the implementation workspace. Docker/runtime items remain unverified until run on a Docker host.

| Feature | Status | Real/Mock | Tested | Notes |
|---|---|---|---:|---|
| FastAPI core / errors / correlation IDs | COMPLETE | Real | Yes | Structured JSON API and logs |
| PostgreSQL model + Alembic | IMPLEMENTED | Real | SQLite two-revision upgrade/check/downgrade PASS; PostgreSQL runtime not run | Existing schema extended with web requests/attacks |
| Authentication / roles / permissions | COMPLETE for core | Real | Yes | Argon2 + JWT + backend RBAC |
| Normalized event ingestion | COMPLETE | Real | Yes | Unique source event ID |
| Web request ingestion | COMPLETE core | Real | Yes | Allowlisted targets, safe headers, redaction, session hashing |
| 35-category web catalog | COMPLETE detection interface | Real signatures/behavior/signals | Yes | Context-dependent types require upstream evidence |
| Web attack aggregation | COMPLETE | Real | Yes | 15-minute source/target/type aggregate |
| Cross-attack web correlation | COMPLETE | Real | Yes | One source + target + 4h incident window |
| Live SSE monitor | COMPLETE single-process | Real | Yes | Persisted reload; shared broker needed for multi-replica |
| SOC trend analytics | COMPLETE | Real aggregates | API + browser | Events, attacks, incidents, responses, severity, confidence |
| Attack relationship graph | COMPLETE aggregated | Real relationships | API + browser | Source, attack, endpoint, target, incident |
| Network topology | COMPLETE current telemetry | Real relationships | API + browser | Zoom, pan, fit, filters, node/edge details |
| Incident relationship graph | COMPLETE aggregated | Real relationships | API + browser | IOC, user, host, alert, MITRE, evidence, response, events |
| Global search | COMPLETE core | Real parameterized search | API + browser | Typed results and direct incident/attack navigation |
| Web statistics/top lists | COMPLETE | Real data | Yes | No hardcoded operational values |
| Sysmon parser | COMPLETE boundary | Real | Yes | Representative record tested |
| Zeek / Suricata / Cowrie parsing | IMPLEMENTED | Real | Partial | Live sensors not run |
| Sigma detection | COMPLETE subset | Real | Yes | Unsupported syntax rejected |
| MITRE mapping | COMPLETE subset | Real | Yes | Bundled rules only |
| Alert deduplication | COMPLETE | Real | Yes | Rule/event fingerprint |
| Correlation | COMPLETE deterministic | Real | Yes | Host/IOC + technique + 4h bucket |
| Incidents / IOC / timeline | COMPLETE core | Real | Yes | Unified detail API/UI |
| Explainable risk | COMPLETE core | Real | Yes | Persisted score and reasons |
| CTI abstraction/failures | COMPLETE boundary | Real HTTP + mocked transport tests | Yes | Live provider requests not run |
| External Wazuh/Velociraptor/etc. | PARTIAL/OPTIONAL | Boundary | No live service | Never claimed healthy blindly |
| Evidence collection | COMPLETE demo, PARTIAL live | Demo mock | Yes | Visibly attributed mocks |
| YARA | PARTIAL/OPTIONAL | Runtime boundary + demo mock | Yes for degradation | No local executable in workspace |
| Response policy / approval | COMPLETE | Real policy | Yes | Seven typed actions; source rate limit/block included |
| Analyst response console | COMPLETE core | Real policy/targets | API + browser | Guardrails, impact, confirmation, approval/denial reason, SSE state |
| Dry-run response truthfulness | COMPLETE | Real state guard | Yes | `DRY_RUN`, executed=false, never confirmed containment |
| Real containment | NOT IMPLEMENTED | None | No | Fails closed |
| Response idempotency | COMPLETE | Real | Yes | Unique key + state guards |
| Audit | COMPLETE core | Real | Yes | Critical workflow actions |
| Hunt | COMPLETE basic | Real | Yes | Controlled parameters, no SQL input |
| Reports PDF/JSON/CSV/ZIP | COMPLETE | Real incident data | Yes | ZIP contains evidence references |
| Endpoint demo/reset/repeat | COMPLETE | Controlled + labeled mocks | Yes | No attack execution |
| Web replay/reset/repeat | COMPLETE | SIMULATED | Yes | 11 inert records, SSE, incident, DRY_RUN, reports |
| Integration enable/disable/test | COMPLETE state control | Real state | Yes | Secrets remain environment-only |
| Dashboard | COMPLETE primary workflow | Real API data | Build + real-browser inspection | Live Monitor, Attacks, Web Security, detail drawer |
| OpenSearch indexing | IMPLEMENTED | Real HTTP | No live service | Graceful degradation |
| Docker core | VERIFIED LOCALLY | PostgreSQL + OpenSearch + backend + frontend | Yes | Healthy Compose stack; see RELEASE_STATUS.md |
| Container restart/failure recovery | NOT VERIFIED | — | No | Requires Docker release QA |
| Full external SOC deployment | OPTIONAL/PARTIAL | External | No | Products not bundled |
