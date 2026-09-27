# Connector matrix and configuration

`REAL` means the adapter performs a documented protocol request or local normalization. It does **not** mean the external service was available in the implementation environment. `BOUNDARY` means configuration and health/error state exist, but requested product operations are intentionally not claimed complete.

| Connector | Delivered mode | Configuration | Implemented/tested scope | Runtime verification |
|---|---|---|---|---|
| OpenSearch | REAL HTTP | `GHOSTSOC_OPENSEARCH_URL`, optional credentials/TLS | Event indexing; failure degradation | Code tested indirectly; live service NOT RUN |
| Wazuh | BOUNDARY | URL + bearer token | URL validation, authenticated health boundary | External service NOT RUN |
| Sysmon | REAL local | none | Process/network field normalization and ingestion | Automated test PASS |
| Sigma | REAL local subset | `backend/rules` | Load, validate, match, reject unsupported conditions | Automated test PASS |
| MITRE ATT&CK | REAL local subset | bundled metadata | Tactic/technique mapping and measured coverage | Automated demo PASS |
| Velociraptor | BOUNDARY + DEMO_MOCK | URL + token | Status/config contract; safe demo evidence | External collection NOT RUN |
| YARA | OPTIONAL local + DEMO_MOCK | installed `yara` executable | Runtime status; labeled demo result | Local executable unavailable |
| Zeek | REAL ingestion | API submission | JSON log normalization | Unit path implemented; live sensor NOT RUN |
| Suricata | REAL ingestion | API submission | EVE JSON normalization and high-alert detection | Unit path implemented; live sensor NOT RUN |
| Arkime | BOUNDARY | URL | Validated status boundary | External service NOT RUN |
| MISP | BOUNDARY | URL + API key | Config/status contract | External service NOT RUN |
| OpenCTI | BOUNDARY | URL + token | Config/status contract | External service NOT RUN |
| ThreatFox | REAL HTTP | abuse.ch Auth-Key | Exact IOC/hash lookup, normalized records/errors | Mocked HTTP transport PASS; live request NOT RUN |
| URLhaus | REAL HTTP | abuse.ch Auth-Key | URL lookup, normalized errors | timeout/rate/malformed tests PASS; live request NOT RUN |
| AbuseIPDB | REAL HTTP | API key | IP lookup, auth/rate handling | mocked success boundary/failure PASS; live NOT RUN |
| MalwareBazaar | REAL HTTP | abuse.ch Auth-Key | Hash lookup and attribution | code path implemented; live NOT RUN |
| VirusTotal | REAL HTTP | API key | IP/domain/URL/hash lookup | code path implemented; live NOT RUN |
| Cowrie | REAL ingestion | API submission | Controlled JSON event normalization | code path implemented; live honeypot NOT RUN |
| Shuffle | BOUNDARY | URL + API key | Optional status boundary | external workflow NOT RUN |
| Atomic Red Team | DOCUMENTED FIXTURE | none | T1059.001 expected telemetry/detection mapping; no host execution | deterministic fixture PASS |

## Status vocabulary

- `DISABLED`: connector administratively disabled.
- `API_KEY_REQUIRED`: backend provider key absent.
- `NOT_CONFIGURED`: required service endpoint absent.
- `UNAVAILABLE`: attempted dependency/runtime not reachable.
- `AUTHENTICATION_ERROR`: the provider explicitly rejected credentials.
- `DEGRADED`: reachable but unhealthy/unexpected response.
- `HEALTHY`: local capability loaded or a configured health request succeeded.

No static UI value forces an external connector to `HEALTHY`. The Integration Hub can enable/disable adapters and run bounded health checks; enablement state and audit records are persisted. Secrets remain environment-only and are never returned to the browser.

## CTI behavior

Provider requests are backend-only and use seven-second timeouts, one bounded retry for network/5xx errors, no redirect following, rate-limit/auth classification, normalized output, and provider references. Successful results are persisted on the IOC and reused for one hour with `status=CACHED`; failed/auth/rate-limited responses are not cached. The demo's controlled CTI fixture uses provider `GhostSOC Controlled Fixture`, `mock: true`, and a fixture reference; it is never represented as an external result.

## Private SOC endpoints

Internal Wazuh/OpenSearch/etc. normally resolve to private addresses. Set `GHOSTSOC_ALLOW_PRIVATE_CONNECTORS=true` only for an intentional trusted internal deployment. Public deployments should leave it false and use allowlisted network egress controls in addition to application validation.
