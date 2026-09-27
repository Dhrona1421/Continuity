# Web security monitoring

GhostSOC monitors **authorized allowlisted web targets**. Requests for targets outside `GHOSTSOC_WEB_ALLOWED_HOSTS` are rejected. The module normalizes access/security logs, applies conservative signatures, behavioral thresholds, or explicit upstream WAF/application signals, and reuses the existing SecurityEvent → Alert → Incident → Risk → Response → Audit → Report pipeline.

## Live architecture

```text
Authorized website / reverse proxy / WAF
  → POST /api/v1/web/requests
  → WebRequest + normalized SecurityEvent
  → 35-category reusable detection catalog
  → aggregated AttackDetection
  → existing Alert + correlated Incident
  → IOC / risk / investigation
  → policy-controlled DRY_RUN or verified adapter action
  → SSE live stream + audit + reports
```

The live UI uses Server-Sent Events (`/api/v1/live/stream`) and reloads persisted records after reconnect. PostgreSQL/SQLite remains authoritative; the in-process stream is notification-only.

## Detection truth model

- **SIGNATURE**: conservative request/header pattern; starts as `SUSPICIOUS`.
- **BEHAVIORAL**: time-window frequency, account diversity, session reuse, rate, or concurrency.
- **CONTEXT/CONFIGURATION SIGNAL**: requires an authorized upstream application, WAF, scanner, or policy engine. GhostSOC does not infer IDOR, CSRF, or business-logic exploitation from a URL alone.
- **Repetition**: three aggregate matches become `LIKELY_ATTACK`; eight or a trusted upstream signal becomes `CONFIRMED_ATTACK`.
- Analysts can mark detections `FALSE_POSITIVE`; this is audited.

## 35-category matrix

| # | Attack category | Family | Detection mode | Rule | MITRE | Verification |
|---:|---|---|---|---|---|---|
| 1 | SQL Injection | INJECTION | SIGNATURE OR SIGNAL | `GS-WEB-001` | T1190 | Signal path; representative signatures tested |
| 2 | Cross-Site Scripting (XSS) | CLIENT SIDE | SIGNATURE OR SIGNAL | `GS-WEB-002` | T1189 | Signal path; representative signatures tested |
| 3 | Cross-Site Request Forgery (CSRF) | CLIENT SIDE | CONTEXT SIGNAL | `GS-WEB-003` | T1190 | Explicit context-signal test |
| 4 | IDOR / Broken Access Control | AUTHORIZATION | CONTEXT SIGNAL | `GS-WEB-004` | T1190 | Explicit context-signal test |
| 5 | Brute-Force Attack | AUTHENTICATION | BEHAVIORAL OR SIGNAL | `GS-WEB-005` | T1110 | Signal path; representative behavior tested |
| 6 | Credential Stuffing | AUTHENTICATION | BEHAVIORAL OR SIGNAL | `GS-WEB-006` | T1110.004 | Signal path; representative behavior tested |
| 7 | Password Spraying | AUTHENTICATION | BEHAVIORAL OR SIGNAL | `GS-WEB-007` | T1110.003 | Signal path; representative behavior tested |
| 8 | Session Hijacking | AUTHENTICATION | CONTEXT SIGNAL | `GS-WEB-008` | T1539 | Explicit context-signal test |
| 9 | Command Injection | INJECTION | SIGNATURE OR SIGNAL | `GS-WEB-009` | T1059 | Signal path; representative signatures tested |
| 10 | Path Traversal | SERVER FILE | SIGNATURE OR SIGNAL | `GS-WEB-010` | T1190 | Signal path; representative signatures tested |
| 11 | Malicious File Upload | SERVER FILE | CONTEXT OR SIGNATURE | `GS-WEB-011` | T1105 | Signal path; representative signatures tested |
| 12 | Server-Side Request Forgery (SSRF) | SERVER FILE | SIGNATURE OR SIGNAL | `GS-WEB-012` | T1190 | Signal path; representative signatures tested |
| 13 | Security Misconfiguration | SERVER FILE | CONFIGURATION SIGNAL | `GS-WEB-013` | T1190 | Explicit context-signal test |
| 14 | Information Disclosure | SERVER FILE | SIGNATURE OR SIGNAL | `GS-WEB-014` | T1552 | Signal path; representative signatures tested |
| 15 | Open Redirect | CLIENT SIDE | SIGNATURE OR SIGNAL | `GS-WEB-015` | T1189 | Signal path; representative signatures tested |
| 16 | XML External Entity (XXE) | INJECTION | SIGNATURE OR SIGNAL | `GS-WEB-016` | T1190 | Signal path; representative signatures tested |
| 17 | Insecure Deserialization | SERVER FILE | SIGNATURE OR SIGNAL | `GS-WEB-017` | T1190 | Signal path; representative signatures tested |
| 18 | HTTP Request Smuggling | HTTP API | HEADER OR SIGNAL | `GS-WEB-018` | T1190 | Signal path; representative signatures tested |
| 19 | Business Logic Abuse | AUTHORIZATION | CONTEXT OR BEHAVIOR | `GS-WEB-019` | T1190 | Signal path; representative behavior tested |
| 20 | API Attack | HTTP API | SIGNATURE BEHAVIOR SIGNAL | `GS-WEB-020` | T1190 | Signal path; representative signatures tested |
| 21 | Host Header Injection | HTTP API | HEADER OR SIGNAL | `GS-WEB-021` | T1190 | Signal path; representative signatures tested |
| 22 | HTTP Parameter Pollution | INJECTION | STRUCTURE OR SIGNAL | `GS-WEB-022` | T1190 | Signal path; representative signatures tested |
| 23 | Clickjacking | CLIENT SIDE | CONFIGURATION SIGNAL | `GS-WEB-023` | T1189 | Explicit context-signal test |
| 24 | Web Cache Poisoning | CACHE INFRASTRUCTURE | HEADER BEHAVIOR SIGNAL | `GS-WEB-024` | T1190 | Signal path; representative behavior tested |
| 25 | Web Cache Deception | CACHE INFRASTRUCTURE | CONTEXT SIGNAL | `GS-WEB-025` | T1190 | Explicit context-signal test |
| 26 | Prototype Pollution | CLIENT SIDE | SIGNATURE OR SIGNAL | `GS-WEB-026` | T1190 | Signal path; representative signatures tested |
| 27 | Server-Side Template Injection (SSTI) | INJECTION | SIGNATURE OR SIGNAL | `GS-WEB-027` | T1190 | Signal path; representative signatures tested |
| 28 | Local File Inclusion (LFI) | INJECTION | SIGNATURE OR SIGNAL | `GS-WEB-028` | T1190 | Signal path; representative signatures tested |
| 29 | Remote File Inclusion (RFI) | INJECTION | SIGNATURE OR SIGNAL | `GS-WEB-029` | T1105 | Signal path; representative signatures tested |
| 30 | Race Condition Attack | CACHE INFRASTRUCTURE | BEHAVIORAL OR SIGNAL | `GS-WEB-030` | T1190 | Signal path; representative behavior tested |
| 31 | CORS Misconfiguration | HTTP API | CONFIGURATION SIGNAL | `GS-WEB-031` | T1190 | Explicit context-signal test |
| 32 | JWT Attack | AUTHENTICATION | SIGNATURE OR SIGNAL | `GS-WEB-032` | T1539 | Signal path; representative signatures tested |
| 33 | API Rate-Limit Bypass | HTTP API | BEHAVIORAL OR SIGNAL | `GS-WEB-033` | T1499 | Signal path; representative behavior tested |
| 34 | GraphQL Attack | HTTP API | SIGNATURE OR SIGNAL | `GS-WEB-034` | T1190 | Signal path; representative signatures tested |
| 35 | WebSocket Attack | HTTP API | PROTOCOL OR SIGNAL | `GS-WEB-035` | T1190 | Explicit context-signal test |

All 35 definitions are synchronized into the existing `detection_rules` table and are tested through the API with authorized structured signals. Representative signatures, behavioral brute-force/password-spray escalation, cross-attack incident correlation, redaction, target allowlisting, duplicate requests, summary statistics, replay, reporting, and reset have dedicated tests.

## Request ingestion schema

Required: request ID, timestamp, source IP, allowlisted target host, HTTP method, path, and status code. Optional: query string, safe headers, bounded body excerpt, latency, response size, username, session identifier, metadata, and upstream signals. Authorization/cookie headers are discarded; likely secrets in query/body excerpts are redacted. Session identifiers are stored only as SHA-256 hashes.

## Controlled replay

`POST /api/v1/demo/web-run` submits 11 inert records covering normal traffic, SQL injection, XSS, traversal/LFI, repeated login failures/password spray, GraphQL introspection, and SSRF. It performs a pre-approved **dry-run** source rate-limit action and records `executed=false`. It generates PDF/JSON/CSV/ZIP reports. Web incidents include `web_attacks` in JSON and `web-attacks.json` in the evidence ZIP. `POST /api/v1/demo/web-reset` removes only controlled web-demo operational records and files.

## What this module does not do

It is not a WAF, DDoS scrubbing service, vulnerability scanner, or offensive testing engine. It does not transmit attack payloads to a website. Real blocking/rate limiting requires a separately implemented and verified reverse-proxy/firewall adapter; without one, GhostSOC fails closed and displays `DRY_RUN`, never `BLOCKED` or `CONTAINED`.
