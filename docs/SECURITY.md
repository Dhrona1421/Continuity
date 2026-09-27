# GhostSOC security model

## Response safety

GhostSOC has no shell, PowerShell, arbitrary SQL, unrestricted file, or arbitrary connector-query endpoint. Event data, CTI output, report content, and UI strings are never interpolated into commands.

Accepted response types:

- `COLLECT_EVIDENCE`
- `QUARANTINE_FILE`
- `TERMINATE_PROCESS`
- `BLOCK_IOC`
- `BLOCK_SOURCE`
- `RATE_LIMIT_SOURCE`
- `ISOLATE_ENDPOINT`

Each request passes authentication, backend authorization, policy minimum risk, action allowlist, action-specific target validation, approval state, audit creation, execution guard, result recording, and incident timeline update. The UI obtains target options from the backend response context and provides no free-form command or target field. Exact idempotency keys are unique. Reusing a key with changed parameters returns conflict.

`GHOSTSOC_DRY_RUN=true` is the default. Dry-run results explicitly store `execution_status=DRY_RUN` and `executed=false`. They do not mark incidents contained. Confirmed containment requires a non-dry-run adapter result with `executed=true` and `verified=true`. Setting dry-run false without a verified adapter fails closed.

## RBAC

| Permission | ADMIN | ANALYST | VIEWER |
|---|---:|---:|---:|
| View events/incidents | yes | yes | yes |
| Manage incidents | yes | yes | no |
| Run investigation | yes | yes | no |
| Execute response request | yes | yes | no |
| Approve response | yes | no | no |
| Manage connectors/rules | yes | no | no |
| Export reports | yes | yes | no |
| View audit | yes | yes | no |

The controlled all-in-one demo requires approval permission; reset requires connector-management permission.

`GHOSTSOC_DEMO_AUTO_ACCESS` is disabled by default and is an explicit authentication bypass for isolated judge/demo instances only. Configuration validation permits it only when both demo mode and dry-run are enabled and always rejects it in production. Do not enable it on a shared or externally trusted deployment.

## Credentials and identity

- Passwords are hashed using Argon2 via `argon2-cffi`.
- JWTs are HS256-signed with issuer, audience, issued-at, not-before, and expiry claims.
- API clients use standard Bearer authentication. The browser dashboard also receives the signed JWT in an HTTP-only session cookie, avoiding dependence on proxy-forwarded authorization headers. Secure embedded deployments set `GHOSTSOC_SESSION_COOKIE_SECURE=true`, producing `Secure; SameSite=None`; local HTTP uses `SameSite=Lax`. Cross-site iframe deployments may additionally enable `GHOSTSOC_SESSION_COOKIE_PARTITIONED=true` for a CHIPS partitioned cookie.
- `X-GhostSOC-Token` remains a same-origin compatibility fallback and is never logged.
- Production settings reject the known development secret, demo bootstrap password, and enabled demo mode.
- API keys and connector tokens are environment-only and never returned by connector views.
- Login errors do not reveal whether an email exists.

For production, use a randomly generated secret, disable demo mode, rotate/remove the bootstrap credential, terminate TLS at a trusted ingress, add centralized login rate limiting, and store secrets in a platform secret manager.

## Input and network controls

- Pydantic bounds input lengths, enumerations, ports, and idempotency syntax.
- Hunt supports predefined filters/ILIKE values through SQLAlchemy parameters; it does not accept SQL.
- Response targets reject command metacharacters and must match exact authorized endpoint, endpoint/PID, attached IOC, or SHA-256 shapes.
- Connector URLs allow HTTP(S) only, reject URL-embedded credentials, do not follow redirects, and block private/reserved resolution by default.
- Web request targets must match `GHOSTSOC_WEB_ALLOWED_HOSTS`; authorization/cookie headers are discarded, likely secrets are redacted, and session identifiers are hashed.
- Context-dependent attack types require explicit authorized WAF/application signals rather than inference from a URL alone.
- Report names are server generated and resolved below one configured directory.
- CORS uses an explicit origin list; credentials are enabled only for the HTTP-only browser session cookie.

## Container controls

- Backend and frontend images run as non-root users.
- `no-new-privileges` is enabled.
- Only the frontend port is exposed to the host by default.
- PostgreSQL and OpenSearch use internal Compose networking and persistent volumes.
- Production OpenSearch security/TLS must be enabled. The Compose file disables its security plugin only for the isolated local core/demo experience.

## Logging and audit

Application logs are structured JSON and avoid request bodies/tokens. Correlation IDs flow to responses and audit records. Audit covers login, ingestion, incident updates, response request/approval, reports, demo execution, and reset. Database administrators remain in the trust boundary; tamper-evident remote audit storage is a future hardening item.

## Security review limitations

Automated tests cover RBAC, password hashing, unsafe response targets, idempotency, connector SSRF rules, malformed external data, all 35 web categories through authorized signals, representative request signatures, behavioral escalation, target allowlisting, redaction, cross-attack correlation, and truthful dry-run state. No dynamic container scan, live penetration test, or external connector credential test was possible in the implementation workspace. Do not interpret this document as an independent security certification.
