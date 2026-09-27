# Troubleshooting

## OpenSearch does not start

On Linux:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Allocate at least 4 GB to Docker. Check `docker compose logs opensearch`. Event/incident persistence remains in PostgreSQL, but the default Compose backend waits for OpenSearch health during core startup; fix resource/configuration errors rather than removing the health gate.

## Backend reports production configuration errors

Production rejects demo/default credentials. Generate a random secret of at least 32 characters, set a non-default bootstrap password, and set `GHOSTSOC_DEMO_MODE=false`.

## Connector is NOT_CONFIGURED

Set the documented backend URL/token in `.env`, restart the backend, then invoke **Check health**. For trusted private Wazuh/OpenSearch/etc., `GHOSTSOC_ALLOW_PRIVATE_CONNECTORS=true` is required. Do not put credentials in URLs.

## Connector is UNAVAILABLE or AUTHENTICATION_ERROR

Check DNS/network policy, endpoint TLS, API token scope, and provider rate limits. GhostSOC keeps core incident processing available. The last bounded error is shown without returning credentials.

## Demo returns permission denied

The all-in-one demo includes an approval and requires an administrator (`APPROVE_RESPONSE`). Reset is also admin-class. Confirm `/api/v1/auth/me` reports `ADMIN`.

## No Sigma alert appears

Confirm the event has `event_type=process_creation`, a process ending with `powershell.exe` or `pwsh.exe`, and a command line containing a bundled suspicious flag. View `/api/v1/detections`. Unsupported Sigma conditions are rejected at startup rather than silently ignored.

## Web request target is rejected

Add only the authorized monitored host to `GHOSTSOC_WEB_ALLOWED_HOSTS` and restart the backend. GhostSOC intentionally refuses arbitrary targets. Do not add public systems you do not own or administer.

## Live Monitor says RECONNECTING

Persisted requests and attacks remain safe. Check `/api/v1/live/stream`, reverse-proxy buffering, and backend health. Nginx must not buffer SSE. The current in-process broker is for one API replica; multi-replica production requires a shared broker.

## A real action did not run

Expected. Dry-run is the safe default and no destructive response adapter is claimed in this release. `execution_result.executed=false` is intentional.

## Local development path issues

Run Alembic and Uvicorn from `backend/` so the rules directory and Alembic paths resolve correctly. Use the root `Makefile` targets to avoid path mistakes.

## Report download missing

Reports are stored in `GHOSTSOC_REPORT_DIR`. In Docker this is a named volume. A demo reset removes generated operational reports by server-generated filename but preserves report audit records.
