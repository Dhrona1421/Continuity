# Testing

## One command

After `make install`:

```bash
make verify
```

## Backend

```bash
cd backend
../.venv/bin/ruff check app tests alembic/versions
../.venv/bin/pytest -vv
../.venv/bin/pytest --cov=app --cov-report=term-missing
```

The suite covers:

- liveness/readiness and consistent errors
- login success/failure, Argon2 hashing, production config rejection, RBAC
- rule validation and unsupported-condition rejection
- normalized and Sysmon-compatible ingestion
- detection, alert evidence references, MITRE mapping, deduplication
- deterministic correlation, IOC extraction, explainable risk, hunt filters
- CTI success/timeout/rate limit/invalid key/malformed response with mocked HTTP transport
- connector URL SSRF controls and truthful inventory
- unsafe response rejection, policy minimum risk, backend-derived response targets, viewer authorization, approval/denial reason, idempotency, SSE response updates, and dry-run result
- real-data PDF/JSON/CSV/ZIP output
- complete endpoint demo, reset, and repeat
- exact 35-category web catalog and explicit authorized-signal path for each category
- SQLi/XSS signatures, brute-force/password-spray thresholds, cross-attack correlation
- web target allowlisting, header filtering, secret redaction, duplicate requests
- real backend summary statistics, replay, dry-run response truthfulness, web reset
- SSE broker fan-out/history and frontend live-page browser inspection
- backend-derived SOC trend buckets, network edges, attack relationships, incident graph aggregation, and global search
- real-browser global search navigation, notifications, charts, graph modes, zoom, keyboard node/edge inspection, pagination, overlap detection, and tablet layout

Mocked HTTP tests verify adapter behavior, not live third-party availability. The final measured backend application coverage in this implementation environment is 88% across 41 tests.

## Migrations

```bash
cd backend
GHOSTSOC_DATABASE_URL=sqlite:///./migration-check.db ../.venv/bin/alembic upgrade head
GHOSTSOC_DATABASE_URL=sqlite:///./migration-check.db ../.venv/bin/alembic check
GHOSTSOC_DATABASE_URL=sqlite:///./migration-check.db ../.venv/bin/alembic downgrade base
rm -f migration-check.db
```

For release, repeat `upgrade head` against a fresh PostgreSQL instance.

## Frontend

```bash
cd frontend
npm ci
npm audit
npm run lint
npm run build
```

Important dashboard metrics are fetched from `/api/v1/dashboard`; no hard-coded operational counts are used.

## Docker release gate

```bash
cp .env.example .env
# change secrets
docker compose config
docker compose build --no-cache
docker compose up -d
docker compose ps
curl -fsS http://localhost:8080/api/v1/health
docker compose --profile demo run --rm demo-runner
docker compose logs --no-color backend frontend postgres opensearch
docker compose down
```

This gate is mandatory before a release recommendation. Compose configuration, image builds, database migrations, local startup, and health endpoints were verified on Docker Desktop on 2026-09-27. See `docs/RELEASE_STATUS.md` for current evidence and remaining restart/failure-injection checks.

## Failure injection still needed on a Docker host

The automated suite proves provider and application-level failure isolation. Release QA should additionally restart PostgreSQL, OpenSearch, and backend containers independently and verify recovery/persistence. Those runtime restart tests cannot be substituted by static Compose inspection.
