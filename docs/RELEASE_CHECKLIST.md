# GhostSOC Release Checklist

A release is **not** considered production-ready until every mandatory gate below has a recorded successful run.

## 1. Source hygiene

- [ ] No `.env`, database, cache, bytecode, build, or dependency directories are tracked.
- [ ] `git status --short` is clean before packaging.
- [ ] Release version and changelog are updated.
- [ ] `RELEASE-MANIFEST.json` is regenerated.
- [ ] SHA-256 checksums are generated for release archives.

## 2. Application gates

- [ ] `make verify` passes.
- [ ] Backend coverage remains at or above the CI threshold.
- [ ] Frontend lint and production build pass.
- [ ] Alembic upgrade/check/downgrade pass on a clean database.
- [ ] Production configuration rejects demo mode, default secrets, insecure cookies, and demo auto-access.
- [ ] Security Memory search shows only Hindsight-recalled facts; source links appear only for retained provenance, and recommendation history uses matched source records.
- [x] Groq recommendation path was live-verified with Hindsight using `openai/gpt-oss-120b`.

## 3. Docker gates

Run on a clean host with Docker Engine + Compose v2:

```bash
docker compose config --quiet
docker compose build --no-cache
docker compose up -d
docker compose ps
curl -fsS http://localhost:8080/api/v1/health
curl -fsS http://localhost:8080/api/v1/ready
docker compose --profile demo run --rm demo-runner
docker compose --profile demo run --rm web-demo-runner
```

Then verify persistence/recovery:

```bash
docker compose restart backend
# verify health and persisted incidents

docker compose restart opensearch
# verify API remains healthy and search recovers

docker compose restart postgres
# verify API recovers and data remains present
```

Finally:

```bash
docker compose logs --no-color backend frontend postgres opensearch
docker compose down
```

## 4. Production deployment gates

For an internet-facing deployment:

- [ ] `GHOSTSOC_ENV=production`.
- [ ] A unique 32+ character random `GHOSTSOC_SECRET_KEY` is supplied through a secret manager.
- [ ] Bootstrap credentials are unique and rotated after first login.
- [ ] `GHOSTSOC_DEMO_MODE=false`.
- [ ] `GHOSTSOC_DEMO_AUTO_ACCESS=false`.
- [ ] `GHOSTSOC_DRY_RUN=true` unless a verified response adapter has been explicitly deployed and tested.
- [ ] `GHOSTSOC_SESSION_COOKIE_SECURE=true`.
- [ ] CORS contains only the real frontend origin(s).
- [ ] `GHOSTSOC_WEB_ALLOWED_HOSTS` contains only authorized application hosts.
- [ ] `GHOSTSOC_AUTHORIZED_TARGETS` contains only approved assets.
- [ ] `GHOSTSOC_ALLOW_PRIVATE_CONNECTORS=false` unless private connector access is intentional and documented.
- [ ] TLS is terminated by a trusted ingress/reverse proxy.
- [ ] PostgreSQL is backed up and restore-tested.
- [ ] OpenSearch security/TLS is enabled; the bundled insecure OpenSearch mode is for isolated local/demo use only.
- [ ] Application, database, search, and audit logs have retention and monitoring.
- [ ] Rate limiting is enforced at the ingress for login and other externally exposed endpoints.
- [ ] External connector credentials are stored in a secret manager and individually tested.

## 5. Release artifact

Use:

```bash
python scripts/package_release.py --output release
```

Publish the generated source archive, easy-install archive, tarball, and SHA-256 checksum file together with release notes.
