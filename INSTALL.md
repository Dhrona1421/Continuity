# GhostSOC easy installation

This bundle contains the complete GhostSOC source tree. The easiest supported installation uses Docker Compose and does not require manually installing Python, Node.js, PostgreSQL, or OpenSearch.

## Requirements

- 64-bit computer with at least 4 GB free RAM (6–8 GB recommended)
- Docker Desktop on Windows/macOS, or Docker Engine + Compose v2 on Linux
- At least 8 GB free disk space for images and persistent data
- Port 8080 available

Linux OpenSearch requirement:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Persist it using your distribution's `/etc/sysctl.d` configuration before production use.

## Linux or macOS — one command

```bash
chmod +x install.sh start.sh stop.sh
./install.sh
```

The installer:

1. checks Docker and Compose;
2. generates a strong local application secret, administrator password, and PostgreSQL password when `.env` is absent;
3. validates Compose configuration;
4. builds and starts the stack;
5. waits up to five minutes for application health;
6. prints the URL and generated administrator password.

Preflight and environment generation without starting:

```bash
./install.sh --no-start
```

## Windows PowerShell

Start Docker Desktop, open PowerShell in this folder, then run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

Preflight only:

```powershell
.\install.ps1 --no-start
```

## Open Continuity

```text
http://localhost:8080
```

Use the credentials printed by the installer. If `.env` already existed, use the credentials configured there. The Windows installer needs Docker Desktop running first; an elevated PowerShell window is not required for this per-user Docker Desktop setup.

## Daily commands

Linux/macOS:

```bash
./start.sh
./stop.sh
```

Windows:

```powershell
.\start.ps1
.\stop.ps1
```

General Docker commands:

```bash
docker compose ps
docker compose logs -f
docker compose restart backend
docker compose down                 # preserves named volumes
docker compose down -v              # DELETES databases, reports, and evidence
```

## Controlled demos

From the UI, use **Run controlled demo** or **Start controlled web demo**.

CLI containers:

```bash
docker compose --profile demo run --rm demo-runner
docker compose --profile demo run --rm web-demo-runner
```

The demos are simulated/dry-run and do not execute malware, attacks, or real containment.

## Existing `.env`

The installer never overwrites an existing `.env`. To intentionally regenerate local credentials:

```bash
mv .env .env.backup
./install.sh
```

Never commit or share `.env`.

## Troubleshooting

### OpenSearch does not become healthy

- Confirm Docker has enough memory.
- On Linux, set `vm.max_map_count=262144`.
- Run `docker compose logs opensearch`.

### Port 8080 is already in use

Stop the conflicting service or change the frontend port mapping in `docker-compose.yml`.

### Backend migration/startup failure

```bash
docker compose logs backend postgres
docker compose restart postgres backend
```

### Reset only controlled demo records

Use the dashboard reset controls. Do not use `docker compose down -v` unless you intend to delete all persistent data.

## Security before non-demo deployment

- Set `GHOSTSOC_DEMO_MODE=false`.
- Keep `GHOSTSOC_DEMO_AUTO_ACCESS=false`.
- Set `GHOSTSOC_SESSION_COOKIE_SECURE=true` behind HTTPS.
- Use a reverse proxy/TLS ingress and rate limiting.
- Store production secrets in a platform secret manager.
- Enable OpenSearch security/TLS; the included OpenSearch configuration is intended for isolated local/demo use.
- Configure only authorized endpoint and web targets.

See `README.md`, `docs/SECURITY.md`, and `docs/TROUBLESHOOTING.md` for full details.
