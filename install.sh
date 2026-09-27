#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
NO_START=false
[ "${1:-}" = "--no-start" ] && NO_START=true

fail() {
  printf 'GhostSOC installer: %s\n' "$1" >&2
  exit 1
}

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  elif command -v od >/dev/null 2>&1; then
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
  else
    fail "openssl or od is required to generate secure local credentials"
  fi
}

command -v docker >/dev/null 2>&1 || fail "Docker is not installed. See INSTALL.md."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required."
docker info >/dev/null 2>&1 || fail "Docker is installed but the daemon is not running."

GENERATED=false
ADMIN_PASSWORD=""
if [ ! -f .env ]; then
  [ -f .env.example ] || fail ".env.example is missing"
  SECRET_KEY=$(random_hex 32)
  ADMIN_PASSWORD=${GHOSTSOC_ADMIN_PASSWORD:-$(random_hex 18)}
  POSTGRES_PASSWORD=$(random_hex 24)
  awk -v secret="$SECRET_KEY" -v admin="$ADMIN_PASSWORD" -v pg="$POSTGRES_PASSWORD" '
    /^GHOSTSOC_SECRET_KEY=/ { print "GHOSTSOC_SECRET_KEY=" secret; next }
    /^GHOSTSOC_BOOTSTRAP_ADMIN_PASSWORD=/ { print "GHOSTSOC_BOOTSTRAP_ADMIN_PASSWORD=" admin; next }
    /^POSTGRES_PASSWORD=/ { print "POSTGRES_PASSWORD=" pg; next }
    { print }
  ' .env.example > .env
  chmod 600 .env 2>/dev/null || true
  GENERATED=true
  printf 'Created .env with generated local credentials.\n'
else
  printf 'Using existing .env; no credentials were overwritten.\n'
fi

docker compose config >/dev/null || fail "docker-compose.yml or .env validation failed"

if [ "$NO_START" = true ]; then
  printf 'Preflight passed. Start later with ./start.sh\n'
  exit 0
fi

printf 'Building and starting GhostSOC. OpenSearch can take several minutes on first start...\n'
docker compose up -d --build

printf 'Waiting for GhostSOC health'
i=0
healthy=false
while [ "$i" -lt 100 ]; do
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 4 http://localhost:8080/api/v1/health >/dev/null 2>&1 && healthy=true
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 4 -O /dev/null http://localhost:8080/api/v1/health >/dev/null 2>&1 && healthy=true
  else
    docker compose exec -T backend python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3)" >/dev/null 2>&1 && healthy=true
  fi
  [ "$healthy" = true ] && break
  printf '.'
  i=$((i + 1))
  sleep 3
done
printf '\n'

if [ "$healthy" != true ]; then
  docker compose ps >&2 || true
  docker compose logs --tail=120 backend frontend postgres opensearch >&2 || true
  fail "services did not become healthy within 5 minutes; see INSTALL.md troubleshooting"
fi

printf '\nGhostSOC is ready: http://localhost:8080\n'
if [ "$GENERATED" = true ]; then
  printf 'Email: admin@ghostsoc.local\n'
  printf 'Password: %s\n' "$ADMIN_PASSWORD"
  printf 'Save this password now. It remains in .env and is not written to another file.\n'
else
  printf 'Use the administrator email/password configured in .env.\n'
fi
printf 'Status: docker compose ps\nLogs:   docker compose logs -f\nStop:   ./stop.sh\n'
