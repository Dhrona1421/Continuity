#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
[ -f .env ] || { echo "Run ./install.sh first." >&2; exit 1; }
docker compose up -d
docker compose ps
printf 'Continuity: http://localhost:8080\n'
