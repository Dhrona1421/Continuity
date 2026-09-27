#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
docker compose down
printf 'GhostSOC stopped. Persistent volumes were preserved.\n'
