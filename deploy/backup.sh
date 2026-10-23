#!/bin/sh
# Dumps SentinelAPI's audit database, from the repository root.
# Usage: deploy/backup.sh [file], backups/sentinelapi-<UTC time>.dump by default.
# On the server, .env's COMPOSE_FILE names both compose files (docs/runbooks/deploy.md).
set -eu

target="${1:-backups/sentinelapi-$(date -u +%Y%m%dT%H%M%SZ).dump}"
mkdir -p "$(dirname "$target")"

# As the owner, inside the postgres container; --format=custom is compressed and what pg_restore reads.
docker compose exec -T postgres \
  sh -c 'pg_dump --format=custom --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' > "$target"

[ -s "$target" ] || { echo "backup: $target is empty" >&2; exit 1; }
echo "backup: $target ($(wc -c < "$target") bytes)"
