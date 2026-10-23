#!/bin/sh
# Restores a dump of deploy/backup.sh, from the repository root.
# Usage: deploy/restore.sh backups/sentinelapi-<UTC time>.dump
set -eu

dump="${1:?usage: deploy/restore.sh <dump>}"
[ -s "$dump" ] || { echo "restore: $dump is missing or empty" >&2; exit 1; }

# Nothing writes while the data is replaced.
docker compose stop api
# --clean --if-exists drops what the dump holds and recreates it, grants included, so the
# app's role is again limited to INSERT and SELECT (AR-12).
docker compose exec -T postgres \
  sh -c 'pg_restore --clean --if-exists --no-owner --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' < "$dump"
docker compose start api
echo "restore: $dump restored; check it with deploy/verify.sh"
