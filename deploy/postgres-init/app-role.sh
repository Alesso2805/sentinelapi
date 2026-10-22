#!/bin/sh
# The role the API connects as. `sentinel migrate --app-role sentinel_app` then grants it
# INSERT and SELECT on the audit table and nothing else, so the trail is append-only (AR-12).
# Postgres runs this once, when its data volume is first created.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --set app_password="$SENTINEL_APP_DB_PASSWORD" <<'SQL'
CREATE ROLE sentinel_app LOGIN PASSWORD :'app_password';
SQL
