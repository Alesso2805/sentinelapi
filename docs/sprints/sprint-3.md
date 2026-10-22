# Sprint 3 — A three-line integration and an audit trail that is migrated, private and flood-proof (SEN-22 to SEN-26)

**Status as of 2026-10-22:** started right after Sprint 2, with no calendar. 18 points.

**Order:** SEN-22 (the installer is where the audit sink plugs in), SEN-23, SEN-24, SEN-25, SEN-26.

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-22 | #15 | `sentinelapi/integration.py`: `install_sentinel(app, settings, on_event=...)` builds the backend, the three detectors, the client resolver and the audit sink (`audit/sink.py`), adds the middleware, starts and stops them inside the app's own lifespan (closing Redis, which nothing closed before), and returns a `Sentinel`; its `login_guard` wraps the login's password check. `SentinelMiddleware` is pure ASGI. Every event goes to the log, the audit sink and `on_event`; a failing sink is logged and never fails the request. `SENTINEL_AUDIT=false` keeps events in the log only. The demo uses all of it | The README's snippet is extracted and executed as a test; streaming responses and background tasks pass through; a raising `on_event` leaves the 429 in place; the app's own lifespan still runs and the backend is closed; AR-18 holds, so its strict xfail is gone. 137 passed, 8 xfailed |
| SEN-23 | #16 | `sentinelapi/audit/migrations/`: an Alembic history with its own version table (`sentinel_alembic_version`), run on an async connection by `sentinelapi.audit.migrate` and by the new `sentinel migrate` command. Revision 0001 creates the table with timestamptz columns, CHECKs on type and level and its indexes; `--app-role` (or `SENTINEL_AUDIT_APP_ROLE`) grants that Postgres role INSERT and SELECT only. No `create_all`: a sink on an unmigrated database logs `audit_table_not_migrated`. `UTCDateTime` keeps times aware on SQLite. Postgres joins CI. Compose migrates before starting the API (its own service in SEN-29). AR-16's last exception is gone | On SQLite and Postgres: upgrade, `alembic check` clean, downgrade to base and up again, an unknown threat type refused by the database; on Postgres the app role can INSERT and SELECT but UPDATE and DELETE get "permission denied" (AR-11 and AR-12, their placeholders replaced). The wheel ships the migrations and the `sentinel` script; the Compose stack migrated and stored timestamptz events. The 75 `utcnow` warnings are gone. 146 passed, 6 xfailed |
| SEN-24 | #17 | `sentinelapi/privacy.py`: an HMAC-SHA256 `Pseudonymizer` under `SENTINEL_AUDIT_HASH_KEY` (a random key per process, with a warning, when unset). The audit row stores it for the fingerprint, the address (`client_hash`) and the account (`subject_hash`, from a new `SecurityEvent.subject`: the brute-force account's opaque id, never the username); the security log carries the same hashes. Migration 0002 drops `ip` and `user_id`. `detail` no longer quotes tokens (exception names and missing-claim names only) nor `jti`s. `sentinel purge` deletes rows past `SENTINEL_AUDIT_RETENTION_DAYS`, as the owner | AR-13 holds, so its strict xfail is gone: after ten failures and a login, rows and captured log lines contain no username, address or token. Keyed hashes are deterministic, differ by key and are not a plain SHA-256; `purge` deletes 91-day-old rows and keeps 89-day-old ones; migrations still reverse cleanly and match the models on SQLite and Postgres. 154 passed, 5 xfailed |
| SEN-25 | — | — | — |
| SEN-26 | — | — | — |

## Sprint decisions

—

## Changes to the specification in this sprint

—

## Retro

- **Went well:** —
- **To improve:** —
- **To try:** —
