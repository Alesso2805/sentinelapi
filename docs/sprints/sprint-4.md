# Sprint 4 — A production-ready stack and the attack console (SEN-27 to SEN-32)

**Status as of 2026-10-22:** started right after Sprint 3, with no calendar. 18 points. Since #20 no architecture rule is marked xfail: all 18 hold.

**Order:** SEN-27, SEN-28, SEN-29, SEN-30, SEN-32 (it needs SEN-26's events), SEN-31.

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-27 | #20 | `SENTINEL_ENV=production` refuses, in one error naming each problem: a JWT secret that is an example value or under 32 bytes, a missing or short `SENTINEL_AUDIT_HASH_KEY`, and the memory backend unless `SENTINEL_ALLOW_MEMORY_BACKEND=true`. `SENTINEL_BACKEND` accepts only `memory` or `redis` in any environment | AR-10 holds, so the last strict xfails are gone. Each unsafe case changes one thing in an otherwise safe production configuration; every problem named at once; the memory backend allowed on purpose; development starts with the defaults; `Redis` (a typo) fails. 177 passed, 0 xfailed |
| SEN-28 | #21 | Multi-stage Dockerfile on `python:3.12.15-slim-bookworm` with `uv` 0.11.25 copied from its pinned image; `uv sync --locked --no-dev --no-editable` with the `demo`, `redis` and `postgres` extras, dependencies in their own cached layer; a non-root user (uid 10001); `HEALTHCHECK` on `/health` with the standard library (no curl in a slim image); a `.dockerignore` that keeps tests, docs, databases and the agent's files out. CI job "Image builds and starts", now required on `main` | Built and run locally: healthy, `/health` 200, user `sentinel` (10001), no pytest, Ruff, Mypy or httpx inside, 317 MB; the same checks in the new CI job |
| SEN-29 | #22 | `docker-compose.yml`: `migrate` runs `sentinel migrate` once as the owner and exits; the API waits for it and connects as `sentinel_app`, created by `deploy/postgres-init/app-role.sh` and granted INSERT and SELECT only; Redis and Postgres pinned and unpublished; every secret overridable from `.env`. `deploy/docker-compose.prod.yml`: `SENTINEL_ENV=production`, secrets required (`${...:?}`), the API unpublished and trusting only the private ranges, Caddy pinned by digest as in VeriLedger. CI job "Full stack from an empty database", required on `main` | Locally, from empty volumes: migrate exit 0, only the API published, 8 wrong passwords then 429, the operator reads the event, the app role gets "permission denied" on DELETE, `sentinel purge` runs as the owner. The server overlay rehearsed on ports 18080/18443 with `SENTINEL_HOSTNAME=localhost`: HTTPS `/health` 200, API unpublished, `production` with Redis, and 61 requests each with a different forged `X-Forwarded-For` still got the 429 at the 61st, because Caddy replaces the header |
| SEN-30 | #23 | `GET /ready`: `Sentinel.ready()` pings the counter backend and checks the audit database is reachable and migrated, each within 2 s, and the demo answers 503 with the failing checks. The middleware gives every request an id (the caller's `X-Request-ID` if well formed, a new one otherwise), returns it in the response and binds it to every log line of the request; the demo logs JSON in production, tracebacks as fields | Ready with both up; 503 with no database, with an unmigrated one, and with Redis unreachable; ids on every response and on a 429, a caller's kept and a malformed one replaced; the 429's security event logged with the response's id; a production log line is one JSON object with `request_id`. 185 passed |
| SEN-32 | #24 | `examples/demo_app/console.py` and `static/`: the page at `/`, `POST /demo/scenarios/{burst,stuffing,replay}` and `GET /demo/events` (SSE), only with `SENTINEL_DEMO_MODE`. Each run uses `Sentinel.sandbox()`, the real detectors on a fresh memory backend, with synthetic sources from RFC 5737; every verdict goes through `Sentinel.report` (log, audit) and to the visitor's own stream, keyed by an HttpOnly, SameSite=Strict session cookie. 10 runs per hour per address. A strict CSP, no third-party script, light and dark themes, usable at 390 px. A CI job runs it in Chromium | Burst blocked from request 61 with `Retry-After`; stuffing locks the account at the 8th failure from 8 addresses and refuses the owner too; a replayed token gets 403 and a forged one 401; two runs give identical steps; a run reaches the operator's events API; the 11th run in an hour gets 429; without demo mode `/`, the scenarios and the static files are 404; a visitor's stream carries only their events. In Chromium: the keyboard alone runs the burst, the live event arrives, and axe-core finds no serious or critical violation before, after and in the dark theme. 196 passed, plus the browser test |
| SEN-31 | — | — | — |

## Sprint decisions

—

## Changes to the specification in this sprint

—

## Retro

- **Went well:** —
- **To improve:** —
- **To try:** —
