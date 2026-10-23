# Sprint 5 — A deployed demo and release 1.0.0 (SEN-33 to SEN-37)

**Status as of 2026-10-22:** started right after Sprint 4, with no calendar. 14 points.

**Needed from the product owner**

- **SEN-33, the server** (ADR-0009): VeriLedger's server or one of its own, a hostname (for example `sentinelapi.duckdns.org`) and SSH access.
- **SEN-36, PyPI:** an account with a trusted publisher for this repository, and the distribution name if `sentinelapi` is taken.

**Order:** what needs nobody first: SEN-34 (runbooks, rehearsed locally), SEN-35 (benchmark), the publishing workflow of SEN-36; then SEN-33 and SEN-36's first publish when the server and the account exist; SEN-37 last, its screenshots from the deployed console.

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-33 | — | — | — |
| SEN-34 | #26 | `docs/runbooks/`: `deploy.md` (own server or VeriLedger's, `.env` with `COMPOSE_FILE` and generated secrets, start, verify, nightly backups and weekly purge, update, roll back, a laptop rehearsal), `backup-and-restore.md`, `rotate-secrets.md` (each secret and what rotating it does; database passwords through `ALTER ROLE`), `rollout.md` (shadow mode, a week of verdicts, enforce, alert, the account lock). `deploy/backup.sh`, `restore.sh`, `verify.sh`. Two bugs the rehearsal found: the app's role could not read Alembic's version table, so `/ready` was 503 and startup warned "not migrated" in the real stack (`sentinel migrate --app-role` now grants SELECT on it); and the image could ship stale code, since uv reused a cached wheel of the project (`--reinstall-package sentinelapi`). `LoginGuard.check` returns its verdict, so `signal` mode can be used as `rollout.md` says | On a throwaway stack: 2 rows, backup, TRUNCATE, restore, 2 rows, the app role still refused a DELETE, `/ready` 200 and `verify.sh` green; the same cycle and `/ready` added to CI's stack job. The app role's readiness checked on Postgres; signal mode hands the app a challenge from the 8th failure. The shared-server section is unrehearsed: it needs that server (SEN-33) |
| SEN-35 | #27 | `benchmarks/overhead.py` (`make bench`): the ASGI app called directly, so only SentinelAPI is measured; without it, on the memory backend, and on Redis when `SENTINEL_BENCH_REDIS_URL` is set; nothing blocked, so every request pays the full check; p50, p95, p99 and the overhead, with the machine. README › Overhead | On a Windows 11 laptop, 20,000 requests each: memory adds 0.039 ms at p95; Redis in Docker Desktop on the same machine adds 1.420 ms at p95, under the 2 ms target |
| SEN-36 | — | — | — |
| SEN-37 | — | — | — |

## Sprint decisions

—

## Changes to the specification in this sprint

—

## Retro

- **Went well:** —
- **To improve:** —
- **To try:** —
