# Sprint 5 — A deployed demo and release 1.0.0 (SEN-33 to SEN-37, SEN-43)

**Status as of 2026-10-22:** started right after Sprint 4, with no calendar. 16 points: 14 planned, and SEN-43, found during the sprint.

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
| SEN-36 | #28 | `sentinelapi` is free on PyPI and TestPyPI. `.github/workflows/release.yml`: a tag `vX.Y.Z` checks it matches `pyproject.toml`, builds, publishes to TestPyPI then PyPI with `uv publish --trusted-publishing always` from the environments `testpypi` and `pypi` (created); actions pinned by SHA, verified against GitHub. CI job "The wheel installs and works, with each extra": a fresh environment per extra set, run from outside the repository, the README's snippet against the installed package, and with `sqlite` the wheel's own `sentinel migrate` first (`scripts/smoke_installed.py`). `docs/runbooks/release.md`; the README's install line | Locally, the wheel in five fresh environments (none, each extra, all three): the package comes from site-packages, `py.typed` is there, each extra's driver imports, the snippet blocks the 8th wrong password and the right one after it, and `sentinel migrate` creates the table. Not done: the first publish, which needs the product owner's pending publishers on PyPI and TestPyPI |
| SEN-37 | — | — | — |
| SEN-43 | #29 | Checking the README's claims for SEN-37 found that, with `lock`, credential stuffing never reached CRITICAL: once the account was locked, refused attempts were not counted, so it stayed at its 8th failure, and the webhook never heard of it. `BruteForceDetector.check` counts a refused attempt against a locked account (the fixed window does not move); `record_failure` does not count it again, so shadow mode shows the levels enforcement would; `signal` counts only failures, as before. `WebhookAlerter` holds alerts back per account when the event has one: stuffing comes from a new address every time. The console's stuffing run says when the attack turns CRITICAL | Before: 40 attempts against one account with the default settings, never CRITICAL; after: CRITICAL from the 15th. Unit tests for enforce, shadow and signal mode and for one alert per account; end to end, 20 wrong passwords from 20 addresses through a trusted proxy reach a real HTTP receiver once; the console's run turns CRITICAL at its 15th attempt |

## Sprint decisions

- **Refused attempts count against a locked account (SEN-43).** CRITICAL means an attack that goes on after the lock; counting only failures, it could never come with `lock`, the default. Each attempt counts once: in `check` when the account is locked, otherwise in `record_failure`.
- **Alerts are held back per account when the event has one (SEN-43),** per source otherwise: credential stuffing comes from a new address every time, and one message per address is a flood.

## Changes to the specification in this sprint

- #29: the scope table's brute-force and alerts rows, and the verdict table's CRITICAL row for brute force.

## Retro

- **Went well:** —
- **To improve:** —
- **To try:** —
