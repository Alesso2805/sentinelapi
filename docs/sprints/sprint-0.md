# Sprint 0 — Baseline as built, documented and audited (SEN-01 to SEN-09)

**Status as of 2026-10-22:** SEN-01 to SEN-08 were built on August 31, 2026, before there was a backlog, in a sandbox without network access (the README says so). They are recorded here retroactively so that each one has acceptance criteria the audit can check. SEN-09 (this documentation), SEN-10 (version control) and SEN-38 (a public repository) were done on October 22. The sprint closes on October 25.

## Where the code stands

Under git since 2026-10-22, at [github.com/Alesso2805/sentinelapi](https://github.com/Alesso2805/sentinelapi), public. Until then the folder had no history; every source file was last modified on 2026-08-31, between 22:54 and 23:12.

- `6a643ce`: the baseline exactly as built, with a `.gitignore` that keeps the local and internal files out of the history.
- `ef30ed3`: this documentation.
- #1: SEN-11's first step, `sqlalchemy[asyncio]`, so the image and a fresh install start.
- #2: SEN-38, what a public repository needs.

To pick it up again:

1. `git clone https://github.com/Alesso2805/sentinelapi` and `pip install -e ".[dev,demo]"` (uv and a lockfile come with SEN-11).
2. Run `pytest`: 21 tests pass. They write to `sentinelapi_audit.db` in the folder (SEN-13).
3. `uvicorn examples.demo_app.main:app --reload` runs the demo with the memory backend and SQLite, and `docker compose up --build` runs it with Redis and Postgres, as long as ports 8000, 6379 and 5432 are free (SEN-29 stops publishing the database ports).

## What was delivered

| Story | Files | Result | Verification |
| --- | --- | --- | --- |
| SEN-01 | `domain/`, `detectors/`, `storage/backend.py`, `storage/memory_backend.py`, `config.py` | Framework-free detectors behind a storage protocol; 14 settings | Unit tests with the memory backend. Its window is not Redis's (probe 1) |
| SEN-02 | `detectors/rate_limiter.py`, `middleware.py` | Fixed-window limit per fingerprint and path; 429 past twice the limit | 5 unit tests, 1 integration test. Live with Redis: first 429 at the 121st request against a limit of 60 |
| SEN-03 | `detectors/brute_force.py`, `examples/demo_app/auth.py` | Two-axis failure counting; 403 on HIGH or CRITICAL | 4 unit tests, 1 integration test. Live: the right password after a block → 200 |
| SEN-04 | `detectors/jwt_replay.py`, `middleware.py` | Single-use `jti` on `/auth/refresh` | 6 unit tests, 1 integration test. Live with Redis: 200, then 403 |
| SEN-05 | `storage/redis_backend.py` | INCR + EXPIRE NX, SET NX EX | No test. Live: works, TTL set on the first hit |
| SEN-06 | `audit/`, `examples/demo_app/main.py` | Event table, repository, `GET /security/events` | Through the integration tests. Live on Postgres: raw addresses, usernames in `detail`, public endpoint, 67 rows from one burst |
| SEN-07 | `middleware.py` | Shadow mode | No test |
| SEN-08 | `examples/demo_app/`, `Dockerfile`, `docker-compose.yml` | Demo app and a three-service stack | The image builds; the API exits on import (greenlet) |
| SEN-09 | `ef30ed3` | Specification, backlog, ten ADRs, architecture rules, audit, these notes | Done; the audit and `CLAUDE.md` stay local (SEN-38) |
| SEN-10 | `6a643ce`, `ef30ed3` | The baseline and the documentation as the first two commits; a private repository on GitHub | No database, agent file or internal note in the history (`git log --all --name-only`) |
| SEN-38 | #2 | MIT `LICENSE`, `SECURITY.md`, a README that states the status and the known limitations, internal notes out of version control; then public, with private vulnerability reporting, a description and topics | The repository's page and its settings, checked after the switch |

The suite on 2026-10-22: 21 tests (15 unit, 6 integration), all passing, with 90 warnings.

## Sprint decisions

- **Story prefix `SEN-`**, one backlog in this repository. The two-week sprint calendar is VeriLedger's, so the ceremonies of both projects can share a day.
- **The audit drives the plan.** Every blocking or important finding of `docs/AUDIT.md` became a story in E1 to E5.
- **Correctness before exposure.** Nothing is deployed before the detectors hold (E2) and the audit trail is private (SEN-24, SEN-26).
- **The final version** is 1.0.0: detectors with no known evasion, a deployed attack console and, if ADR-0008 is accepted, a package on PyPI. With the repository public, the portfolio can already link `repoUrl`; `demoUrl` waits for SEN-33.
- **Public now** (product owner, 2026-10-22). SEN-10 and SEN-38 were brought forward from Sprints 1 and 5. The README says the project is before 1.0.0 and lists the audit's findings as known limitations, each with its story, so the repository claims nothing untrue while they are fixed. The audit itself stays local, as Willay's and VeriLedger's do.
- **Accepted, retroactive:** ADR-0001 (framework-agnostic detectors), ADR-0002 (fixed windows), ADR-0003 (brute force called by the login).
- **Proposed, waiting for the product owner:** ADR-0004 (client identity behind proxies) and ADR-0005 (what a block means), both needed for Sprint 2; ADR-0006 (audit trail) and ADR-0007 (pure ASGI and installer) for Sprint 3; ADR-0008 (PyPI and Python versions), ADR-0009 (deployment) and ADR-0010 (attack console).

## Changes to the specification in this sprint

The specification did not exist before. `docs/SPEC.md` and `docs/BACKLOG.md` were written on 2026-10-22 from the code, the README and the audit.

## Retro

- **Went well:** the separation the README promises is real. Detectors, storage and adapter are cleanly apart, and each detector's main scenario works, against Redis and Postgres too.
- **To improve:** it was built and tested only where it could run: the memory backend, SQLite, one fingerprint per test. The failures that matter (the default backend blocking honest clients, each detector's cheap evasion, an image that does not start) stayed invisible until the audit ran probes and the real stack.
- **To try:** from Sprint 1, everything under git with one PR per story and CI. Every claim in the README gets the test that proves it, and every evasion found becomes a test before its fix.
