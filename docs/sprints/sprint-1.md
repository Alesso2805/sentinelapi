# Sprint 1 — Green from a clean clone, CI that blocks regressions (SEN-11 to SEN-16)

**Status as of 2026-10-22:** closed. Started and finished on 2026-10-22, with no calendar: all six stories (12 points) are merged into `main` with green CI. SEN-10 was done in Sprint 0, and SEN-11's first step was #1. The suite went from 21 tests to 73 passed and 10 xfailed, each xfail naming the story that removes it.

**Order:** SEN-11, SEN-12, SEN-13, SEN-14, SEN-15, SEN-16.

**Decided before it started** (product owner, 2026-10-22)

- **No calendar:** as fast as the stories can be done; each PR is merged as soon as its CI is green.
- **Python 3.11 to 3.15** (ADR-0008), for SEN-11 and SEN-14's matrix.
- **import-linter + Pytest + Alembic** for the architecture tests (ARCHITECTURE_RULES.md › Tool), for SEN-15.
- **AR-16 to AR-18 adopted** (an injected clock, detectors that receive identity, one composition point), so SEN-15 tests 18 rules.
- **ADR-0004 to ADR-0010 accepted,** with `lock` as ADR-0005's default: nothing in Sprints 2 to 5 waits for a decision except the server (SEN-33) and the PyPI account (SEN-36).

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-11 | #1, #4 | `uv.lock` (46 packages), dev tools in a dependency group, `.python-version` 3.12, classifiers for 3.11 to 3.15, a Makefile; the README installs with uv or pip | `uv sync --all-extras` then `uv run pytest`: 21 passed; `make check-imports` imports the library with no extra and no dev tool |
| SEN-12 | #5 | `ruff format` on 13 files; the 4 Ruff errors fixed (`Annotated` dependencies, `StrEnum`); Mypy `strict = true` over `sentinelapi`, `examples` and `tests`; `py.typed` | Ruff 0 errors, 0 files to reformat; Mypy strict: no issues in 28 files; Pytest 21 passed; the enums keep their values; the wheel ships `py.typed` and not the demo |
| SEN-13 | #6 | `create_app(settings)` in the demo; `tests/unit` and `tests/integration`; each integration test builds its own app with its own memory backend and a SQLite file in `tmp_path`, with the lifespan run; tests for shadow mode, for the audit trail written through `on_event`, and for two apps not sharing counters; a session guard fails the run if any test writes to `./sentinelapi_audit.db`; the pydantic Mypy plugin | 24 passed (15 unit, 9 integration); the demo's database kept its size and timestamp across the run; Ruff, format and Mypy strict clean |
| SEN-14 | #7 | `.github/workflows/ci.yml`: Lint and types; Tests on Python 3.11 to 3.15 with a Redis service; Imports with required dependencies only (`scripts/check_imports.py`, AR-06); actions pinned by SHA; `main` protected, requiring all seven checks | The PR's own run: 7 checks green, 3.15 included (uv found wheels for every dependency); the import check loads 17 modules without extras |
| SEN-15 | #8 | import-linter contracts for AR-04 and AR-05; Pytest in `tests/architecture/` (AR-01 to AR-03, AR-09, AR-14, AR-15, AR-17, AR-18), `tests/contract/` (AR-07, against every backend: memory always, Redis when `SENTINEL_TEST_REDIS_URL` is set), `tests/unit/` (AR-08, AR-10) and `tests/integration/` (AR-11 to AR-13); Ruff `banned-api` for AR-16. Rules that do not hold are `xfail(strict=True)` with their story. The contract tests surfaced redis-py's deprecated `close()`, now `aclose()` | 73 passed and 10 xfailed, against a local Redis too. Deliberately broken: `import fastapi` in `domain/entities.py` fails `test_imports`; `import redis` in `detectors/rate_limiter.py` breaks the AR-04 contract |
| SEN-16 | #9 | The six claims that were no longer true: "provably correct" (`domain/entities.py`), "thread-safe" (`memory_backend.py`), "not exercised by the test suite" and "sliding-window counters" (`redis_backend.py`), and the storage port's contract, which promised a window extended by every hit instead of ADR-0002's fixed window (`storage/backend.py`). `main.py`'s "every HIGH/CRITICAL event persisted" was already corrected in #6. No comment was doubtful enough for `docs/COMMENTS_REVIEW.md` | Ruff, format and Mypy strict clean; comments only |

## Sprint decisions

- **Every story merges on green CI, with no review wait** (product owner). From #7, `main` requires the seven checks, so a red PR cannot be merged.
- **Python 3.15 is in the matrix from the first day.** It came out on 2026-10-09; uv found wheels for every dependency.
- **Debt is visible, not hidden.** A rule that does not hold is `xfail(strict=True)` with its story; AR-16's current uses of time are per-file exceptions in `pyproject.toml`, each with its story.
- **Pydantic's Mypy plugin,** so settings built in tests type-check (`_env_file=None` keeps a developer's `.env` out of them).

## Changes to the specification in this sprint

- #3: ADR-0004 to ADR-0010 accepted; AR-16 to AR-18; Python 3.11 to 3.15; no calendar.
- #4, #6, #7, #8: SPEC's repository tree follows what exists (`uv.lock`, `Makefile`, `tests/unit`, `tests/integration`, `tests/contract`, `tests/architecture`, `scripts/check_imports.py`, `.github/workflows/ci.yml`, `py.typed`).
- #8: AR-09 asks only that every setting appears in `.env.example`.

## Retro

- **Went well:** the contract suite found what the audit found, a memory backend that counts differently from Redis, now as a strict xfail that SEN-17 must turn green. Running against a real Redis also surfaced a deprecation nothing else would have shown.
- **To improve:** the old integration tests passed only because the developer's own database already had the audit table; nobody noticed until each test ran its own lifespan. Tests that lean on leftover state pass for the wrong reason.
- **To try:** in Sprint 2, write each evasion of the audit as a failing test first, then make it pass.
