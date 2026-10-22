# Sprint 1 — Green from a clean clone, CI that blocks regressions (SEN-11 to SEN-16)

**Status as of 2026-10-22:** started on 2026-10-22, with no calendar: it closes when its stories are merged. 12 points. SEN-10 was done in Sprint 0, and SEN-11's first step is #1.

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
| SEN-13 | — | — | — |
| SEN-14 | — | — | — |
| SEN-15 | — | — | — |
| SEN-16 | — | — | — |

## Sprint decisions

—

## Changes to the specification in this sprint

—

## Retro

- **Went well:** —
- **To improve:** —
- **To try:** —
