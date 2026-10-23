# ADR-0008: A typed library on PyPI; the demo stays out of the package

- **Status:** Accepted on 2026-10-22
- **Date:** 2026-10-22
- **Related:** SPEC.md › Engineering rules; ARCHITECTURE_RULES.md AR-06; SEN-11, SEN-12, SEN-14, SEN-36

## Context

The README sells SentinelAPI as something to "drop into an existing app", but the only way to get it is to clone the repository and `pip install -e .`. The supported Python versions disagree across files: `>=3.11` in `pyproject.toml`, 3.11 for Ruff and Mypy, 3.11+ on the README's badge, 3.12 in the Dockerfile and the virtualenv. There is no `py.typed`, so Mypy treats the package as untyped for its users.

## Options

1. **Install from the Git URL only** (`pip install git+https://github.com/...`). No release process, but no versions to pin either, and no place in the ecosystem.
2. **Publish to PyPI** from a tag, with trusted publishing (no token stored in the repository).
3. **Vendor it into apps.** Not a library any more.

## Decision

Option 2:

- The distribution name is checked on PyPI before SEN-36 starts. If `sentinelapi` is taken, the fallback is `fastapi-sentinel` or another free name the product owner picks. The import name stays `sentinelapi` either way.
  - **Applied on 2026-10-22:** `sentinelapi` was free as written, but PyPI refused it as too similar to the existing `sentinel-api` (it compares names without separators). The product owner chose the fallback: the distribution is `fastapi-sentinel`.
- The wheel contains only the `sentinelapi` package, as `[tool.hatch.build.targets.wheel]` already says; the demo app is not shipped.
- Extras stay `redis`, `postgres` and `sqlite`; `sqlalchemy[asyncio]` becomes a required dependency (SEN-11), since the audit sink needs it.
- `py.typed` is shipped (SEN-12).
- **Supported Python: 3.11 to 3.15.** On 2026-10-22 those are the CPython versions under support (3.15.0 came out on 2026-10-09; 3.10 reached its end of life on 2026-10-01). 3.11 is also the first with `StrEnum`. CI tests every one; development and the image use 3.12. A new CPython release is added, and one past its end of life dropped, in a minor version.
- **SemVer.** 1.0.0 is the release of SEN-37; the settings, the installer and the event schema are the public API.

## Consequences

- Each supported Python version is a CI job and a promise. Dropping one is a breaking change.
- Publishing needs a PyPI account with trusted publishing configured for the repository. That is a manual, one-time step for the product owner, written in the release runbook.
- The portfolio can link both the repository and the package.
