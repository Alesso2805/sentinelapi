# SentinelAPI

**Threat-detection middleware for FastAPI.** Drop it into an existing app and get fixed-window rate limiting, credential-stuffing-aware brute-force detection, and refresh-token replay protection — with every verdict written to a queryable audit trail.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://docs.python.org/3/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2-D71F00?logo=sqlalchemy&logoColor=white)](https://docs.sqlalchemy.org/)
[![Redis](https://img.shields.io/badge/Redis-optional-DC382D?logo=redis&logoColor=white)](https://redis.io/docs/latest/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Pytest](https://img.shields.io/badge/tested%20with-pytest-0A9EDC?logo=pytest&logoColor=white)](https://docs.pytest.org/en/stable/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Status: before 1.0.0, not ready for production.** Each detector works in its main scenario, but an audit on 2026-10-22 found a way around each of them. They are listed under [Known limitations](#known-limitations) and are being fixed in the open, one story at a time, on the way to 1.0.0: see the [backlog](docs/BACKLOG.md).

## Why this exists

Most "add security" advice for a junior backend service stops at "put a rate limiter in front of it." That misses two attacks a rate limiter alone won't catch:

- **Credential stuffing** — an attacker spreads login attempts for *one* target account across many IPs, staying under any single-IP threshold. Catching it means tracking failures per **username**, not just per **IP**.
- **Token replay** — a stolen refresh token gets reused after the legitimate client already rotated it. Catching it means treating single-use tokens as actually single-use, which a plain JWT signature check does not do.

SentinelAPI implements both, alongside standard rate limiting, as small, independently-testable detectors — not a monolithic "security module."

## Architecture

The detection logic never imports FastAPI, Redis, or SQLAlchemy. It depends on a `CounterBackend` protocol and returns plain `SecurityEvent` dataclasses. That's what lets the core be tested on its own, with zero external services:

```
sentinelapi/
├── domain/entities.py       # ThreatType, ThreatLevel, SecurityEvent — no dependencies
├── detectors/                # Pure logic. Depends only on domain/ + storage protocol.
│   ├── rate_limiter.py       # Fixed-window rate limiting per fingerprint+path
│   ├── brute_force.py        # Dual-axis: per-fingerprint AND per-username
│   └── jwt_replay.py         # Single-use enforcement via `jti`, for refresh/reset tokens
├── storage/backend.py         # CounterBackend Protocol — the seam between logic and infra
│   ├── memory_backend.py      # Zero-dependency, used by tests + single-process dev
│   └── redis_backend.py       # Multi-process production backend
├── audit/                     # SQLAlchemy async models + repository — the durable log
├── middleware.py               # Thin FastAPI/Starlette adapter over the detectors above
└── config.py                   # Pydantic Settings, all overridable via SENTINEL_* env vars
```

**Why brute-force isn't in the middleware:** rate limiting and JWT-replay apply to *every* request and need nothing but headers, so they run as blanket middleware. Brute-force detection needs to know whether a login attempt actually succeeded — middleware would have to parse response bodies to know that, which is fragile. So it's exposed as a detector your login endpoint calls directly (see `examples/demo_app/auth.py`).

**Why JWT-replay is scoped to specific paths, not every request:** ordinary access tokens are presented on *every* API call by design — treating that as "replay" would flag 100% of legitimate traffic. This detector is for tokens meant to be redeemed exactly once: refresh-token rotation, password-reset links, email-verification links.

## Quickstart

### Docker (full stack: API + Redis + Postgres)

```bash
docker compose up --build
curl http://localhost:8000/health
```

### Local dev (in-memory backend + SQLite, zero external services)

With [uv](https://docs.astral.sh/uv/), which installs the exact versions of `uv.lock`:

```bash
uv sync --all-extras
uv run uvicorn examples.demo_app.main:app --reload
```

Or with pip: `pip install -e ".[demo]"`, then `uvicorn examples.demo_app.main:app --reload`.

Try it:

```bash
# Normal login
curl -X POST localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice@example.com","password":"correct-horse-battery-staple"}'

# Trigger brute-force detection (run this ~10x with a wrong password)
curl -X POST localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice@example.com","password":"wrong"}'

# See what SentinelAPI has caught
curl localhost:8000/security/events
```

## Testing

Two layers, on purpose:

```bash
# Core detectors — stdlib unittest, no framework, database or Redis needed
uv run python -m unittest discover -s tests/unit -p "test_rate_limiter.py"
uv run python -m unittest discover -s tests/unit -p "test_brute_force.py"
uv run python -m unittest discover -s tests/unit -p "test_jwt_replay.py"

# Everything, the full app end-to-end included
uv run pytest
```

`make test`, `make lint`, `make typecheck` and `make demo` wrap the same commands.

The first three files need no running service by design (only the package and PyJWT), so the detection logic itself can be verified without spinning up FastAPI, Redis, or a database — that's what let this project be built and tested inside a sandboxed environment with no network access, before ever touching Docker.

## Configuration

All settings are `SENTINEL_`-prefixed environment variables (or a `.env` file — see `.env.example`, which lists every one). Key ones:

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_BACKEND` | `memory` | `memory` (dev/single-process) or `redis` (production) |
| `SENTINEL_RATE_LIMIT_MAX_REQUESTS` | `60` | Requests per window per client, whatever the path. The next one gets a 429 with `Retry-After`; passing 80 % of it (`SENTINEL_RATE_LIMIT_WARN_AT`) logs a warning |
| `SENTINEL_RATE_LIMIT_PATHS` | `{}` | Stricter limits per path prefix on top of that, e.g. `{"/auth/": 10}`. `/health` and `/ready` are never counted (`SENTINEL_RATE_LIMIT_EXEMPT_PATHS`) |
| `SENTINEL_TRUSTED_PROXIES` | `[]` | CIDRs of your reverse proxies. Their `X-Forwarded-For` is believed, right-most hop first; with none, the direct peer is the client, so no header can choose its address |
| `SENTINEL_BRUTE_FORCE_PER_USERNAME_HIGH` | `8` | Failed attempts against one account (any source) before blocking |
| `SENTINEL_JWT_REPLAY_PATHS` | `["/auth/refresh"]` | Paths checked for single-use token replay |
| `SENTINEL_ENFORCE` | `true` | `false` = log-only "shadow mode," useful before you trust it to block for real |

## Known limitations

Found by the audit of 2026-10-22. Each one is a story in the [backlog](docs/BACKLOG.md), and each fix lands with the test that reproduces it.

- **A brute-force block does not stop the right password.** It only turns the failed login's 401 into a 403 (SEN-20).
- **Usernames are counted as typed,** so changing their case splits the per-account count, and the account owner's successful login erases failures that came from other sources (SEN-20).
- **A single-use token without `exp` is remembered for one hour only** (SEN-21).
- **The audit trail stores raw IP addresses** and, for brute force, the targeted username; the demo's `/security/events` needs no credentials; every event is one row, written inside the request (SEN-24, SEN-25, SEN-26).
- **The audit table is created with `create_all` at startup,** not by migrations (SEN-23).

## Roadmap

Planned in [docs/BACKLOG.md](docs/BACKLOG.md), in two-week sprints:

1. A locked, linted and type-checked repository, with CI on every pull request.
2. Detectors without the evasions above.
3. A three-line integration, and an audit trail that is migrated, private and safe under a flood.
4. A production-ready stack, webhook alerts on CRITICAL events, and an attack console where you launch each attack and watch it get caught.
5. A deployed demo and release 1.0.0.

## Documentation

- [Specification](docs/SPEC.md): scope, architecture, the detection contract, the audit table and every setting.
- [Backlog](docs/BACKLOG.md) and [sprint notes](docs/sprints/).
- [Architecture rules](docs/ARCHITECTURE_RULES.md) and [decision records](docs/adr/README.md).

## Security

Found a vulnerability that is not under Known limitations? Please report it privately: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
