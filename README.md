# SentinelAPI

**Adaptive threat-detection middleware for FastAPI.** Drop it into an existing app and get sliding-window rate limiting, credential-stuffing-aware brute-force detection, and JWT-replay protection — with every blocking decision written to a queryable audit trail.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://docs.python.org/3/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-D71F00?logo=sqlalchemy&logoColor=white)](https://docs.sqlalchemy.org/en/20/)
[![Redis](https://img.shields.io/badge/Redis-optional-DC382D?logo=redis&logoColor=white)](https://redis.io/docs/latest/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Pytest](https://img.shields.io/badge/tested%20with-pytest-0A9EDC?logo=pytest&logoColor=white)](https://docs.pytest.org/en/stable/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why this exists

Most "add security" advice for a junior backend service stops at "put a rate limiter in front of it." That misses two attacks a rate limiter alone won't catch:

- **Credential stuffing** — an attacker spreads login attempts for *one* target account across many IPs, staying under any single-IP threshold. Catching it means tracking failures per **username**, not just per **IP**.
- **Token replay** — a stolen refresh token gets reused after the legitimate client already rotated it. Catching it means treating single-use tokens as actually single-use, which a plain JWT signature check does not do.

SentinelAPI implements both, alongside standard rate limiting, as small, independently-testable detectors — not a monolithic "security module."

## Architecture

The detection logic never imports FastAPI, Redis, or SQLAlchemy. It depends on a `CounterBackend` protocol and returns plain `SecurityEvent` dataclasses. That's what makes the core provably correct on its own, with zero external services:

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

```bash
pip install -e ".[demo]"
uvicorn examples.demo_app.main:app --reload
```

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
# Core detectors — pure stdlib unittest, no dependencies at all, runs anywhere
python -m unittest discover -s tests -p "test_rate_limiter.py"
python -m unittest discover -s tests -p "test_brute_force.py"
python -m unittest discover -s tests -p "test_jwt_replay.py"

# Full app, end-to-end — needs the [dev] extras installed
pip install -e ".[dev]"
pytest tests/test_middleware_integration.py -v
```

The first three files are dependency-free by design, so the detection logic itself can be verified without spinning up FastAPI, Redis, or a database — that's what let this project be built and tested inside a sandboxed environment with no network access, before ever touching Docker.

## Configuration

All settings are `SENTINEL_`-prefixed environment variables (or a `.env` file — see `.env.example`). Key ones:

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_BACKEND` | `memory` | `memory` (dev/single-process) or `redis` (production) |
| `SENTINEL_RATE_LIMIT_MAX_REQUESTS` | `60` | Requests per window before blocking |
| `SENTINEL_BRUTE_FORCE_PER_USERNAME_HIGH` | `8` | Failed attempts against one account (any source) before blocking |
| `SENTINEL_JWT_REPLAY_PATHS` | `["/auth/refresh"]` | Paths checked for single-use token replay |
| `SENTINEL_ENFORCE` | `true` | `false` = log-only "shadow mode," useful before you trust it to block for real |

## Roadmap

- [ ] Alembic migrations for the audit table (currently `create_all` — fine for a demo, not for a shared prod DB)
- [ ] Small React dashboard over `/security/events` instead of raw JSON
- [ ] Pluggable notification hook (Slack/email) on CRITICAL events

## License

MIT
