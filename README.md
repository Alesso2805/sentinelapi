# SentinelAPI

**Threat-detection middleware for FastAPI.** Drop it into an existing app and get fixed-window rate limiting, credential-stuffing-aware brute-force detection, and refresh-token replay protection — with every verdict written to a queryable audit trail.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://docs.python.org/3/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2-D71F00?logo=sqlalchemy&logoColor=white)](https://docs.sqlalchemy.org/)
[![Redis](https://img.shields.io/badge/Redis-optional-DC382D?logo=redis&logoColor=white)](https://redis.io/docs/latest/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Pytest](https://img.shields.io/badge/tested%20with-pytest-0A9EDC?logo=pytest&logoColor=white)](https://docs.pytest.org/en/stable/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Status: before 1.0.0, not ready for production yet.** An audit on 2026-10-22 found a way around each detector and gaps in the audit trail; all of them are fixed, each with the test that reproduces it (see [Known limitations](#known-limitations)). What remains before 1.0.0 is production readiness (settings that refuse unsafe values, a reproducible image) and a public demo: see the [backlog](docs/BACKLOG.md).

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
│   ├── rate_limiter.py       # Fixed-window rate limiting per client, stricter per path prefix
│   ├── brute_force.py        # Dual-axis: per source AND per account, checked before the password
│   └── jwt_replay.py         # Single-use enforcement via `jti`, for refresh/reset tokens
├── storage/backend.py         # CounterBackend Protocol — the seam between logic and infra
│   ├── memory_backend.py      # Zero-dependency, used by tests + single-process dev
│   └── redis_backend.py       # Multi-process production backend
├── audit/                     # SQLAlchemy async models + repository — the durable log
├── client_address.py           # The client's address, through the proxies you trust
├── clock.py                    # The only module that reads the time
├── middleware.py               # Pure ASGI adapter over the detectors above
├── integration.py              # install_sentinel: wires all of it into an app
└── config.py                   # Pydantic Settings, all overridable via SENTINEL_* env vars
```

**Why brute-force isn't in the middleware:** rate limiting and JWT-replay apply to *every* request and need nothing but headers, so they run as blanket middleware. Brute-force detection needs to know whether a login attempt actually succeeded — middleware would have to parse response bodies to know that, which is fragile. So it's exposed as a guard your login endpoint calls directly (below, and `examples/demo_app/auth.py`).

**Why JWT-replay is scoped to specific paths, not every request:** ordinary access tokens are presented on *every* API call by design — treating that as "replay" would flag 100% of legitimate traffic. This detector is for tokens meant to be redeemed exactly once: refresh-token rotation, password-reset links, email-verification links.

## Use it in your app

```python
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from sentinelapi.integration import install_sentinel

app = FastAPI()
sentinel = install_sentinel(app)  # rate limit + replay check on every request, and the audit trail


class Login(BaseModel):
    username: str
    password: str


@app.post("/login")
async def login(body: Login, request: Request) -> dict[str, str]:
    await sentinel.login_guard.check(request, body.username)  # 429 while the source or account is blocked
    if not passwords_match(body.username, body.password):  # your own check
        await sentinel.login_guard.failed(request, body.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    await sentinel.login_guard.succeeded(request, body.username)
    return {"token": "..."}
```

Three lines are SentinelAPI's: the import, `install_sentinel(app)`, and the guard around your own password check. Settings come from `SENTINEL_*` variables (see Configuration); `install_sentinel(app, settings, on_event=...)` also takes them explicitly, and an `on_event` coroutine receives every verdict after the log and the audit trail. This snippet runs as a test (`tests/integration/test_installer.py`), so it cannot drift from the code.

## Quickstart

### Docker (full stack: API + Redis + Postgres)

```bash
docker compose up --build --wait    # or: make up
curl http://localhost:8000/health
```

A `migrate` service creates the audit table as its owner and exits; the API starts after it and connects as a role that can only add and read audit rows. Only the API's port is published. `docker compose run --rm migrate sentinel purge` applies the retention period. On a server, `deploy/docker-compose.prod.yml` adds production settings, requires the secrets in `.env` and puts Caddy in front with HTTPS.

### Local dev (in-memory backend + SQLite, zero external services)

With [uv](https://docs.astral.sh/uv/), which installs the exact versions of `uv.lock`:

```bash
uv sync --all-extras
uv run sentinel migrate        # creates the audit table (SQLite here)
uv run uvicorn examples.demo_app.main:app --reload
```

Or with pip: `pip install -e ".[demo]"`, then `sentinel migrate` and `uvicorn examples.demo_app.main:app --reload`. `make demo` does both.

In your own app, run `sentinel migrate` against `SENTINEL_DATABASE_URL` before it starts, as you run your own migrations. SentinelAPI's history keeps its own version table, so the two never meet. On Postgres, `sentinel migrate --app-role <the role your app connects as>` grants that role INSERT and SELECT on the audit table and nothing else, so the trail is append-only.

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

# See what SentinelAPI has caught: operators only, with SENTINEL_OPERATOR_TOKEN
# (start the demo with SENTINEL_OPERATOR_TOKEN=dev-operator-token to try this;
# docker compose sets it for you)
curl -H "Authorization: Bearer dev-operator-token" "localhost:8000/security/events?threat_level=high"
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
| `SENTINEL_BRUTE_FORCE_PER_USERNAME_HIGH` | `8` | Failed attempts against one account, from any source, its username trimmed and casefolded |
| `SENTINEL_BRUTE_FORCE_ACCOUNT_ACTION` | `lock` | `lock`: the account is refused from every source until its window ends (so anyone who knows a username can lock its owner out that long). `signal`: events carry `challenge_required` for your app to ask for a CAPTCHA or MFA |
| `SENTINEL_ENV` | `development` | `production` refuses to start with an example or short (< 32 bytes) `SENTINEL_JWT_SECRET`, without `SENTINEL_AUDIT_HASH_KEY`, or on the memory backend (unless `SENTINEL_ALLOW_MEMORY_BACKEND=true`), naming every problem at once |
| `SENTINEL_JWT_SECRET` | `change-me` | The key your app signs tokens with; the replay detector verifies with it |
| `SENTINEL_AUDIT_HASH_KEY` | none | Key of the HMACs that stand for addresses, accounts and fingerprints in the audit trail and the log: correlatable, not reversible without it. Unset, a random key per process. `sentinel purge` deletes events older than `SENTINEL_AUDIT_RETENTION_DAYS` (90) |
| `SENTINEL_AUDIT_AGGREGATE_SECONDS` | `60` | Identical events within this window become one audit row with a count, written by a background task, so an attack never becomes a write flood and a database outage never fails a request |
| `SENTINEL_JWT_REPLAY_PATHS` | `["/auth/refresh"]` | Paths checked for single-use token replay. Tokens there need `exp` and `jti`; a used `jti` is refused until the token expires |
| `SENTINEL_ENFORCE` | `true` | `false` = log-only "shadow mode," useful before you trust it to block for real |

## Known limitations

None known. The audit of 2026-10-22 found a way around every detector and gaps in the audit trail; each became a story in the [backlog](docs/BACKLOG.md), and each fix landed with the test that reproduces it, between #10 and #19:

- a client under its limit blocked by the in-memory backend; rotating the User-Agent; sharing a proxy's address; blocking only past twice the limit;
- a brute-force block that let the right password in; usernames counted as typed; the owner's login erasing an attack;
- tokens without `exp` forgotten after an hour;
- raw addresses and usernames in the audit trail, readable by anyone; one row per request, written inside it; a table created at startup.

## Roadmap

Planned in [docs/BACKLOG.md](docs/BACKLOG.md):

1. Done: a locked, linted and type-checked repository, with CI on every pull request.
2. Done: detectors without the evasions above.
3. Done: a three-line integration, and an audit trail that is migrated, private and safe under a flood.
4. Next: a production-ready stack, webhook alerts on CRITICAL events, and an attack console where you launch each attack and watch it get caught.
5. Then: a deployed demo and release 1.0.0.

## Documentation

- [Specification](docs/SPEC.md): scope, architecture, the detection contract, the audit table and every setting.
- [Backlog](docs/BACKLOG.md) and [sprint notes](docs/sprints/).
- [Architecture rules](docs/ARCHITECTURE_RULES.md) and [decision records](docs/adr/README.md).

## Security

Found a vulnerability that is not under Known limitations? Please report it privately: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
