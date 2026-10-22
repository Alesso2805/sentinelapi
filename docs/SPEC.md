# SentinelAPI — specification

Oct 22, 2026 · @Alessandro David

This document describes what SentinelAPI is, what was built on August 31, 2026, and what it must become to be released as 1.0.0 with a public demo. Items marked with a story ID (SEN-NN) are not built yet; the story in [BACKLOG.md](BACKLOG.md) is where they get done. Decisions marked "Proposed" in [the ADRs](adr/) wait for the product owner.

## Vision and problem

**The problem.** Most advice for securing a small API stops at "put a rate limiter in front of it". That misses two common attacks:

- **Credential stuffing:** one target account, with login attempts spread across many addresses so that no single address crosses a limit. Catching it means counting failures per account, not only per address.
- **Refresh-token replay:** a stolen single-use token redeemed again after the legitimate client already rotated it. A signature check accepts it; only remembering which tokens were already used catches it.

Adding these checks inside each app means solving counting, windows, multi-process storage and auditing again every time.

**The proposal.** A middleware library for FastAPI (any Starlette app):

- small detectors, each testable without a web framework or a database;
- one storage port with an in-memory and a Redis implementation;
- a thin adapter that turns verdicts into HTTP responses;
- an audit trail of every verdict.

A demo app shows it working. It is a portfolio project, so the clarity of its guarantees matters more than the number of attacks it covers: every claim the README makes is backed by a test.

**Goals of the current plan**

- A demo deployed on the internet where a visitor launches each attack and watches it get caught (SEN-32, SEN-33).
- Every detector holds against the obvious evasions: rotating the User-Agent, changing a username's case, retrying after a block, sitting behind a proxy (SEN-17 to SEN-21).
- An integrator adds SentinelAPI to an app in three lines, from a package that installs and imports cleanly (SEN-22, SEN-36).
- The repository is under version control and green from a clean clone: lint, types, architecture tests and tests in CI (SEN-10 to SEN-15).

**Success metrics**

| Metric | Target | How it is measured |
| --- | --- | --- |
| Known evasions that get through | 0 | One test per evasion found by the audit of 2026-10-22, listed in the README's Known limitations (SEN-17 to SEN-21) |
| Legitimate traffic blocked | 0 for a client under its limit, however long it keeps going | Steady-traffic test with a controlled clock, on every backend (SEN-17) |
| Latency added per request | p95 ≤ 2 ms with Redis on the same host (proposed target) | Benchmark (SEN-35) |
| Integration effort | Three lines in an existing FastAPI app | The README's snippet runs as a test (SEN-22) |
| Clean clone to a running demo | One command, no manual steps | `docker compose up` in CI answers `/health` (SEN-29) |
| CI on every PR | Ruff, format, Mypy strict, architecture tests, Pytest green before merge | GitHub branch protection (SEN-14) |

## Scope and features

Status: **Built** (exists in the working tree; see the audit for its defects), **Planned** (a story in the backlog).

| Area | Feature | Detail | Status |
| --- | --- | --- | --- |
| Rate limiting | Per-client limit | Fixed window of `rate_limit_window_seconds`, one counter per client (its address, since SEN-19), whatever the path; the request after `rate_limit_max_requests` → HIGH, 429 with `Retry-After`; crossing `rate_limit_warn_at` → MEDIUM once per window | Built (SEN-02, SEN-18, SEN-19) |
| Rate limiting | `Retry-After`, exempt paths, stricter limits per path prefix | `/health` and `/ready` exempt by default; a prefix such as `/auth/` adds its own, stricter counter | Built (SEN-18) |
| Rate limiting | Client address behind a proxy | Trusted proxies and `X-Forwarded-For`; IPv6 grouped by /64 | Built (SEN-19, ADR-0004) |
| Brute force | Two axes | Failures per fingerprint (MEDIUM 5, HIGH 10) and per username (HIGH 8, CRITICAL 15) in 15 minutes; a success clears both | Built (SEN-03) |
| Brute force | A block that holds | Checked before the password; usernames normalized; a success clears only its own source | Planned (SEN-20, ADR-0005) |
| Token replay | Single-use tokens | Only on `jwt_replay_paths`; a `jti` is remembered until the token's `exp`; a second use → CRITICAL, 403 | Built (SEN-04); `exp` and `jti` required in SEN-21 |
| Storage | Memory and Redis backends | One `CounterBackend` protocol | Built (SEN-01, SEN-05); one window semantics and bounded memory since SEN-17 |
| Audit | Event log | Table `sentinel_security_events`; the demo's `GET /security/events` | Built (SEN-06); migrations SEN-23, privacy SEN-24, write path SEN-25, protected API SEN-26 |
| Enforcement | Shadow mode | `SENTINEL_ENFORCE=false` logs and records without blocking | Built (SEN-07), untested until SEN-13 |
| Integration | One-call installer | `install_sentinel(app, settings)`; pure ASGI middleware | Planned (SEN-22, ADR-0007) |
| Alerts | Webhook on CRITICAL events | Slack-compatible JSON, deduplicated | Planned (SEN-31) |
| Demo | Demo app | Login, refresh, `/me`, `/health`, events | Built (SEN-08) |
| Demo | Attack console | A page where a visitor runs each attack and watches the verdicts | Planned (SEN-32, ADR-0010) |
| Operations | Compose stack | API, Redis 7, Postgres 16 | Built (SEN-08); the image does not start until SEN-11; migrations and a `migrate` service in SEN-29 |
| Operations | Deployment | One server, Caddy, HTTPS | Planned (SEN-33, ADR-0009) |
| Distribution | Package | Typed wheel on PyPI | Planned (SEN-36, ADR-0008) |

**Out of scope for this plan:**

- payload inspection (SQL injection or XSS signatures): SentinelAPI is not a WAF;
- bot detection by behavior, JavaScript challenges, CAPTCHA;
- IP reputation feeds and geo-blocking;
- network-level DDoS mitigation (a middleware runs after the connection is accepted);
- frameworks that are not built on Starlette;
- a hosted, multi-tenant service.

## Architecture

One Python package, `sentinelapi`, that runs inside the integrator's process (ADR-0001). Detectors decide; the adapter translates.

| Module | Holds | May import |
| --- | --- | --- |
| `domain` | `ThreatType`, `ThreatLevel`, `RequestFingerprint`, `SecurityEvent` | Standard library only |
| `storage/backend.py` | The `CounterBackend` protocol | Standard library only |
| `storage/memory_backend.py` | `InMemoryBackend` | Standard library only |
| `storage/redis_backend.py` | `RedisBackend` | Standard library and `redis` |
| `detectors` | `RateLimiter`, `BruteForceDetector`, `JWTReplayDetector`, `build_fingerprint` | Standard library, PyJWT, `domain`, `storage.backend` |
| `audit` | SQLAlchemy model, engine helpers, `SecurityEventRepository` | SQLAlchemy, `domain` |
| `middleware.py` | `SentinelMiddleware` | Starlette, `detectors`, `domain`, `logging_config` |
| `config.py`, `logging_config.py` | `SentinelSettings`, structlog setup | pydantic-settings, structlog |
| `examples/demo_app` | The demo FastAPI app | Everything; nothing in `sentinelapi` imports it |

The rules above are written as verifiable statements AR-01 to AR-18 in [ARCHITECTURE_RULES.md](ARCHITECTURE_RULES.md).

**Request flow, as built.**

1. The middleware builds a fingerprint from `request.client.host` and the `User-Agent`.
2. `RateLimiter.check(fingerprint, path)`.
3. If the path is in `jwt_replay_paths` and a bearer token is present: `JWTReplayDetector.check`.
4. Every event is logged with structlog and passed to `on_event`; the demo writes it to the database inside the request.
5. If enforcement is on and the event is HIGH or CRITICAL: 429 for rate limiting, 403 for anything else. Otherwise the request reaches the app.

**Login flow, as built.** Brute-force detection is not in the middleware (ADR-0003): only the login endpoint knows whether a password was right. The demo's `/auth/login` verifies the password, calls `BruteForceDetector.record_failure` only when it is wrong, and answers 403 instead of 401 when the event is HIGH or CRITICAL. A success calls `record_success`, which clears both counters.

**Target.**

- The client's address is resolved through trusted proxies (SEN-19).
- The login asks `BruteForceDetector.check` before verifying the password (SEN-20).
- The middleware is pure ASGI and is installed by `install_sentinel` (SEN-22).
- `on_event` puts the event on a bounded queue that a background writer drains in batches (SEN-25).

**Processes.** SentinelAPI has none of its own: it runs inside the app's process. With several workers or replicas, the counters must live in Redis; the memory backend counts per process (SEN-27 refuses it in production unless explicitly allowed). The demo stack runs the API, Redis and Postgres, plus a `migrate` container from SEN-29.

## Detection contract

What each verdict means. Every "Target" cell is checked by a test in the story named.

### Identity of a request

| | As built | Target |
| --- | --- | --- |
| Client address | Since SEN-19: the direct peer; behind a trusted proxy (`SENTINEL_TRUSTED_PROXIES`), the right-most `X-Forwarded-For` hop no trusted proxy wrote. Before, `request.client.host`: the proxy's address behind one, so every client shared it (seen live as the Docker gateway) | Done (SEN-19, ADR-0004) |
| Fingerprint | SHA-256 of the address, the User-Agent and the user id, first 32 hex characters; since SEN-19 it only correlates events in the audit trail | Done (SEN-19) |
| Rate-limit key | Fingerprint + exact path until SEN-19, so a new User-Agent or a new path opened a new counter. Since SEN-18 and SEN-19: the client's address (IPv6 by /64), plus one counter per configured path prefix | Done (SEN-18, SEN-19) |
| Brute-force keys | Since SEN-19 the client's address for the source axis; the username exactly as typed | The username normalized (trim, casefold), with the normalizer replaceable (SEN-20) |

### Windows

Every backend counts in fixed windows: the first hit opens a window of `window_seconds`, and later hits never extend it (ADR-0002). One contract suite (AR-07) runs against each.

- Redis sets the TTL on the first hit only (`EXPIRE … NX`).
- The memory backend does the same since SEN-17, and bounds its memory: expired keys are swept at most once a second, and past `max_keys` (100,000) the tenth closest to expiring is dropped.

Until SEN-17 the memory backend moved its expiry forward on every hit, so a client sending one request every 2 s against a limit of 60 per 60 s was blocked at its 121st request, after 4 minutes (audit, probe 1). That scenario is now a test.

### Verdicts

| Detector | Condition | As built | Target |
| --- | --- | --- | --- |
| Rate limit | count > `rate_limit_max_requests` | MEDIUM until SEN-18; since then HIGH, 429 with `Retry-After` | Done (SEN-18) |
| Rate limit | count > 2 × `rate_limit_max_requests` | HIGH, 429: the first block until SEN-18 | (covered by the row above) |
| Rate limit | count passes `rate_limit_warn_at` (default 80 % of the limit) | MEDIUM, logged once per window since SEN-18 | Done (SEN-18) |
| Brute force | failures from one source ≥ 5 | MEDIUM | Same |
| Brute force | failures from one source ≥ 10 | HIGH, 403 | HIGH; the source is refused before its password is checked until the window ends (SEN-20) |
| Brute force | failures against one username ≥ 8 | HIGH, 403 | Per ADR-0005 |
| Brute force | failures against one username ≥ 15 | CRITICAL, 403 | Per ADR-0005 |
| Token replay | expired token | LOW | Same |
| Token replay | bad signature or claims; no `jti` | MEDIUM | Same; a token without `exp` too (SEN-21) |
| Token replay | `jti` already redeemed | CRITICAL, 403 | Same, remembered for the token's whole life (SEN-21) |

HIGH and CRITICAL block; LOW and MEDIUM are only logged and recorded.

### HTTP responses

- **Middleware, enforcing and blocking:** 429 for rate limiting, 403 otherwise, with `{"detail": "Request blocked by SentinelAPI", "reason": "<threat_type>"}`. Since SEN-18 a 429 carries `Retry-After`, the seconds left in the window.
- **Demo login, as built:** 403 with `"Blocked by SentinelAPI: <detail>"`, which reveals the failure count and the username. Target: 429 with `Retry-After` and no internal detail (SEN-20).
- **Shadow mode** (`SENTINEL_ENFORCE=false`): the same events are logged and recorded; nothing is blocked.

## Data model

One table, `sentinel_security_events`, written by the audit sink. SQLite in development and tests, PostgreSQL 16 in the demo stack.

| Column | As built | Target |
| --- | --- | --- |
| `id` | varchar(36), UUID v4 from Python | Same |
| `threat_type` | varchar(32), indexed | Same, with a CHECK on the enum's values (SEN-23) |
| `threat_level` | varchar(16), indexed | Same, with a CHECK (SEN-23) |
| `fingerprint_key` | varchar(32), indexed | Same |
| `ip` | varchar(64), the raw address | Replaced by `client_hash`: a keyed hash of the address (SEN-24, ADR-0006) |
| `user_id` | varchar(128), nullable; always null today | Replaced by `subject_hash`: a keyed hash of the normalized username or user id (SEN-24) |
| `path` | varchar(256) | Same |
| `detail` | varchar(512); names the targeted account for brute force | Never contains a username, an address or token material (SEN-24) |
| `occurred_at` | double precision (epoch seconds) | timestamptz (SEN-23) |
| `created_at` | timestamp without time zone, from `datetime.utcnow` | timestamptz, `now()` by default (SEN-23) |
| `count` | — | integer ≥ 1: identical events folded into one row (SEN-25) |
| `last_occurred_at` | — | timestamptz (SEN-25) |

**Rules.**

- The table is created by a migration shipped with the package, never by `create_all` at startup (SEN-23, ADR-0006).
- In the demo stack the app's database role cannot UPDATE or DELETE the table; retention runs as the owner role (SEN-23, SEN-24).
- Rows older than `SENTINEL_AUDIT_RETENTION_DAYS` are purged by a command (SEN-24).

## Configuration contract

Every setting is an environment variable with the `SENTINEL_` prefix, or a line in `.env`.

| Variable | Default | Purpose | Status |
| --- | --- | --- | --- |
| `SENTINEL_BACKEND` | `memory` | `memory` or `redis`; any other value silently means memory today | Built; a typo fails from SEN-27 |
| `SENTINEL_REDIS_URL` | `redis://localhost:6379/0` | Redis for counters | Built |
| `SENTINEL_DATABASE_URL` | `sqlite+aiosqlite:///./sentinelapi_audit.db` | Audit database | Built |
| `SENTINEL_RATE_LIMIT_MAX_REQUESTS` | `60` | Requests per window per client; the next one is blocked | Built; until SEN-18 blocking started past twice it |
| `SENTINEL_RATE_LIMIT_WINDOW_SECONDS` | `60` | Window length | Built |
| `SENTINEL_BRUTE_FORCE_WINDOW_SECONDS` | `900` | Brute-force window | Built |
| `SENTINEL_BRUTE_FORCE_PER_FINGERPRINT_MEDIUM` / `_HIGH` | `5` / `10` | Failures from one source | Built |
| `SENTINEL_BRUTE_FORCE_PER_USERNAME_HIGH` / `_CRITICAL` | `8` / `15` | Failures against one account | Built |
| `SENTINEL_JWT_SECRET` | `change-me` | Key that verifies tokens | Built; the demo ignores it until SEN-21; production refuses the default in SEN-27 |
| `SENTINEL_JWT_ALGORITHMS` | `["HS256"]` | Accepted algorithms | Built; the demo ignores it until SEN-21 |
| `SENTINEL_JWT_REPLAY_PATHS` | `["/auth/refresh"]` | Paths checked for replay | Built |
| `SENTINEL_ENFORCE` | `true` | `false` = shadow mode | Built |
| `SENTINEL_ENV` | `development` | `production` turns on the refusals of SEN-27 | Planned (SEN-27) |
| `SENTINEL_ALLOW_MEMORY_BACKEND` | `false` | Lets production run the memory backend, for a single process | Planned (SEN-27) |
| `SENTINEL_BRUTE_FORCE_ACCOUNT_ACTION` | `lock` | `lock` or `signal`: what the account axis does (ADR-0005) | Planned (SEN-20) |
| `SENTINEL_TRUSTED_PROXIES` | empty | CIDRs whose `X-Forwarded-For` is believed | Built (SEN-19) |
| `SENTINEL_RATE_LIMIT_WARN_AT` | 80 % of the limit | MEDIUM threshold, logged once per window | Built (SEN-18) |
| `SENTINEL_RATE_LIMIT_EXEMPT_PATHS` | `["/health", "/ready"]` | Never counted | Built (SEN-18) |
| `SENTINEL_RATE_LIMIT_PATHS` | empty | Stricter limits per path prefix, e.g. `{"/auth/": 10}` | Built (SEN-18) |
| `SENTINEL_JWT_AUDIENCE`, `SENTINEL_JWT_ISSUER` | empty | Checked when set | Planned (SEN-21) |
| `SENTINEL_AUDIT_HASH_KEY` | none; required in production | Key for `client_hash` and `subject_hash` | Planned (SEN-24) |
| `SENTINEL_AUDIT_RETENTION_DAYS` | `90` | Purge horizon | Planned (SEN-24) |
| `SENTINEL_AUDIT_QUEUE_SIZE`, `SENTINEL_AUDIT_AGGREGATE_SECONDS` | `10000`, `60` | Write path | Planned (SEN-25) |
| `SENTINEL_OPERATOR_TOKEN` | none | Protects the demo's events API | Planned (SEN-26) |
| `SENTINEL_ALERT_WEBHOOK_URL` | empty | CRITICAL alerts | Planned (SEN-31) |
| `SENTINEL_DEMO_MODE` | `false` | Turns on the attack console | Planned (SEN-32) |

## Demo app API contract

The demo app is not part of the library; it is how a visitor and the tests see the library work. Its generated OpenAPI document is exported to `docs/openapi.json` from SEN-37.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | Public | Liveness; never rate limited (SEN-18) |
| GET | `/ready` | Public | Redis and database reachable, 503 otherwise. Planned (SEN-30) |
| POST | `/auth/login` | Public | JSON `{username, password}` → `{access_token, refresh_token}`; 401 wrong credentials; 403 brute force (429 from SEN-20) |
| POST | `/auth/refresh` | Bearer refresh token | New pair; a replayed token is stopped by the middleware with 403 |
| GET | `/me` | Bearer access token | `{user}` |
| GET | `/security/events` | Public today; operator token from SEN-26 | The 50 latest HIGH and CRITICAL events |
| POST | `/demo/scenarios/{name}` | Public, only with `SENTINEL_DEMO_MODE` | Runs `burst`, `stuffing` or `replay` server-side with synthetic sources. Planned (SEN-32) |
| GET | `/demo/events` | Public, only with `SENTINEL_DEMO_MODE` | Server-sent events with the visitor's own verdicts. Planned (SEN-32) |

The demo user is `alice@example.com` with the password `correct-horse-battery-staple`. It is public on purpose and exists only in the demo app.

## Non-functional requirements and security

A security library that blocks legitimate users is worse than no library. Every decision prefers a false negative over blocking someone under their limit, and is backed by a test.

| Category | Requirement | How it is verified |
| --- | --- | --- |
| Correctness | A client under its limit is never blocked, however long it runs | Steady-traffic test with a controlled clock, on every backend (SEN-17) |
| Correctness | Every backend counts the same way | One contract suite run against each `CounterBackend` (SEN-17, AR-07) |
| Evasion | A new User-Agent, a username in another case or a different path does not reset a counter | One test per evasion of the audit (SEN-18, SEN-19, SEN-20) |
| Evasion | A blocked source or account cannot log in, even with the right password, until its window ends | Test (SEN-20) |
| Evasion | A single-use token is refused for its whole life | Test with the clock moved past one hour (SEN-21) |
| Spoofing | `X-Forwarded-For` from a peer that is not a trusted proxy is ignored | Test (SEN-19) |
| Availability | An unreachable audit database never turns a request into a 500 | Test with the database down (SEN-25) |
| Availability | An attack does not become a write flood: rows grow with distinct sources, not with requests | Flood test: 1,000 requests from one source write at most one row per threat level and window (SEN-25) |
| Availability | The memory backend's memory stays bounded | Test: expired keys are evicted and the key count is capped (SEN-17) |
| Privacy | No raw address, username or token in the audit table or the logs | AR-13 test (SEN-24) |
| Privacy | Events are visible to operators only; a demo visitor sees only their own | Tests (SEN-26, SEN-32) |
| Security | Production refuses default or short secrets and the memory backend | Settings tests (SEN-27, AR-10) |
| Integrity | The audit table is append-only for the app's database role | Test on Postgres (SEN-23, AR-12) |
| Performance | p95 latency added ≤ 2 ms with Redis on the same host | Benchmark (SEN-35) |
| Reproducibility | The image installs exactly `uv.lock`; the package imports with its required dependencies only | CI (SEN-11, SEN-28, AR-06) |
| Deployment | `docker compose up` migrates before the API starts | Startup from an empty database in CI (SEN-29) |
| Observability | JSON logs with a request id; `/ready` checks Redis and the database | Tests (SEN-30) |
| Quality | Ruff and Mypy strict without errors; architecture tests green; coverage ≥ 90 % in `detectors` and `storage` | GitHub Actions (SEN-12, SEN-14, SEN-15) |
| Compatibility | The Python versions of ADR-0008 | CI matrix (SEN-14) |

## Engineering rules

**Stack.** Python 3.12 for development and the image (the library's supported range is ADR-0008's decision), FastAPI and Starlette, Pydantic v2 and pydantic-settings, SQLAlchemy 2 async (asyncpg, aiosqlite), Alembic (SEN-23), PyJWT, redis-py's asyncio client, structlog, uv, Ruff, Mypy strict, Pytest with pytest-asyncio, httpx. PostgreSQL 16 and Redis 7 in the demo stack; SQLite only in tests and local development. Docker Compose; Caddy on the server (ADR-0009).

**Architecture rules.** The module rules of the Architecture section, written as verifiable rules AR-01 to AR-18 in [ARCHITECTURE_RULES.md](ARCHITECTURE_RULES.md), each with the test that checks it (SEN-15).

**How we work**

- **A plan first.** Each story starts from a short plan, what will change and which files, agreed with the product owner before any code.
- **Raise contradictions.** If a request contradicts this specification or an ADR, the contradiction is raised before the work starts. A change to this document goes in its own `docs(spec)` commit.
- **Small commits.** Conventional Commits, one PR per story; work over about 300 lines is split.
- **Explain decisions.** Non-obvious decisions are explained where they are made: a comment that says why, the PR, or an ADR.
- **Evidence over claims.** A guarantee enters the README only together with the test that proves it.

**Definition of done**

- The acceptance criteria are met and demonstrable.
- Unit tests for every detector branch, and an integration test for every new or changed behavior of the middleware or the demo app; backend behavior tested against both backends.
- Green checks: Ruff, Ruff format, Mypy strict, the architecture tests, Pytest.
- `docker compose up` from a clean clone brings the demo up with no manual steps.
- This specification, the README's configuration table and `.env.example` are updated when a setting or a contract changes.
- If a story changes the architecture, ARCHITECTURE_RULES.md, its tests and the corresponding ADR are updated in the same PR.

## Repository, conventions and living documentation

Target tree. Entries marked with a story do not exist yet.

```text
sentinelapi/
├── sentinelapi/
│   ├── domain/                   # entities, no dependencies
│   ├── detectors/                # rate limit, brute force, token replay, fingerprint
│   ├── storage/                  # CounterBackend and its implementations
│   ├── audit/
│   │   └── migrations/           # Alembic history for the audit table (SEN-23)
│   ├── alerts/                   # webhook on CRITICAL events (SEN-31)
│   ├── client_address.py         # trusted proxies (SEN-19)
│   ├── integration.py            # install_sentinel (SEN-22)
│   ├── middleware.py             # pure ASGI from SEN-22
│   ├── config.py
│   ├── logging_config.py
│   └── py.typed
├── examples/demo_app/            # + attack console (SEN-32)
├── tests/
│   ├── unit/
│   ├── contract/                 # every CounterBackend (AR-07)
│   ├── integration/              # the demo app; Postgres from SEN-23
│   └── architecture/             # AR-NN
├── benchmarks/                   # SEN-35
├── deploy/                       # docker-compose.prod.yml, Caddyfile (SEN-29, SEN-33)
├── docs/
│   ├── SPEC.md                   # this document
│   ├── BACKLOG.md                # stories and sprint plan
│   ├── ARCHITECTURE_RULES.md
│   ├── AUDIT.md                  # local, not versioned (SEN-38)
│   ├── openapi.json              # the demo app's contract (SEN-37)
│   ├── adr/
│   ├── runbooks/                 # SEN-34
│   └── sprints/
├── .github/workflows/ci.yml
├── scripts/check_imports.py      # AR-06, run by CI without extras
├── docker-compose.yml            # with the migrate service (SEN-29)
├── Dockerfile
├── Makefile
├── pyproject.toml
├── uv.lock
├── CHANGELOG.md                  # SEN-37
├── LICENSE
├── SECURITY.md
├── CLAUDE.md                     # local, not versioned (SEN-38)
└── README.md
```

Kept on each workstation and out of version control (SEN-38): `CLAUDE.md` and `.claude/`, the coding agent's instructions and settings; `graphify-out/`, its generated code graph; `docs/AUDIT.md` and `docs/COMMENTS_REVIEW.md`, internal working notes. The README's Known limitations sums up the audit's result.

| Artifact | Purpose | When it is updated |
| --- | --- | --- |
| `docs/SPEC.md` | Vision, scope, architecture, detection contract, data, configuration | When the scope or a contract changes |
| `docs/BACKLOG.md` | Stories, acceptance criteria, sprint plan | At planning and when a story is added or moved |
| `docs/ARCHITECTURE_RULES.md` | Verifiable architecture rules and their tests | When a story changes the architecture |
| `docs/adr/NNNN-*.md` | One technical decision: context, options, decision, consequences | Every non-trivial decision |
| `docs/sprints/sprint-N.md` | What was delivered, decisions, spec changes, retro | At the close of each sprint |
| `docs/AUDIT.md` (local, SEN-38) | Independent comparison of the repository against these documents; the README sums up its result | Before a release, or when asked |
| `CHANGELOG.md` | Visible changes per version (Keep a Changelog + SemVer) | Every release |

**Conventions.** Branches `feat/SEN-NN-description`, `fix/…`, `chore/…`; Conventional Commits; PRs reference the story and include the DoD checklist; table and column names in English `snake_case`; code, comments and documentation in English.
