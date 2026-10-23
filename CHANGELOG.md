# Changelog

All notable changes to SentinelAPI are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). From 1.0.0, the public API is the settings, `install_sentinel` and what it returns, the event schema and the audit table ([ADR-0008](docs/adr/0008-distribution.md)).

## [Unreleased]

### Added

- The demo's attack console speaks Spanish too. The browser's languages decide until the visitor picks one with its ES/EN switch, which is remembered.

## [1.0.0] - 2026-10-22

The first release: everything since the prototype of 2026-08-31 (0.1.0, never published). It is published on PyPI as `fastapi-sentinel`; the package it installs is `sentinelapi`.

### Added

- `install_sentinel(app, settings, on_event)` wires everything in one call: the rate limiter and the replay check on every request, a login guard, the audit trail and the alerts. It returns a `Sentinel` with `login_guard`, `report()`, `ready()` and `sandbox()`.
- `LoginGuard`: `check`, `failed` and `succeeded`, called around the app's own password check. `check` refuses a blocked source or a locked account before the password is verified.
- `SENTINEL_BRUTE_FORCE_ACCOUNT_ACTION`: `lock` (the default) or `signal`. With `signal`, the app gets `challenge_required` instead of a locked account.
- Trusted proxies (`SENTINEL_TRUSTED_PROXIES`). The client is the right-most `X-Forwarded-For` hop that is not a trusted proxy, and IPv6 clients are grouped by /64.
- New rate-limiting settings:
  - stricter limits per path prefix (`SENTINEL_RATE_LIMIT_PATHS`);
  - a warning threshold (`SENTINEL_RATE_LIMIT_WARN_AT`);
  - exempt paths (`SENTINEL_RATE_LIMIT_EXEMPT_PATHS`, by default `/health` and `/ready`);
  - `Retry-After` on every 429.
- `SENTINEL_JWT_AUDIENCE` and `SENTINEL_JWT_ISSUER`, checked when set.
- The `sentinel` command:
  - `sentinel migrate [--app-role ROLE]` creates the audit table from Alembic migrations, with their own version table. On Postgres, the app's role gets INSERT and SELECT only.
  - `sentinel purge` deletes events older than `SENTINEL_AUDIT_RETENTION_DAYS`.
- Keyed hashes (HMAC with `SENTINEL_AUDIT_HASH_KEY`) for addresses, accounts and fingerprints, in the audit trail, the log and the alerts.
- Audit writes off the request path. Identical events within `SENTINEL_AUDIT_AGGREGATE_SECONDS` become one row with `count` and `last_occurred_at`. A background task writes the rows from a bounded queue (`SENTINEL_AUDIT_QUEUE_SIZE`).
- Webhook alerts for CRITICAL events (`SENTINEL_ALERT_WEBHOOK_URL`): Slack-compatible, at most one per account (or source) and threat every 10 minutes, retried with backoff.
- `SENTINEL_ENV=production`, which refuses three things and names every problem at once:
  - an example or short JWT secret;
  - a missing audit hash key;
  - the memory backend, unless `SENTINEL_ALLOW_MEMORY_BACKEND=true`.
- Readiness (`Sentinel.ready()` and the demo's `/ready`), a request id on every response and log line, and JSON logs in production.
- `py.typed`, and the extras `redis`, `postgres` and `sqlite`.
- In the demo:
  - the events API, for the operator only (`SENTINEL_OPERATOR_TOKEN`), with filters and pages;
  - the attack console (`SENTINEL_DEMO_MODE`);
  - its OpenAPI document in `docs/openapi.json`.
- Operations:
  - a reproducible, non-root image;
  - a Compose stack that migrates, then starts;
  - a production overlay behind Caddy;
  - runbooks for deploying, backing up and restoring, rotating secrets and rolling out;
  - a benchmark (`make bench`).

### Changed

- **Breaking:** `SENTINEL_BRUTE_FORCE_PER_FINGERPRINT_MEDIUM` and `_HIGH` are now `SENTINEL_BRUTE_FORCE_PER_SOURCE_MEDIUM` and `_HIGH`.
- **Breaking:** rate limits and brute-force counts are keyed on the client's address, no longer on a fingerprint of the address and the User-Agent.
- **Breaking:** the audit table is created by migrations, no longer by `create_all` at startup, and its columns changed:
  - `client_hash` and `subject_hash` replace `ip` and `user_id`;
  - `count` and `last_occurred_at` are new;
  - `occurred_at` is a timezone-aware datetime.

  There is no migration from the prototype's table: run `sentinel migrate` on a new database.
- **Breaking:** `SENTINEL_BACKEND` accepts only `memory` or `redis`. Any other value now fails at startup instead of meaning memory.
- `SentinelMiddleware` is pure ASGI (it was a `BaseHTTPMiddleware`), so streaming responses and background tasks pass through untouched.
- Rate limiting blocks from the first request over the limit (HIGH, 429), not from twice the limit. On both backends, a window starts with the first hit and is never extended.
- A brute-force block is checked before the password and holds until its window ends. It is answered with 429 and `Retry-After`, the same whether the account exists or not.
- Usernames are trimmed and casefolded before counting.
- On a replay path, a JWT needs `exp` and `jti`, and a used `jti` is remembered until the token expires.
- Events carry `retry_after`, `challenge_required` and `subject`. Their time comes from an injected clock.

### Fixed

- The in-memory backend extended a window on every hit, so a client under its limit was eventually blocked. It also kept expired keys forever; they are now evicted, and live keys are capped.
- A new User-Agent reset a client's count.
- Behind a proxy, every client shared the proxy's address.
- A blocked source or a locked account still got in with the right password.
- The owner's successful login erased failures from other sources, and an attacker could clear its own record by signing into an account of its own.
- A token without `exp` was forgotten after an hour, and could be replayed after that.
- Each event was written to the audit table while its request was being answered, so a database outage could fail requests.
- With `lock`, credential stuffing never reached CRITICAL or the webhook (SEN-43).

### Security

- Raw addresses and usernames no longer reach the audit trail or the log.
- The demo's events API requires the operator's token; it used to be public.
- The app's database role can only add and read audit rows.

[Unreleased]: https://github.com/Alesso2805/sentinelapi/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Alesso2805/sentinelapi/releases/tag/v1.0.0
