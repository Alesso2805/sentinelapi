# Sprint 2 — Detectors that hold: the same windows everywhere, limits that mean what they say, no cheap evasion (SEN-17 to SEN-21)

**Status as of 2026-10-22:** closed. Started right after Sprint 1 and finished the same day, with no calendar: all five stories (19 points) merged with green CI, #10 to #14. Every evasion the audit found in the detectors is now a test, and five of the eight Known limitations left the README; the three left are the audit trail's (Sprint 3).

**Order:** SEN-17 (its contract suite and injectable clock are what the rest stand on), SEN-19, SEN-18, SEN-20, SEN-21.

**Rule for every story:** each evasion of the audit (README › Known limitations) is first written as a test that fails, then made to pass, and its line leaves the README in the same PR.

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-17 | #10 | `sentinelapi/clock.py` (AR-16): detectors and the memory backend receive a `Clock`; `SecurityEvent.occurred_at` comes from it. The memory backend opens a window on the first hit and never extends it, sweeps expired keys at most once a second, and past `max_keys` drops the tenth closest to expiring, so a flood of new keys pays one sweep per batch | The contract suite's fixed-window test passes on both backends (its xfail is gone); new tests for probe 1 (600 requests, one every 2 s against 60 per 60 s: no event) and probe 6 (10,000 expired keys evicted), and for the key cap. 79 passed, 9 xfailed |
| SEN-19 | #11 | `sentinelapi/client_address.py`: `ClientResolver` believes `X-Forwarded-For` only from `SENTINEL_TRUSTED_PROXIES`, walking it right to left; ports and brackets understood, garbage falls back to the peer. `RequestFingerprint.client` is the address, IPv6 grouped by /64 and IPv4-mapped IPv6 as IPv4; the rate limiter and the brute-force source axis count on it, never on the User-Agent. The middleware and the demo's login resolve the address the same way. Bad CIDRs fail at startup | Probe 3 is a test (500 requests with a new User-Agent each: 495 events); probe 9 is a test (behind a trusted proxy two clients keep their own limits); a forged header from an untrusted peer changes nothing; 13 resolver tests; hostile `X-Forwarded-For` values. 102 passed, 9 xfailed |
| SEN-18 | #12 | One counter per client whatever the path, so inventing URLs buys no budget; the request after the limit is HIGH with `retry_after`, the middleware's 429 carries `Retry-After`; MEDIUM once per window when 80 % (or `SENTINEL_RATE_LIMIT_WARN_AT`) is passed; `SENTINEL_RATE_LIMIT_EXEMPT_PATHS` (`/health`, `/ready`) and `SENTINEL_RATE_LIMIT_PATHS`, stricter counters per prefix. The storage port gains `ttl(key)`, in both backends and the contract suite. Empty settings in `.env` mean the default | The 61st request of 60 gets 429 and a `Retry-After` between 1 and 60 (end to end); `Retry-After` is exactly what is left of the window (fake clock); a new path does not reset the count; 200 health checks stay 200; `ttl` passes the contract on both backends. 111 passed, 9 xfailed |
| SEN-20 | #13 | `BruteForceDetector.check` before the password: a source over its threshold is refused, and an account over its own is locked (`lock`) or flagged `challenge_required` (`signal`), with `retry_after`. Usernames are trimmed, casefolded (replaceable) and hashed into the keys, so none reaches Redis. A per-pair counter lets `record_success` take back only that source's failures against that account, through the new `CounterBackend.decrement` (a Lua script in Redis). The demo answers 429 with `Retry-After` and one fixed message. Settings `…_PER_FINGERPRINT_…` renamed `…_PER_SOURCE_…`; `SENTINEL_BRUTE_FORCE_ACCOUNT_ACTION` | Probes 4, 5 and 7 are tests; so are one source against many accounts (the branch no test reached), an attacker signing into its own account, the block lifting with the window, signal mode and a custom normalizer; end to end, 12 failures then the right password → 429. `decrement` passes the contract on both backends. 125 passed, 9 xfailed |
| SEN-21 | #14 | `exp` and `jti` required (`options={"require": [...]}`), so a token without `exp` is invalid instead of being forgotten after an hour; a used `jti` is kept for `exp − now`, from the clock; a non-string `jti` is invalid; `SENTINEL_JWT_AUDIENCE` and `SENTINEL_JWT_ISSUER` checked when set. The demo signs and verifies with `SENTINEL_JWT_SECRET` and `SENTINEL_JWT_ALGORITHMS` instead of its constant, through `app.state.settings`, and issues `aud` and `iss` when they are set; its AR-16 exception is gone | A token replayed two hours later on a fake clock: CRITICAL; a token without `exp`: invalid; wrong audience or issuer: invalid; end to end, a token signed with the old constant gets 401 and audience and issuer travel through login and refresh. 131 passed, 9 xfailed |

## Sprint decisions

- **SEN-19 before SEN-18,** as planned: the per-client key had to exist before limits could count on it.
- **One counter per client, whatever the path** (SEN-18). The SPEC's target said "client address plus one counter per configured prefix"; counting per exact path would have kept the evasion of inventing URLs.
- **The storage port grew two methods,** `ttl` (SEN-18, for `Retry-After`) and `decrement` (SEN-20, so a success takes back only its own failures), each covered by the contract suite on both backends.
- **Usernames are hashed into the brute-force keys** (SEN-20): no username reaches Redis, and a 1 MB username is a 32-character key.
- **Settings renamed before 1.0.0:** `SENTINEL_BRUTE_FORCE_PER_FINGERPRINT_*` became `..._PER_SOURCE_*`, since the source axis no longer counts on the fingerprint. The CHANGELOG of SEN-37 lists it.
- **An empty variable in `.env` means the default** (`env_ignore_empty`), so `.env.example` can list optional settings without values.

## Changes to the specification in this sprint

- #10 to #14: the Detection contract (identity, windows, verdicts, HTTP responses), the scope table, the configuration table and the demo's API describe what is built, each row saying what it was before.
- #10: AR-02 allows `sentinelapi.clock`.

## Retro

- **Went well:** writing the tests before the code caught a gap in ADR-0005 itself. "A success clears its own source's counters" would have let an attacker clear its record by signing into an account of its own; a success now takes back only that source's failures against that account.
- **To improve:** the integration tests used `/health` for bursts, and broke when health checks became exempt; tests should drive the behavior they check, not the nearest endpoint.
- **To try:** in Sprint 3, write AR-13's privacy scan as the first commit of SEN-24, and keep it running against Postgres as well as SQLite.
