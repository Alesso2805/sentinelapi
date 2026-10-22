# Sprint 2 — Detectors that hold: the same windows everywhere, limits that mean what they say, no cheap evasion (SEN-17 to SEN-21)

**Status as of 2026-10-22:** started right after Sprint 1, with no calendar. 19 points.

**Order:** SEN-17 (its contract suite and injectable clock are what the rest stand on), SEN-19, SEN-18, SEN-20, SEN-21.

**Rule for every story:** each evasion of the audit (README › Known limitations) is first written as a test that fails, then made to pass, and its line leaves the README in the same PR.

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-17 | #10 | `sentinelapi/clock.py` (AR-16): detectors and the memory backend receive a `Clock`; `SecurityEvent.occurred_at` comes from it. The memory backend opens a window on the first hit and never extends it, sweeps expired keys at most once a second, and past `max_keys` drops the tenth closest to expiring, so a flood of new keys pays one sweep per batch | The contract suite's fixed-window test passes on both backends (its xfail is gone); new tests for probe 1 (600 requests, one every 2 s against 60 per 60 s: no event) and probe 6 (10,000 expired keys evicted), and for the key cap. 79 passed, 9 xfailed |
| SEN-19 | #11 | `sentinelapi/client_address.py`: `ClientResolver` believes `X-Forwarded-For` only from `SENTINEL_TRUSTED_PROXIES`, walking it right to left; ports and brackets understood, garbage falls back to the peer. `RequestFingerprint.client` is the address, IPv6 grouped by /64 and IPv4-mapped IPv6 as IPv4; the rate limiter and the brute-force source axis count on it, never on the User-Agent. The middleware and the demo's login resolve the address the same way. Bad CIDRs fail at startup | Probe 3 is a test (500 requests with a new User-Agent each: 495 events); probe 9 is a test (behind a trusted proxy two clients keep their own limits); a forged header from an untrusted peer changes nothing; 13 resolver tests; hostile `X-Forwarded-For` values. 102 passed, 9 xfailed |
| SEN-18 | #12 | One counter per client whatever the path, so inventing URLs buys no budget; the request after the limit is HIGH with `retry_after`, the middleware's 429 carries `Retry-After`; MEDIUM once per window when 80 % (or `SENTINEL_RATE_LIMIT_WARN_AT`) is passed; `SENTINEL_RATE_LIMIT_EXEMPT_PATHS` (`/health`, `/ready`) and `SENTINEL_RATE_LIMIT_PATHS`, stricter counters per prefix. The storage port gains `ttl(key)`, in both backends and the contract suite. Empty settings in `.env` mean the default | The 61st request of 60 gets 429 and a `Retry-After` between 1 and 60 (end to end); `Retry-After` is exactly what is left of the window (fake clock); a new path does not reset the count; 200 health checks stay 200; `ttl` passes the contract on both backends. 111 passed, 9 xfailed |
| SEN-20 | — | — | — |
| SEN-21 | — | — | — |

## Sprint decisions

—

## Changes to the specification in this sprint

—

## Retro

- **Went well:** —
- **To improve:** —
- **To try:** —
