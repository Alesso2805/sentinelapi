# ADR-0002: Fixed-window counters, with one semantics in every backend

- **Status:** Accepted (retroactive); the memory backend does not follow it yet (SEN-17)
- **Date:** 2026-08-31, written down on 2026-10-22
- **Related:** SPEC.md › Detection contract › Windows; ARCHITECTURE_RULES.md AR-07; AUDIT.md probes 1, 2 and 6; SEN-17, SEN-39

## Context

Every detector counts something within a window: requests per client, failed logins per source and per account. The counting primitive must be cheap, because it runs on every request, and atomic across processes when Redis is used.

## Options

1. **Fixed window:** one counter per key, created with a TTL on the first hit. One INCR per request. A client can send up to twice the limit across a window boundary.
2. **Sliding log:** one timestamp per request in a sorted set. Exact, but memory grows with the limit and every request costs several commands.
3. **Sliding-window counter:** the current and previous fixed windows, weighted. Close to exact with two counters.
4. **Token bucket or GCRA:** smooth, one key per client, but harder to explain in an audit trail ("27 requests in 60 s" is clearer than "bucket empty").

## Decision

Option 1, as `rate_limiter.py`'s docstring argues: for abuse detection, not billing, a fixed window catches the same bursts with one INCR.

The window starts with the first hit and is never extended by later hits. **Every backend implements exactly this**, and one contract suite proves it (AR-07).

## Consequences

- Redis already does it: `INCR` and `EXPIRE … NX` in one transaction (`redis_backend.py:27-32`).
- **The memory backend does not.** It moves the expiry forward on every hit (`memory_backend.py:29`), so a client that never pauses for a full window is never reset. In the audit, a client at half its limit was blocked after 4 minutes. That is the default backend, the one the tests and the demo use. SEN-17 fixes it and adds key eviction (expired keys are never removed today).
- The README's "sliding-window rate limiting" is not true and goes in SEN-37. A smoother limiter can come later as an option on the same port (SEN-39, Could).
- The boundary effect (up to twice the limit in a short span across two windows) is accepted and documented in the README.
