# Sprint 3 — A three-line integration and an audit trail that is migrated, private and flood-proof (SEN-22 to SEN-26)

**Status as of 2026-10-22:** started right after Sprint 2, with no calendar. 18 points.

**Order:** SEN-22 (the installer is where the audit sink plugs in), SEN-23, SEN-24, SEN-25, SEN-26.

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-22 | #15 | `sentinelapi/integration.py`: `install_sentinel(app, settings, on_event=...)` builds the backend, the three detectors, the client resolver and the audit sink (`audit/sink.py`), adds the middleware, starts and stops them inside the app's own lifespan (closing Redis, which nothing closed before), and returns a `Sentinel`; its `login_guard` wraps the login's password check. `SentinelMiddleware` is pure ASGI. Every event goes to the log, the audit sink and `on_event`; a failing sink is logged and never fails the request. `SENTINEL_AUDIT=false` keeps events in the log only. The demo uses all of it | The README's snippet is extracted and executed as a test; streaming responses and background tasks pass through; a raising `on_event` leaves the 429 in place; the app's own lifespan still runs and the backend is closed; AR-18 holds, so its strict xfail is gone. 137 passed, 8 xfailed |
| SEN-23 | — | — | — |
| SEN-24 | — | — | — |
| SEN-25 | — | — | — |
| SEN-26 | — | — | — |

## Sprint decisions

—

## Changes to the specification in this sprint

—

## Retro

- **Went well:** —
- **To improve:** —
- **To try:** —
