# ADR-0007: A pure ASGI middleware, installed by one call

- **Status:** Proposed
- **Date:** 2026-10-22
- **Related:** ADR-0001; ADR-0003; ARCHITECTURE_RULES.md AR-15; SEN-22

## Context

`SentinelMiddleware` extends Starlette's `BaseHTTPMiddleware`. Starlette's documentation lists that class's limitations: context variables set in the endpoint do not propagate back through it, and it wraps the response in its own streaming machinery. For a library that sits in front of other people's apps, those are surprises the integrator did not choose.

Wiring is also manual. The demo's `main.py` builds the settings, the backend, three detectors and the middleware, keeps the brute-force detector in `app.state`, and never closes the Redis client. An integrator has to copy that.

## Options

1. **Keep `BaseHTTPMiddleware`** and document its limitations.
2. **A pure ASGI middleware:** a class with `__call__(scope, receive, send)` that inspects the scope, answers directly when it blocks, and otherwise passes `receive` and `send` through untouched.
3. **FastAPI dependencies instead of a middleware,** opt-in per route. Precise, but easy to forget on a new route, and the rate limit would no longer cover everything.

## Decision (proposed)

Option 2, plus an installer:

- `SentinelMiddleware` becomes pure ASGI. It reads only the scope (path, headers, client) and never consumes `receive` (AR-15).
- `install_sentinel(app, settings=None, *, on_event=None)`:
  - builds the backend, the detectors, the audit sink and the middleware from the settings;
  - registers their startup and shutdown with the app's lifespan, closing Redis and draining the audit queue;
  - returns a handle whose `login_guard` is what the login endpoint calls (ADR-0003, ADR-0005).
- An exception in `on_event` is logged and never fails the request.

## Consequences

- The README's integration fits in three lines: create the app, call `install_sentinel(app)`, use `sentinel.login_guard` in the login.
- The demo becomes the installer's first user, and its tests cover the integration path that integrators follow.
- Pure ASGI is more code than `dispatch`. Its tests must cover streaming responses and background tasks passing through untouched (SEN-22).
