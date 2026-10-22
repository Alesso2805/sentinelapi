# ADR-0003: Brute-force detection is called by the login endpoint, not by the middleware

- **Status:** Accepted (retroactive)
- **Date:** 2026-08-31, written down on 2026-10-22
- **Related:** SPEC.md › Architecture › Login flow; ADR-0005; README › Architecture; `examples/demo_app/auth.py`

## Context

Rate limiting and token replay need only the request's headers and path, so they fit a blanket middleware. Brute-force detection needs to know whether a login attempt failed, which only the endpoint that checked the password knows.

## Options

1. **Infer failure in the middleware** from the response: status 401, or a body field. Fragile: it depends on each app's status codes and response shapes, and reading a response body in middleware means buffering it.
2. **Expose the detector to the app,** which calls it from its login endpoint.
3. **Ship a login endpoint** that apps must use. It would own the app's authentication, which is not SentinelAPI's job.

## Decision

Option 2. `BruteForceDetector` is used directly by the login endpoint: `record_failure` when the password is wrong, `record_success` when it is right. The demo's `auth.py` is the reference integration.

## Consequences

- Each integrator must call it; forgetting means no brute-force protection, silently. SEN-22's installer exposes the detector next to the middleware, and the README shows the login integration as part of the three lines.
- As built, the detector is consulted only after a wrong password, so a "block" changes a 401 into a 403 and nothing more: the right password still gets in (audit, probe 7). ADR-0005 adds a check before the password, which keeps this decision (the endpoint calls the detector) and changes when it calls it.
- The demo writes brute-force events to the audit trail by calling `persist_event` itself, because they do not pass through the middleware's `on_event`. From SEN-22 the installer gives every detector the same audit sink.
