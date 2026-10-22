# ADR-0001: Framework-agnostic detectors behind one storage port

- **Status:** Accepted (retroactive)
- **Date:** 2026-08-31, written down on 2026-10-22
- **Related:** SPEC.md › Architecture; ARCHITECTURE_RULES.md AR-01 to AR-05; README › Architecture

## Context

SentinelAPI is meant to be dropped into someone else's app, and its value is that its verdicts are right. The project was first built in a sandbox with no network, where neither FastAPI, Redis nor a database could be installed, so the detection logic had to be testable with nothing but the standard library. Counting also has two very different deployments: one process (tests, a laptop) and several workers or replicas, where counts must be shared.

## Options

1. **One security module inside a FastAPI middleware**, talking to Redis directly. Least code, but every rule would be tested through HTTP and a running Redis.
2. **Detectors as plain classes behind a storage protocol,** with a thin adapter for the framework.
3. **An external service** (a sidecar or gateway plugin). It would protect any framework, but adds a network hop and a deployment, and cannot see whether a login succeeded.

## Decision

Option 2.

- `domain` holds the vocabulary: `ThreatType`, `ThreatLevel`, `RequestFingerprint` and `SecurityEvent`, frozen dataclasses with no dependencies.
- `detectors` decide. Each returns a `SecurityEvent` or `None` and never touches HTTP.
- `storage/backend.py` defines `CounterBackend` as a `typing.Protocol` with four async methods: `incr_with_expiry`, `get`, `set_if_absent`, `reset`. `InMemoryBackend` and `RedisBackend` implement it.
- `middleware.py` translates: a Starlette request into a fingerprint, a verdict into a response and an `on_event` call.
- `audit` stores events; nothing in the detectors depends on it.

## Consequences

- The detectors' 15 unit tests run with no service at all.
- Switching from one process to Redis is a setting, with no detector change, as long as both backends behave the same. Today they do not (ADR-0002, SEN-17), which is why AR-07 adds a contract suite.
- Wiring is left to the app: the demo builds every piece by hand in `main.py`. SEN-22's installer (ADR-0007) gives integrators one call.
- A `Protocol` checks shape, not behavior. Only the contract suite of SEN-17 makes "the detectors don't care which backend" true.
