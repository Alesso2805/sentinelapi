# ADR-0006: The audit trail: its own migrations, keyed hashes instead of personal data, writes off the request path

- **Status:** Accepted on 2026-10-22
- **Date:** 2026-10-22
- **Related:** SPEC.md › Data model; ARCHITECTURE_RULES.md AR-11 to AR-13; AUDIT.md probes 8 and 10; SEN-23 to SEN-26

## Context

The audit trail is what a security review reads, so it has to be complete, private and durable. As built, it is none of the three:

- **Schema:** created by `create_all` at startup, with naive timestamps and an epoch float. The README's roadmap already lists Alembic.
- **Privacy:** the raw address and, for brute force, the targeted username are stored, and the demo serves them to anyone.
- **Write path:** one row per event, written inside the request. A burst of 125 requests wrote 67 rows. An attack becomes a write flood, and a database error becomes a 500 on the request that triggered it.

The table also lives in someone else's database, next to their own migrations.

## Options

**Schema ownership**

1. Keep `create_all`. No history, no way to change a column safely.
2. Ask integrators to copy a migration into their own Alembic history. Easy to forget, and it drifts.
3. **Ship an Alembic history in the package, with its own version table** (`sentinel_alembic_version`), run by `sentinel migrate`. It coexists with the app's history.

**What identifies a client and an account**

1. Raw values, with a retention period. Useful, but it is personal data kept by a library that promised not to (`fingerprint.py`).
2. Plain SHA-256 of the address. The IPv4 space is small enough to reverse every hash in minutes.
3. Truncated addresses (/24). Private, but two clients in one /24 look alike.
4. **A keyed hash** (HMAC-SHA256 with `SENTINEL_AUDIT_HASH_KEY`) of the address and of the normalized username. Correlatable, not reversible without the key.

**Write path**

1. Synchronous, as today.
2. One fire-and-forget task per event. Unbounded under an attack.
3. **A bounded queue drained by one background writer in batches,** folding identical events into one row with a count.

## Decision

Option 3, option 4 and option 3:

- The package ships its migrations and `sentinel migrate`; the table stops being created at startup. Timestamps are timestamptz.
- `client_hash` and `subject_hash` replace `ip` and `user_id`; `detail` never contains a username, an address or token material. The security log lines follow the same rule.
- Events are put on a bounded queue (`SENTINEL_AUDIT_QUEUE_SIZE`). Identical events (fingerprint, type, level, path) within `SENTINEL_AUDIT_AGGREGATE_SECONDS` become one row with `count` and `last_occurred_at`. When the queue is full, events are dropped and the number dropped is logged. The queue is drained on shutdown.
- In the demo stack, the app's role may only INSERT and SELECT; retention (`sentinel purge`, `SENTINEL_AUDIT_RETENTION_DAYS`) runs as the owner role.

## Consequences

- The structured log line, written at once for every event, stays the complete record. The table becomes the queryable summary and may lose up to one queue's worth of events if the process dies. The README says so.
- Rotating the hash key breaks correlation across the rotation; `rotate-secrets.md` (SEN-34) says when that is acceptable.
- A request never waits on the database, and an unreachable database never fails a request (SEN-25's test).
- The audit's numbers become checkable: a flood from one source writes at most one row per threat level and aggregation window.
