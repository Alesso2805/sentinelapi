# Sprint 2 — Detectors that hold: the same windows everywhere, limits that mean what they say, no cheap evasion (SEN-17 to SEN-21)

**Status as of 2026-10-22:** started right after Sprint 1, with no calendar. 19 points.

**Order:** SEN-17 (its contract suite and injectable clock are what the rest stand on), SEN-19, SEN-18, SEN-20, SEN-21.

**Rule for every story:** each evasion of the audit (README › Known limitations) is first written as a test that fails, then made to pass, and its line leaves the README in the same PR.

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-17 | #10 | `sentinelapi/clock.py` (AR-16): detectors and the memory backend receive a `Clock`; `SecurityEvent.occurred_at` comes from it. The memory backend opens a window on the first hit and never extends it, sweeps expired keys at most once a second, and past `max_keys` drops the tenth closest to expiring, so a flood of new keys pays one sweep per batch | The contract suite's fixed-window test passes on both backends (its xfail is gone); new tests for probe 1 (600 requests, one every 2 s against 60 per 60 s: no event) and probe 6 (10,000 expired keys evicted), and for the key cap. 79 passed, 9 xfailed |
| SEN-19 | — | — | — |
| SEN-18 | — | — | — |
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
