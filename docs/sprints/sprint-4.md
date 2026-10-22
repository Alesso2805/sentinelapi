# Sprint 4 — A production-ready stack and the attack console (SEN-27 to SEN-32)

**Status as of 2026-10-22:** started right after Sprint 3, with no calendar. 18 points. Since #20 no architecture rule is marked xfail: all 18 hold.

**Order:** SEN-27, SEN-28, SEN-29, SEN-30, SEN-32 (it needs SEN-26's events), SEN-31.

## What was delivered

| Story | PRs | Result | Verification |
| --- | --- | --- | --- |
| SEN-27 | #20 | `SENTINEL_ENV=production` refuses, in one error naming each problem: a JWT secret that is an example value or under 32 bytes, a missing or short `SENTINEL_AUDIT_HASH_KEY`, and the memory backend unless `SENTINEL_ALLOW_MEMORY_BACKEND=true`. `SENTINEL_BACKEND` accepts only `memory` or `redis` in any environment | AR-10 holds, so the last strict xfails are gone. Each unsafe case changes one thing in an otherwise safe production configuration; every problem named at once; the memory backend allowed on purpose; development starts with the defaults; `Redis` (a typo) fails. 177 passed, 0 xfailed |
| SEN-28 | — | — | — |
| SEN-29 | — | — | — |
| SEN-30 | — | — | — |
| SEN-32 | — | — | — |
| SEN-31 | — | — | — |

## Sprint decisions

—

## Changes to the specification in this sprint

—

## Retro

- **Went well:** —
- **To improve:** —
- **To try:** —
