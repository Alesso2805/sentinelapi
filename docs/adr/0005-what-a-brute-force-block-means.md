# ADR-0005: A brute-force block is checked before the password and holds until its window ends

- **Status:** Accepted on 2026-10-22
- **Date:** 2026-10-22
- **Related:** ADR-0003; SPEC.md › Detection contract › Verdicts; AUDIT.md probes 4, 5 and 7; SEN-20

## Context

As built, the detector only records failures. After a "block", a wrong password gets 403 instead of 401, and the right one still gets tokens (probe 7). Two more evasions:

- **Case:** the account counter uses the username as typed, so `bob@`, `Bob@`, `BOB@` and `bob@Example` count apart (probe 4).
- **The victim's own login** clears the account counter, erasing failures that came from other sources (probe 5).

There are two axes, and a block means something different on each:

- **Source axis** (one address failing many times): the source is the attacker. Refusing it costs nobody else anything.
- **Account axis** (many sources failing against one account): the account is the victim. Refusing it locks the real owner out, which an attacker can do on purpose (an account-lockout denial of service).

## Options

1. **Lock both axes** for the window. Simple, and it stops stuffing, at the price of letting anyone lock any known username out for 15 minutes.
2. **Lock the source; on the account axis, return a "challenge required" verdict** for the app to act on (CAPTCHA, MFA, an email link). SentinelAPI has none of those (out of scope), so in the demo nothing would visibly happen.
3. **Lock the source; lock the account only for sources that never logged into it successfully** (a device seen on a recent success keeps working). The fairest, and the most state to keep.
4. **Progressive delay** instead of a block. It slows a distributed attack little, since each source waits on its own.

## Decision

- **Source axis:** a hard block. `BruteForceDetector.check(client, username)` runs **before** the password is verified; a blocked source gets 429 with `Retry-After` until its window ends, right password or not.
- **Account axis:** a setting, `SENTINEL_BRUTE_FORCE_ACCOUNT_ACTION`:
  - `lock` (default): option 1, time-boxed to the window, with the trade-off in the README;
  - `signal`: option 2, for apps that have their own challenge.
- **Usernames are normalized** before counting (trim and casefold), with the normalizer replaceable for apps whose usernames are case-sensitive.
- **A success clears only its own source's counters,** never failures recorded from other sources.
- **The response does not help the attacker:** the same 429 and body whether the account exists or not, with no count and no username.

## Consequences

- With `lock`, an attacker who knows a username can keep its owner out by failing 8 times every 15 minutes. That is the price of stopping stuffing without a challenge; option 3 can replace it later without changing the detector's interface.
- The login code changes from "verify, then record" to "check, verify, record". The README's login snippet and the demo change with SEN-20.
- Each rule gets a test, including the cases the audit found: one source against many accounts (untested today), case variants, the victim's success, and the right password after a block.
