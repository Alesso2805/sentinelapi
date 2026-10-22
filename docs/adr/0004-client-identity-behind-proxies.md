# ADR-0004: Identify clients by address, through trusted proxies

- **Status:** Accepted on 2026-10-22
- **Date:** 2026-10-22
- **Related:** SPEC.md › Detection contract › Identity of a request; AUDIT.md probes 3 and 9; SEN-18, SEN-19; ADR-0009

## Context

As built, every counter is keyed on a fingerprint: a hash of `request.client.host` and the `User-Agent`. Two problems, both seen in the audit:

- **The User-Agent is chosen by the client.** 500 requests from one address, each with a new User-Agent, raised no event at all.
- **Behind a proxy, `request.client.host` is the proxy.** In the live pass every request came from the Docker gateway. Deployed behind Caddy (ADR-0009), every visitor would share one address and one bucket: one abusive visitor would block everyone.

`X-Forwarded-For` carries the real address, but any client can send that header too.

## Options

1. **Keep the fingerprint as the key.** Evaded by changing one header.
2. **Always believe `X-Forwarded-For`.** Evaded by sending a different forged address with every request.
3. **Believe `X-Forwarded-For` only from trusted proxies:** take the right-most hop that is not a trusted proxy, and only when the direct peer is one.
4. **Leave it to the server** (uvicorn's `--forwarded-allow-ips`). It works with uvicorn only, and SentinelAPI could not test it or warn when it is missing.

## Decision

Option 3, inside the library:

- `SENTINEL_TRUSTED_PROXIES`, a list of CIDRs, empty by default. Empty means "no proxy": the direct peer is the client and the header is ignored.
- The client address is the right-most `X-Forwarded-For` hop that is not in that list, walking from the right. A header from an untrusted peer is ignored.
- Limit keys use the client address. IPv6 addresses are grouped by /64, since one host usually owns a whole /64.
- The fingerprint (address, User-Agent, user id) stays, to correlate events in the audit trail. It is never a limit key.

## Consequences

- Clients behind one NAT (an office, a mobile carrier) share a bucket. Limits must be sized for that, and the README says so; stricter limits go on sensitive prefixes such as `/auth/` (SEN-18) rather than everywhere.
- A wrong `SENTINEL_TRUSTED_PROXIES` either puts everyone in one bucket or lets clients spoof addresses. The deploy runbook (SEN-34) sets it to Caddy's network, and `/ready` (SEN-30) could warn when requests carry `X-Forwarded-For` but no proxy is trusted.
- An authenticated user id could be a second key; that is not part of this plan.
