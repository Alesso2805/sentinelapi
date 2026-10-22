# ADR-0009: Deploy the demo on one server, behind Caddy, on one hostname

- **Status:** Accepted on 2026-10-22
- **Date:** 2026-10-22
- **Related:** Willay's ADR-0010 and VeriLedger's ADR-0005 (the same decision); ADR-0004; SEN-29, SEN-33, SEN-34

## Context

The portfolio lists SentinelAPI without a demo link (work-portfolio README › Pending). The demo stack is small: the API, Redis and Postgres. Willay and VeriLedger already run on one server each, behind Caddy, with a free DuckDNS hostname and Let's Encrypt certificates.

## Options

1. **A platform as a service** (Render, Railway, Fly.io). Redis and Postgres are paid add-ons on most of them, for a demo that needs a few hundred megabytes.
2. **Share VeriLedger's server:** one more Compose project, and one more site in its Caddy. No new server, but the two demos share a machine and an outage.
3. **A server of its own,** set up as Willay's runbook describes.

## Decision

Options 2 or 3, decided by the product owner when SEN-33 starts, with the same shape either way:

- `deploy/docker-compose.prod.yml` on top of `docker-compose.yml`, removing every published port except Caddy's (SEN-29).
- Caddy terminates HTTPS and routes the hostname (for example `sentinelapi.duckdns.org`) to the demo app.
- `SENTINEL_TRUSTED_PROXIES` covers the private ranges Docker networks use. The API publishes no port, so only containers on the stack's own network reach it, which means Caddy; a fixed subnet for that network collided with other Docker networks in the first rehearsal (SEN-29). Without trusting Caddy, every visitor would arrive from its address and share one rate-limit bucket (ADR-0004).
- `SENTINEL_ENV=production` and `SENTINEL_DEMO_MODE=true`, with secrets in the server's `.env` only.

## Consequences

- The deploy runbook (SEN-34) is written by following it from scratch, as Willay's and VeriLedger's were.
- On a shared server, the SentinelAPI stack's memory is measured before it goes up, and each demo keeps its own Compose project, network and volumes.
- The deployed demo is a public target by definition: it waits for E2 (detectors that hold) and SEN-24 and SEN-26 (a private audit trail).
