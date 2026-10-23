# ADR-0010: The public demo is an attack console served by the demo app

- **Status:** Accepted on 2026-10-22
- **Date:** 2026-10-22
- **Related:** README › Roadmap ("small React dashboard over /security/events"); ADR-0004; ADR-0009; SEN-32, SEN-41

## Context

A visitor who opens the demo today sees JSON. The interesting attacks are also hard to reproduce from a browser: credential stuffing needs many source addresses, and every request from one browser comes from one address. The demo must not let the client choose its address with a header (ADR-0004), so the browser cannot simulate sources itself.

The README's roadmap asks for a small React dashboard. The portfolio labels SentinelAPI as a Python project.

## Options

1. **A React single-page app** in its own repository, as VeriLedger's webapp. A second toolchain and a second CI for one page.
2. **A page rendered by the demo app** (Jinja2 templates, HTMX, server-sent events). No build step; one image; stays Python.
3. **No page:** Swagger UI and `curl` recipes in the README. Nothing for a visitor to see.

## Decision

Option 2, an "attack console":

- **Three scenarios,** each a button: a burst of requests, credential stuffing from 20 simulated addresses, and a refresh-token replay.
- **Run server-side.** `POST /demo/scenarios/{name}` drives the real detectors with synthetic sources taken from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- **Live and private.** The page shows each request's verdict and the resulting audit events as they happen, over server-sent events. A console session id (a cookie) tags every event, and the stream shows only the visitor's own.
- **Only in demo mode,** with its own limits: the routes exist only with `SENTINEL_DEMO_MODE=true`, and each address may run 10 scenarios per hour.
- **Accessible:** usable with the keyboard, with no serious or critical axe-core violation.

## Consequences

- **As built (SEN-32):** a static page and about 100 lines of plain JavaScript, not Jinja2 and HTMX. Nothing on the page is rendered per visitor, so no template engine is needed, and a security demo carries no third-party script; its Content Security Policy allows only its own origin. Each run gets `Sentinel.sandbox()`: fresh detectors with the app's settings on a memory backend of their own, built by the installer (AR-18), so two visitors never interfere and every run starts the same way.
- The README's "React dashboard" item is replaced by this console. If a richer dashboard is wanted later, it reads the same events API (SEN-26).
- The scenarios exercise the real detectors and the real audit sink, so the console doubles as an end-to-end test of the deployed stack.
- Spanish and English, as the other portfolio demos have, is a Could (SEN-41). Built after 1.0.0: the server sends every text in both languages, so the page switches at once and keeps no visitor's language on the server. The detectors' messages stay English in the log and the audit trail; the console shows them translated.
