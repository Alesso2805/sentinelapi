# Architecture Decision Records

One technical decision per file: context, options, decision and consequences. Any decision not covered by [SPEC.md](../SPEC.md) is recorded here with the next free number (`NNNN-title.md`).

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-framework-agnostic-detectors.md) | Framework-agnostic detectors behind one storage port | Accepted (retroactive) |
| [0002](0002-fixed-window-counters.md) | Fixed-window counters, with one semantics in every backend | Accepted (retroactive) |
| [0003](0003-brute-force-called-by-the-login.md) | Brute-force detection is called by the login endpoint, not by the middleware | Accepted (retroactive) |
| [0004](0004-client-identity-behind-proxies.md) | Identify clients by address, through trusted proxies | Accepted |
| [0005](0005-what-a-brute-force-block-means.md) | A brute-force block is checked before the password and holds until its window ends | Accepted |
| [0006](0006-audit-trail.md) | The audit trail: its own migrations, keyed hashes instead of personal data, writes off the request path | Accepted |
| [0007](0007-pure-asgi-middleware-and-installer.md) | A pure ASGI middleware, installed by one call | Accepted |
| [0008](0008-distribution.md) | A typed library on PyPI; the demo stays out of the package | Accepted |
| [0009](0009-deploy-on-one-server-behind-caddy.md) | Deploy the demo on one server, behind Caddy, on one hostname | Accepted |
| [0010](0010-attack-console.md) | The public demo is an attack console served by the demo app | Accepted |

Statuses: Proposed → Accepted → (Superseded by ADR-NNNN | Deprecated). "Retroactive" means the decision was taken in code on August 31, 2026 and written down on October 22, 2026.
