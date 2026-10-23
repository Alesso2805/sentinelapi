# Security policy

SentinelAPI is a portfolio project. No way around its detectors is known; the costs of its design are listed in the README's [Known limitations](README.md#known-limitations). If you find a vulnerability, please report it privately rather than in a public issue or pull request.

## How to report

Use GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a vulnerability**. Say what you found, how to reproduce it and what an attacker could do with it.

You will get an answer within a week. Fixes go to `main`.

## In scope

- A way past a detector that the Known limitations do not already explain: requests over a limit that are never counted, failed logins that are never counted, a single-use token accepted twice.
- A crafted request (a header, a token, a path) that makes the middleware crash, hang or let the request through unchecked.
- Blocking someone else's legitimate traffic in a way the configuration does not explain.
- Personal data or token material reaching the audit trail, the logs or the alerts.
- Secrets in the repository or its history.

## Out of scope

- The trade-offs listed in the README's Known limitations: they are design decisions, each with its record in `docs/adr/`.
- The demo app's user and password, and its SHA-256 password hashing: public and demo-only on purpose, as its code says.
- Denial of service by volume: a middleware runs after the connection is accepted.
- Reports from automated scanners without a way to exploit the finding.

Please do not access data that is not yours.
