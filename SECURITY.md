# Security policy

SentinelAPI is a portfolio project, still before 1.0.0, and it is not meant for production yet: the weaknesses it is known to have are listed in the README's [Known limitations](README.md#known-limitations) and planned in the [backlog](docs/BACKLOG.md). Even so, if you find a vulnerability that is not on that list, please report it privately rather than in a public issue or pull request.

## How to report

Use GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a vulnerability**. Say what you found, how to reproduce it and what an attacker could do with it.

You will get an answer within a week. Fixes go to `main`.

## In scope

- A way past a detector that the Known limitations do not already list: requests over a limit that are never counted, failed logins that are never counted, a single-use token accepted twice.
- A crafted request (a header, a token, a path) that makes the middleware crash, hang or let the request through unchecked.
- Blocking someone else's legitimate traffic in a way the configuration does not explain.
- Personal data or token material reaching the audit trail or the logs beyond what the Known limitations list.
- Secrets in the repository or its history.

## Out of scope

- The limitations already listed in the README: they are known, and each one is a story in the backlog.
- The demo app's user and password, and its SHA-256 password hashing: public and demo-only on purpose, as its code says.
- Denial of service by volume: a middleware runs after the connection is accepted.
- Reports from automated scanners without a way to exploit the finding.

Please do not access data that is not yours.
