# Roll SentinelAPI out in an existing app

A detector that blocks a real user is worse than none, so SentinelAPI starts by watching. This is the order that keeps every step reversible.

## 1. Install it in shadow mode

```python
sentinel = install_sentinel(app)  # README › Use it in your app
```

with `SENTINEL_ENFORCE=false`. Every verdict is logged and written to the audit trail, and nothing is blocked: the login guard and the middleware let every request through.

Before the first deploy:

- `sentinel migrate` against `SENTINEL_DATABASE_URL`, with `--app-role` set to the role your app connects as on Postgres.
- `SENTINEL_TRUSTED_PROXIES` set to your load balancer's or reverse proxy's addresses. Without it, every client arrives from the proxy and shares one limit; with it wrong, clients can choose their address. Check one request's `client_hash` in the audit trail against another client's: they must differ.
- `SENTINEL_BACKEND=redis` if the app runs more than one process.
- `SENTINEL_AUDIT_HASH_KEY` and `SENTINEL_ENV=production`: production refuses to start without its secrets, naming each one.

## 2. Read a week of verdicts

Look at the HIGH and CRITICAL events, the ones enforcement would block:

- the `security_event` log lines, each with its `request_id` (the response's `X-Request-ID`), or
- the audit table: one row per source, threat and minute, with a `count`.

For each source that would have been blocked, decide whether it was an attacker or a client of yours. Common false positives:

- a partner or a batch job above `SENTINEL_RATE_LIMIT_MAX_REQUESTS`: raise the limit, or give its paths a prefix limit of their own;
- many users behind one office or mobile NAT sharing one address: size the per-client limit for them, and keep the stricter limits for sensitive prefixes such as `/auth/` (`SENTINEL_RATE_LIMIT_PATHS`);
- health checks: `SENTINEL_RATE_LIMIT_EXEMPT_PATHS`, which exempts `/health` and `/ready` by default.

## 3. Enforce

Set `SENTINEL_ENFORCE=true`. From then on:

- a client over its limit gets 429 with `Retry-After`;
- a blocked source or a locked account gets 429 from the login guard, the right password included, until its window ends;
- a replayed single-use token gets 403.

Watch the 429 and 403 rates for a day. To undo, set `SENTINEL_ENFORCE=false` again: nothing else changes.

## 4. Alert

Set `SENTINEL_ALERT_WEBHOOK_URL` to a chat webhook. Only CRITICAL events reach it, a replayed token or an account locked many times over, one message per source and threat every 10 minutes.

## The account lock

With `SENTINEL_BRUTE_FORCE_ACCOUNT_ACTION=lock` (the default), an account that fails 8 times in 15 minutes from any number of sources is refused from every source until its window ends: anyone who knows a username can keep its owner out for that long. If your app has its own challenge (a CAPTCHA, MFA), set it to `signal`: the account is never locked, and `await sentinel.login_guard.check(request, username)` returns a verdict whose `challenge_required` tells your login to ask for the challenge (ADR-0005).
