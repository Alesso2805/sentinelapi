# Back up and restore the audit database

The audit trail lives in Postgres; the counters in Redis are short-lived by design and are not backed up. `deploy/backup.sh` and `deploy/restore.sh` wrap `pg_dump` and `pg_restore`; run them from the repository root (on the server, `.env`'s `COMPOSE_FILE` makes them use the production stack).

CI's "Full stack from an empty database" job checks the whole cycle on every pull request: it backs up, empties the table, restores, finds the rows again, and checks the app's role is still refused a DELETE.

## Back up

```bash
sh deploy/backup.sh
```

It writes `backups/sentinelapi-<UTC time>.dump`, a compressed `pg_dump --format=custom` taken as the owner, and prints its size; an empty dump is an error. Give a path as the first argument to write it elsewhere. `backups/` is ignored by git.

A backup on the same disk does not survive the disk: copy the dumps to another machine as well (`rclone`, `scp`). Back up before every update ([deploy.md](deploy.md), step 6): the migrations only go forward.

## Restore

```bash
sh deploy/restore.sh backups/sentinelapi-20261023T030000Z.dump
```

1. It stops the API, so nothing writes while the data is replaced. Events reported meanwhile are still in the log; the audit rows of that minute are lost.
2. It runs `pg_restore --clean --if-exists --no-owner` as the owner, which drops what the dump holds and recreates it, the grants included: the app's role is again limited to INSERT and SELECT.
3. It starts the API.

Then check:

```bash
SENTINEL_OPERATOR_TOKEN=... sh deploy/verify.sh https://sentinelaapi.duckdns.org
```

## After a restore

- Everything after the dump is gone from the table; the log lines of that period are not.
- The keyed hashes still correlate if `SENTINEL_AUDIT_HASH_KEY` is the one in use when the dump was taken ([rotate-secrets.md](rotate-secrets.md)).
- To roll back an update, restore the dump taken before it, then start the older commit ([deploy.md](deploy.md), step 7).
