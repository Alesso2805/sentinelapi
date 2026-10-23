# Rotate the secrets

Every secret of a server is in its `.env` ([deploy.md](deploy.md), step 2). Rotate one when it may have been seen by someone it was not meant for, and as a habit, once a year. After changing `.env`:

```bash
docker compose up -d --wait   # recreates the containers whose settings changed
```

| Secret | What it protects | What a rotation does |
| --- | --- | --- |
| `SENTINEL_JWT_SECRET` | The demo's tokens, and the replay detector's verification of them | Every token issued before is invalid: signed-in users sign in again. In your own app, rotate it together with the key your app signs with: they are the same key |
| `SENTINEL_AUDIT_HASH_KEY` | The keyed hashes standing for addresses, accounts and fingerprints in the audit trail and the log | New events hash differently, so they no longer correlate with older ones: the same address before and after looks like two. Rotate it right after a retention purge, or accept a seam in the trail; keep the old key with the backups made under it if they may need to be read together |
| `SENTINEL_OPERATOR_TOKEN` | The demo's events API | The old token stops working at once; give the new one to whoever reads the events |
| `POSTGRES_PASSWORD` | The owner role, `sentinel` (migrations, purges, backups) | See below: Postgres keeps its own copy |
| `SENTINEL_APP_DB_PASSWORD` | The app's role, `sentinel_app` | See below |
| `SENTINEL_ALERT_WEBHOOK_URL` | The webhook (its URL is its secret) | Make a new incoming webhook in the chat tool, put its URL here, delete the old one |

## The database passwords

Postgres reads `POSTGRES_PASSWORD` and `SENTINEL_APP_DB_PASSWORD` only when its data volume is first created; after that the passwords live in the database. Change them there first, then in `.env`:

```bash
docker compose exec -T postgres psql -U sentinel -d sentinelapi \
  -c "ALTER ROLE sentinel_app PASSWORD 'the new app password'"
docker compose exec -T postgres psql -U sentinel -d sentinelapi \
  -c "ALTER ROLE sentinel PASSWORD 'the new owner password'"
# then the same values in .env, and:
docker compose up -d --wait
```

`docker compose exec` reaches Postgres over its local socket, which does not ask for the old password.
