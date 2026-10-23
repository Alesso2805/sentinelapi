# Deploy SentinelAPI's demo on a server

This runbook puts the demo, the attack console included, on a public server with HTTPS (SEN-33, ADR-0009). It follows the same shape as Willay's and VeriLedger's deployments: one server, Docker Compose, Caddy, one hostname, a free DuckDNS name.

| Path | What |
| --- | --- |
| `/` | the attack console |
| `/health`, `/ready` | liveness and readiness |
| `/auth/…`, `/me` | the demo's own login, for trying the guard by hand |
| `/security/events` | the audit trail, for whoever holds `SENTINEL_OPERATOR_TOKEN` |

The stack needs about 0.5 GB of memory and 2 GB of disk: the API, Redis and Postgres, with Caddy in front.

## 1. The server and the hostname

Two ways (ADR-0009):

- **A server of its own:** any Linux machine with Docker (Willay's runbook covers an Oracle Cloud Always Free server step by step). Ports 80 and 443 open to the internet.
- **VeriLedger's server:** no new machine, but its Caddy already holds ports 80 and 443; see [On a server that already runs Caddy](#on-a-server-that-already-runs-caddy).

Point a hostname at the server's public address, for example `sentinelapi.duckdns.org` at [duckdns.org](https://www.duckdns.org).

## 2. The code and the secrets

```bash
sudo mkdir -p /srv/sentinelapi && sudo chown "$USER" /srv/sentinelapi
git clone https://github.com/Alesso2805/sentinelapi /srv/sentinelapi
cd /srv/sentinelapi
cat > .env <<EOF
# Both compose files for every command run here, scripts included.
COMPOSE_FILE=docker-compose.yml:deploy/docker-compose.prod.yml
SENTINEL_HOSTNAME=sentinelapi.duckdns.org
SENTINEL_JWT_SECRET=$(openssl rand -hex 32)
SENTINEL_AUDIT_HASH_KEY=$(openssl rand -hex 32)
SENTINEL_OPERATOR_TOKEN=$(openssl rand -hex 24)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
SENTINEL_APP_DB_PASSWORD=$(openssl rand -hex 24)
# Optional: a Slack-compatible webhook for CRITICAL events
# SENTINEL_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
EOF
chmod 600 .env
```

`.env` is ignored by git and holds every secret of the server; keep a copy where the server's disk is not ([rotate-secrets.md](rotate-secrets.md) says what each one does). Production refuses to start with an example secret or a short one, naming each problem (`SENTINEL_ENV=production`, set by the overlay).

## 3. Start

```bash
docker compose up -d --build --wait
```

In order: Postgres creates the `sentinel_app` role on its first start; `migrate` creates the audit table as the owner, grants `sentinel_app` INSERT and SELECT only, and exits; the API starts and connects as `sentinel_app`; Caddy gets the certificate from Let's Encrypt on the first request to the hostname. Only Caddy publishes ports.

## 4. Check it

```bash
SENTINEL_OPERATOR_TOKEN=$(grep ^SENTINEL_OPERATOR_TOKEN .env | cut -d= -f2) \
  sh deploy/verify.sh https://sentinelapi.duckdns.org
```

It asks `/health`, `/ready` (Redis up, the schema migrated, as the app's role sees it) and the operator's events. Then open `https://sentinelapi.duckdns.org/` and run each attack once.

Behind Caddy every request arrives from Caddy's address; the API believes Caddy's `X-Forwarded-For` (the overlay trusts the private ranges, which only the stack's own network can come from), so the console's limits apply to each visitor, not to everyone at once.

## 5. Backups

Every night, as [backup-and-restore.md](backup-and-restore.md) describes:

```cron
0 3 * * * cd /srv/sentinelapi && sh deploy/backup.sh && find backups -name 'sentinelapi-*.dump' -mtime +14 -delete
```

And the retention period, as the owner, every week:

```cron
0 4 * * 0 cd /srv/sentinelapi && docker compose run --rm migrate sentinel purge
```

## 6. Update

```bash
cd /srv/sentinelapi
sh deploy/backup.sh                 # migrations only go forward: keep the way back
git pull
docker compose up -d --build --wait  # migrate runs again before the new API starts
sh deploy/verify.sh https://sentinelapi.duckdns.org
```

## 7. Roll back

Restore the dump taken before the update, then check out the previous commit and start it:

```bash
git checkout <previous commit>
sh deploy/restore.sh backups/sentinelapi-<time of the update>.dump
docker compose up -d --build --wait
```

## On a server that already runs Caddy

VeriLedger's server already runs a Caddy on ports 80 and 443. Start SentinelAPI without its own, and let that Caddy reach SentinelAPI's API over SentinelAPI's network:

```bash
docker compose up -d --build --wait --scale caddy=0
docker network connect sentinelapi_default <the other stack's Caddy container>
```

Add a site to that Caddy's Caddyfile, and reload it:

```caddyfile
sentinelapi.duckdns.org {
	encode zstd gzip
	header -Server
	reverse_proxy sentinelapi-api-1:8000
}
```

The container name, not the service name: both stacks have a service called `api`. The network connection is lost if that Caddy container is recreated; connect it again after updating the other stack.

## Rehearse on a laptop

With `SENTINEL_HOSTNAME=localhost`, Caddy serves HTTPS with its own certificate authority, and `HTTP_PORT` and `HTTPS_PORT` move it off ports already in use:

```bash
SENTINEL_HOSTNAME=localhost HTTP_PORT=18080 HTTPS_PORT=18443 docker compose up -d --build --wait
curl -k https://localhost:18443/ready
```
