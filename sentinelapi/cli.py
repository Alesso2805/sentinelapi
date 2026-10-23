from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinelapi.audit import migrate, retention
from sentinelapi.config import SentinelSettings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="SentinelAPI's maintenance commands.")
    commands = parser.add_subparsers(dest="command", required=True)

    up = commands.add_parser("migrate", help="create or upgrade the audit table")
    up.add_argument("--database-url", help="defaults to SENTINEL_DATABASE_URL")
    up.add_argument(
        "--app-role",
        help="Postgres role the app connects as; it gets INSERT and SELECT only"
        " (default: SENTINEL_AUDIT_APP_ROLE)",
    )
    up.add_argument("--revision", default="head")

    purge = commands.add_parser(
        "purge", help="delete events older than the retention period (run as the owner)"
    )
    purge.add_argument("--database-url", help="defaults to SENTINEL_DATABASE_URL")
    purge.add_argument("--older-than-days", type=int, help="defaults to SENTINEL_AUDIT_RETENTION_DAYS")

    args = parser.parse_args(argv)
    settings = SentinelSettings()
    database_url = args.database_url or settings.database_url
    if args.command == "purge":
        days = args.older_than_days if args.older_than_days is not None else settings.audit_retention_days
        deleted = asyncio.run(retention.purge(database_url, days))
        print(f"deleted {deleted} events older than {days} days")
        return 0
    asyncio.run(
        migrate.upgrade(database_url, args.revision, app_role=args.app_role or settings.audit_app_role)
    )
    print(f"SentinelAPI audit table at revision {asyncio.run(migrate.current(database_url))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
