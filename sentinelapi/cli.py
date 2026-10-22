"""The `sentinel` command: `sentinel migrate` creates or upgrades the audit table."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sentinelapi.audit import migrate
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

    args = parser.parse_args(argv)
    settings = SentinelSettings()
    database_url = args.database_url or settings.database_url
    asyncio.run(
        migrate.upgrade(database_url, args.revision, app_role=args.app_role or settings.audit_app_role)
    )
    print(f"SentinelAPI audit table at revision {asyncio.run(migrate.current(database_url))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
