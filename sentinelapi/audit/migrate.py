"""SentinelAPI's migrations, run against an async database URL.

Alembic's commands are synchronous; each runs here on a connection of an
async engine, so the same code serves `sentinel migrate`, an app's own
startup and the tests, which already run inside an event loop.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelapi.audit.migrations import VERSION_TABLE

MIGRATIONS = Path(__file__).parent / "migrations"


def _config(connection: Connection, app_role: str | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.attributes["connection"] = connection
    config.attributes["app_role"] = app_role
    return config


async def _run(database_url: str, step: Callable[[Connection], object]) -> object:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            return await connection.run_sync(step)
    finally:
        await engine.dispose()


async def upgrade(database_url: str, revision: str = "head", *, app_role: str | None = None) -> None:
    await _run(database_url, lambda c: command.upgrade(_config(c, app_role), revision))


async def downgrade(database_url: str, revision: str = "base") -> None:
    await _run(database_url, lambda c: command.downgrade(_config(c), revision))


async def check(database_url: str) -> None:
    """Raises if the models and the migrated schema differ (AR-11)."""
    await _run(database_url, lambda c: command.check(_config(c)))


def head() -> str | None:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    return ScriptDirectory.from_config(config).get_current_head()


async def current(database_url: str) -> str | None:
    def revision(connection: Connection) -> str | None:
        return MigrationContext.configure(
            connection, opts={"version_table": VERSION_TABLE}
        ).get_current_revision()

    result = await _run(database_url, revision)
    return result if isinstance(result, str) else None
