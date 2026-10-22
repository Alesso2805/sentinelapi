"""Where events go to be kept: the audit table."""

from __future__ import annotations

from sentinelapi.audit import migrate
from sentinelapi.audit.db import create_engine_and_sessionmaker, session_scope
from sentinelapi.audit.models import SecurityEventLog
from sentinelapi.audit.repository import SecurityEventRepository
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.logging_config import security_logger
from sentinelapi.privacy import Pseudonymizer


class DatabaseAuditSink:
    def __init__(self, database_url: str, pseudonymize: Pseudonymizer) -> None:
        self._database_url = database_url
        self._pseudonymize = pseudonymize
        self._engine, self._sessions = create_engine_and_sessionmaker(database_url)

    async def start(self) -> None:
        """The table comes from migrations (ADR-0006), never from startup.
        If they have not run, say so once, clearly; writes fail and are
        logged, but requests are never refused for it."""
        try:
            current = await migrate.current(self._database_url)
        except Exception:
            current = None
        if current != migrate.head():
            await security_logger.aerror(
                "audit_table_not_migrated",
                current=current,
                head=migrate.head(),
                hint="run `sentinel migrate` against SENTINEL_DATABASE_URL",
            )

    async def __call__(self, event: SecurityEvent) -> None:
        async with session_scope(self._sessions) as session:
            await SecurityEventRepository(session, self._pseudonymize).add(event)

    async def recent_critical(self, limit: int = 50) -> list[SecurityEventLog]:
        async with session_scope(self._sessions) as session:
            return await SecurityEventRepository(session, self._pseudonymize).recent_critical(limit=limit)

    async def close(self) -> None:
        await self._engine.dispose()
