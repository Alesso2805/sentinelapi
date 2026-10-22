"""Where events go to be kept: the audit table."""

from __future__ import annotations

from sentinelapi.audit.db import create_engine_and_sessionmaker, init_models, session_scope
from sentinelapi.audit.models import SecurityEventLog
from sentinelapi.audit.repository import SecurityEventRepository
from sentinelapi.domain.entities import SecurityEvent


class DatabaseAuditSink:
    def __init__(self, database_url: str) -> None:
        self._engine, self._sessions = create_engine_and_sessionmaker(database_url)

    async def start(self) -> None:
        await init_models(self._engine)

    async def __call__(self, event: SecurityEvent) -> None:
        async with session_scope(self._sessions) as session:
            await SecurityEventRepository(session).add(event)

    async def recent_critical(self, limit: int = 50) -> list[SecurityEventLog]:
        async with session_scope(self._sessions) as session:
            return await SecurityEventRepository(session).recent_critical(limit=limit)

    async def close(self) -> None:
        await self._engine.dispose()
