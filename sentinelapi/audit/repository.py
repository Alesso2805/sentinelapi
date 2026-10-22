from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelapi.audit.models import SecurityEventLog
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.privacy import Pseudonymizer


class SecurityEventRepository:
    def __init__(self, session: AsyncSession, pseudonymize: Pseudonymizer) -> None:
        self._session = session
        self._pseudonymize = pseudonymize

    async def add(self, event: SecurityEvent) -> None:
        row = SecurityEventLog(
            threat_type=event.threat_type.value,
            threat_level=event.threat_level.value,
            fingerprint_key=self._pseudonymize(event.fingerprint.key),
            client_hash=self._pseudonymize(event.fingerprint.ip),
            subject_hash=self._pseudonymize(event.subject),
            path=event.path,
            detail=event.detail,
            occurred_at=datetime.fromtimestamp(event.occurred_at, tz=UTC),
        )
        self._session.add(row)
        await self._session.commit()

    async def recent_critical(self, limit: int = 100) -> list[SecurityEventLog]:
        stmt = (
            select(SecurityEventLog)
            .where(SecurityEventLog.threat_level.in_(["high", "critical"]))
            .order_by(SecurityEventLog.occurred_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
