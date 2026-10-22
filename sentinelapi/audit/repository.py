from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelapi.audit.models import SecurityEventLog
from sentinelapi.domain.entities import SecurityEvent


class SecurityEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, event: SecurityEvent) -> None:
        row = SecurityEventLog(
            threat_type=event.threat_type.value,
            threat_level=event.threat_level.value,
            fingerprint_key=event.fingerprint.key,
            ip=event.fingerprint.ip,
            user_id=event.fingerprint.user_id,
            path=event.path,
            detail=event.detail,
            occurred_at=event.occurred_at,
        )
        self._session.add(row)
        await self._session.commit()

    async def recent_for_fingerprint(self, fingerprint_key: str, limit: int = 50) -> list[SecurityEventLog]:
        stmt = (
            select(SecurityEventLog)
            .where(SecurityEventLog.fingerprint_key == fingerprint_key)
            .order_by(SecurityEventLog.occurred_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def recent_critical(self, limit: int = 100) -> list[SecurityEventLog]:
        stmt = (
            select(SecurityEventLog)
            .where(SecurityEventLog.threat_level.in_(["high", "critical"]))
            .order_by(SecurityEventLog.occurred_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
