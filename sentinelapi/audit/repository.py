from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelapi.audit.models import SecurityEventLog
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.privacy import Pseudonymizer


@dataclass
class EventGroup:
    """Identical events folded into one row: the first one, how many there
    were, and when the last one happened (ADR-0006)."""

    first: SecurityEvent
    count: int
    last_occurred_at: float


def _utc(epoch_seconds: float) -> datetime:
    return datetime.fromtimestamp(epoch_seconds, tz=UTC)


class SecurityEventRepository:
    def __init__(self, session: AsyncSession, pseudonymize: Pseudonymizer) -> None:
        self._session = session
        self._pseudonymize = pseudonymize

    async def add(self, event: SecurityEvent) -> None:
        await self.add_groups([EventGroup(event, 1, event.occurred_at)])

    async def add_groups(self, groups: Iterable[EventGroup]) -> None:
        """One transaction for the whole batch."""
        for group in groups:
            event = group.first
            self._session.add(
                SecurityEventLog(
                    threat_type=event.threat_type.value,
                    threat_level=event.threat_level.value,
                    fingerprint_key=self._pseudonymize(event.fingerprint.key),
                    client_hash=self._pseudonymize(event.fingerprint.ip),
                    subject_hash=self._pseudonymize(event.subject),
                    path=event.path,
                    detail=event.detail,
                    occurred_at=_utc(event.occurred_at),
                    last_occurred_at=_utc(group.last_occurred_at),
                    count=group.count,
                )
            )
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
