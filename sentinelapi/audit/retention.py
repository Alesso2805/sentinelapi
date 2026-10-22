"""How long the audit trail keeps rows (ADR-0006).

Run as the table's owner: the app's role cannot delete (AR-12), which is
the point of an append-only trail.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelapi.audit.models import SecurityEventLog
from sentinelapi.clock import SYSTEM_CLOCK, Clock


async def purge(database_url: str, older_than_days: int, *, clock: Clock = SYSTEM_CLOCK) -> int:
    """Deletes the rows that occurred more than `older_than_days` ago; returns how many."""
    cutoff = datetime.fromtimestamp(clock.now(), tz=UTC) - timedelta(days=older_than_days)
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                delete(SecurityEventLog).where(SecurityEventLog.occurred_at < cutoff)
            )
            return result.rowcount
    finally:
        await engine.dispose()
