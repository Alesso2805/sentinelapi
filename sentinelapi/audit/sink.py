"""Where events go to be kept: the audit table, written off the request path.

Writing one row per event inside the request turns an attack into a write
flood on the database, and a database error into a failed request
(ADR-0006). So the sink only folds the event into memory: identical events
(same fingerprint, account, type, level and path) within
SENTINEL_AUDIT_AGGREGATE_SECONDS become one group, and a background task
writes the groups whose window has closed, in batches. Memory is bounded:
past SENTINEL_AUDIT_QUEUE_SIZE groups, new ones are dropped and counted.
Every event is still in the log line, written at once.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

from sentinelapi.audit import migrate
from sentinelapi.audit.db import create_engine_and_sessionmaker, session_scope
from sentinelapi.audit.models import SecurityEventLog
from sentinelapi.audit.repository import EventGroup, SecurityEventRepository
from sentinelapi.clock import SYSTEM_CLOCK, Clock
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.logging_config import security_logger
from sentinelapi.privacy import Pseudonymizer

GroupKey = tuple[str, str | None, str, str, str]

# How often the writer looks for groups whose window has closed.
WRITE_INTERVAL_SECONDS = 1.0


@dataclass
class _Pending:
    group: EventGroup
    opened_at: float  # monotonic, from the sink's clock


class DatabaseAuditSink:
    def __init__(
        self,
        database_url: str,
        pseudonymize: Pseudonymizer,
        *,
        aggregate_seconds: float = 60,
        max_groups: int = 10_000,
        clock: Clock = SYSTEM_CLOCK,
    ) -> None:
        self._database_url = database_url
        self._pseudonymize = pseudonymize
        self._engine, self._sessions = create_engine_and_sessionmaker(database_url)
        self._aggregate_seconds = aggregate_seconds
        self._max_groups = max_groups
        self._clock = clock
        self._pending: dict[GroupKey, _Pending] = {}
        self._dropped = 0
        self._lock = asyncio.Lock()
        self._writer: asyncio.Task[None] | None = None

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
        self._writer = asyncio.create_task(self._write_periodically())

    async def __call__(self, event: SecurityEvent) -> None:
        """Never touches the database: the request goes on at once."""
        key: GroupKey = (
            event.fingerprint.key,
            event.subject,
            event.threat_type.value,
            event.threat_level.value,
            event.path,
        )
        async with self._lock:
            pending = self._pending.get(key)
            if pending is not None:
                pending.group.count += 1
                pending.group.last_occurred_at = event.occurred_at
            elif len(self._pending) < self._max_groups:
                self._pending[key] = _Pending(
                    EventGroup(event, 1, event.occurred_at), self._clock.monotonic()
                )
            else:
                self._dropped += 1

    async def flush(self, *, everything: bool = False) -> None:
        """Writes the groups whose window has closed, or all of them. A
        failed write keeps them for the next attempt, within the bound."""
        async with self._lock:
            now = self._clock.monotonic()
            due = {
                key: pending
                for key, pending in self._pending.items()
                if everything or now - pending.opened_at >= self._aggregate_seconds
            }
            for key in due:
                del self._pending[key]
            dropped, self._dropped = self._dropped, 0
        if dropped:
            await security_logger.aerror("audit_events_dropped", count=dropped, reason="audit queue full")
        if not due:
            return
        try:
            async with session_scope(self._sessions) as session:
                await SecurityEventRepository(session, self._pseudonymize).add_groups(
                    p.group for p in due.values()
                )
        except Exception:
            await security_logger.aexception("audit_write_failed", groups=len(due))
            async with self._lock:
                for key, pending in due.items():
                    if key not in self._pending and len(self._pending) < self._max_groups:
                        self._pending[key] = pending
                    else:
                        self._dropped += pending.group.count

    async def recent_critical(self, limit: int = 50) -> list[SecurityEventLog]:
        async with session_scope(self._sessions) as session:
            return await SecurityEventRepository(session, self._pseudonymize).recent_critical(limit=limit)

    async def close(self) -> None:
        """Stops the writer and drains what is pending before the process ends."""
        if self._writer is not None:
            self._writer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._writer
        await self.flush(everything=True)
        await self._engine.dispose()

    async def _write_periodically(self) -> None:
        while True:
            await asyncio.sleep(WRITE_INTERVAL_SECONDS)
            try:
                await self.flush()
            except Exception:  # never let the writer die; the next tick tries again
                await security_logger.aexception("audit_writer_failed")
