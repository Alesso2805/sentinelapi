"""The audit trail is written off the request path, folded, bounded (ADR-0006)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import structlog

from examples.demo_app.main import create_app
from sentinelapi.audit.migrate import upgrade
from sentinelapi.audit.sink import DatabaseAuditSink
from sentinelapi.config import SentinelSettings
from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.privacy import Pseudonymizer
from tests.fakes import FakeClock

from .conftest import TEST_JWT_SECRET, ClientFactory

PSEUDONYMIZE = Pseudonymizer("test-audit-hash-key")


def event(level: ThreatLevel = ThreatLevel.HIGH, *, source: str = "203.0.113.7") -> SecurityEvent:
    return SecurityEvent(
        threat_type=ThreatType.RATE_LIMIT_EXCEEDED,
        threat_level=level,
        fingerprint=build_fingerprint(source, "test"),
        path="/api",
        detail="test",
        occurred_at=1_800_000_000.0,
    )


def rows(database: Path) -> list[tuple[str, int]]:
    with sqlite3.connect(database) as db:
        return list(
            db.execute("SELECT threat_level, count FROM sentinel_security_events ORDER BY threat_level")
        )


async def migrated(tmp_path: Path) -> tuple[str, Path]:
    database = tmp_path / "audit.db"
    url = f"sqlite+aiosqlite:///{database.as_posix()}"
    await upgrade(url)
    return url, database


async def test_a_flood_from_one_source_is_one_row_per_level(tmp_path: Path) -> None:
    url, database = await migrated(tmp_path)
    sink = DatabaseAuditSink(url, PSEUDONYMIZE)
    for _ in range(1_000):
        await sink(event())
    await sink(event(ThreatLevel.MEDIUM))
    await sink.close()
    assert rows(database) == [("high", 1_000), ("medium", 1)]


async def test_a_group_is_written_when_its_window_closes(tmp_path: Path) -> None:
    url, database = await migrated(tmp_path)
    clock = FakeClock()
    sink = DatabaseAuditSink(url, PSEUDONYMIZE, aggregate_seconds=60, clock=clock)
    await sink(event())
    await sink.flush()
    assert rows(database) == []  # the window is still open
    clock.advance(60)
    await sink.flush()
    assert rows(database) == [("high", 1)]
    await sink(event())  # a new window, a new row
    await sink.close()
    assert rows(database) == [("high", 1), ("high", 1)]


async def test_an_unreachable_database_never_reaches_the_caller_and_is_retried(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    url = f"sqlite+aiosqlite:///{database.as_posix()}"
    sink = DatabaseAuditSink(url, PSEUDONYMIZE)
    await sink(event())  # no table yet: the caller cannot tell
    with structlog.testing.capture_logs() as logs:
        await sink.flush(everything=True)
    assert [entry["event"] for entry in logs] == ["audit_write_failed"]

    await upgrade(url)
    await sink.close()  # the group was kept, and is written now
    assert rows(database) == [("high", 1)]


async def test_the_queue_is_bounded_and_drops_are_logged(tmp_path: Path) -> None:
    url, database = await migrated(tmp_path)
    sink = DatabaseAuditSink(url, PSEUDONYMIZE, max_groups=3)
    for i in range(5):
        await sink(event(source=f"198.51.100.{i}"))
    with structlog.testing.capture_logs() as logs:
        await sink.close()
    assert len(rows(database)) == 3
    assert [(e["event"], e.get("count")) for e in logs] == [("audit_events_dropped", 2)]


async def test_a_burst_writes_a_couple_of_rows_not_one_per_request(
    make_client: ClientFactory, tmp_path: Path
) -> None:
    async with make_client() as client:
        for _ in range(125):
            await client.get("/api/widgets")
    # Leaving the client ran the app's shutdown, which drains the sink.
    assert rows(tmp_path / "audit.db") == [("high", 65), ("medium", 1)]


async def test_requests_keep_their_verdicts_when_the_database_is_down(tmp_path: Path) -> None:
    settings = SentinelSettings(
        _env_file=None,
        backend="memory",
        jwt_secret=TEST_JWT_SECRET,
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'no' / 'such' / 'dir' / 'audit.db').as_posix()}",
    )
    app = create_app(settings)
    from httpx import ASGITransport, AsyncClient

    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            statuses = [(await client.get("/api/widgets")).status_code for _ in range(61)]
    assert statuses[:60] == [404] * 60
    assert statuses[60] == 429
