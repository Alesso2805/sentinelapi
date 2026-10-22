"""AR-11 and AR-12: the audit table comes from migrations that match the
models and reverse cleanly, and the app's role can only add and read rows.

SQLite always; Postgres too when SENTINEL_TEST_DATABASE_URL is set (CI sets it).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelapi.audit.migrate import check, current, downgrade, head, upgrade
from sentinelapi.audit.retention import purge
from sentinelapi.audit.sink import DatabaseAuditSink
from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.privacy import Pseudonymizer
from tests.fakes import FakeClock

TABLE = "sentinel_security_events"
POSTGRES = os.environ.get("SENTINEL_TEST_DATABASE_URL")
APP_ROLE, APP_PASSWORD = "sentinel_test_app", "app-role-password"
PSEUDONYMIZE = Pseudonymizer("test-audit-hash-key")


@pytest.fixture(params=["sqlite", "postgres"])
async def database_url(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[str]:
    if request.param == "sqlite":
        yield f"sqlite+aiosqlite:///{(tmp_path / 'audit.db').as_posix()}"
        return
    if not POSTGRES:
        pytest.skip("SENTINEL_TEST_DATABASE_URL is not set (CI sets it)")
    await downgrade(POSTGRES, "base")
    yield POSTGRES
    await downgrade(POSTGRES, "base")


async def tables(database_url: str) -> set[str]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            return await connection.run_sync(lambda c: set(inspect(c).get_table_names()))
    finally:
        await engine.dispose()


async def execute(database_url: str, sql: str) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as connection:
            await connection.execute(text(sql))
    finally:
        await engine.dispose()


def an_event(occurred_at: float = 1_800_000_000.0) -> SecurityEvent:
    return SecurityEvent(
        threat_type=ThreatType.BRUTE_FORCE,
        threat_level=ThreatLevel.HIGH,
        fingerprint=build_fingerprint("203.0.113.7", "test"),
        path="/auth/login",
        detail="test",
        occurred_at=occurred_at,
    )


async def test_the_migrations_create_the_table_the_models_describe(database_url: str) -> None:  # AR-11
    await upgrade(database_url)
    assert TABLE in await tables(database_url)
    assert await current(database_url) == head()
    await check(database_url)  # raises if the models and the schema differ


async def test_the_migrations_reverse_cleanly(database_url: str) -> None:  # AR-11
    await upgrade(database_url)
    await downgrade(database_url, "base")
    assert TABLE not in await tables(database_url)
    await upgrade(database_url)
    assert TABLE in await tables(database_url)


async def test_the_database_refuses_an_unknown_threat_type(database_url: str) -> None:
    await upgrade(database_url)
    with pytest.raises(IntegrityError):
        await execute(
            database_url,
            f"INSERT INTO {TABLE} (id, threat_type, threat_level, fingerprint_key, path, detail, occurred_at)"
            " VALUES ('x', 'nonsense', 'high', 'k', '/', 'd', CURRENT_TIMESTAMP)",
        )


async def test_the_sink_writes_and_reads_events(database_url: str) -> None:
    await upgrade(database_url)
    sink = DatabaseAuditSink(database_url, PSEUDONYMIZE)
    try:
        await sink.start()
        await sink(an_event())
        await sink.flush(everything=True)
        rows = await sink.recent_critical()
    finally:
        await sink.close()
    assert [(r.threat_type, r.threat_level, r.occurred_at.timestamp()) for r in rows] == [
        ("brute_force", "high", 1_800_000_000.0)
    ]


@pytest.mark.skipif(not POSTGRES, reason="SENTINEL_TEST_DATABASE_URL is not set (CI sets it)")
async def test_the_app_role_cannot_rewrite_the_audit_trail() -> None:  # AR-12
    assert POSTGRES
    await execute(
        POSTGRES,
        f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN "
        f"CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_PASSWORD}'; END IF; END $$",
    )
    await downgrade(POSTGRES, "base")
    await upgrade(POSTGRES, app_role=APP_ROLE)
    as_app = make_url(POSTGRES).set(username=APP_ROLE, password=APP_PASSWORD)
    as_app_url = as_app.render_as_string(hide_password=False)
    try:
        sink = DatabaseAuditSink(as_app_url, PSEUDONYMIZE)
        await sink(an_event())
        await sink.flush(everything=True)  # INSERT works
        assert len(await sink.recent_critical()) == 1  # SELECT works
        await sink.close()
        for statement in (f"UPDATE {TABLE} SET detail = 'rewritten'", f"DELETE FROM {TABLE}"):
            with pytest.raises(DBAPIError, match="permission denied"):
                await execute(as_app_url, statement)
    finally:
        await downgrade(POSTGRES, "base")


async def test_purge_deletes_only_what_is_past_retention(database_url: str) -> None:
    await upgrade(database_url)
    clock = FakeClock()
    sink = DatabaseAuditSink(database_url, PSEUDONYMIZE)
    try:
        # Flushed one by one: identical events in one window would be one row.
        await sink(an_event(occurred_at=clock.now() - 91 * 86_400))
        await sink.flush(everything=True)
        await sink(an_event(occurred_at=clock.now() - 89 * 86_400))
        await sink.flush(everything=True)
        assert await purge(database_url, older_than_days=90, clock=clock) == 1
        assert len(await sink.recent_critical()) == 1
    finally:
        await sink.close()
