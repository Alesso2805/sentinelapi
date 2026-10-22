"""SEN-30: readiness, request ids, and JSON logs in production."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
import structlog
from httpx import ASGITransport, AsyncClient

from examples.demo_app.main import create_app
from sentinelapi.config import SentinelSettings
from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.logging_config import configure_logging, log_event

from .conftest import TEST_JWT_SECRET, ClientFactory

HEX_ID = re.compile(r"[0-9a-f]{32}")


@asynccontextmanager
async def unmigrated_app(**settings: Any) -> AsyncIterator[AsyncClient]:
    app = create_app(SentinelSettings(_env_file=None, jwt_secret=TEST_JWT_SECRET, **settings))
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            yield client


async def test_ready_when_the_backend_and_the_database_answer(client: AsyncClient) -> None:
    response = await client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"backend": "ok", "database": "ok"}}


async def test_not_ready_when_the_database_is_unreachable(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{(tmp_path / 'no' / 'such' / 'audit.db').as_posix()}"
    async with unmigrated_app(database_url=url) as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {"backend": "ok", "database": "failing"}


async def test_not_ready_when_the_database_is_not_migrated(tmp_path: Path) -> None:
    async with unmigrated_app(database_url=f"sqlite+aiosqlite:///{(tmp_path / 'a.db').as_posix()}") as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["database"] == "failing"


async def test_not_ready_when_redis_is_unreachable() -> None:
    async with unmigrated_app(backend="redis", redis_url="redis://127.0.0.1:1/0", audit=False) as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "checks": {"backend": "failing"}}


async def test_every_response_carries_a_request_id(client: AsyncClient) -> None:
    first = (await client.get("/health")).headers["X-Request-ID"]
    second = (await client.get("/health")).headers["X-Request-ID"]
    assert HEX_ID.fullmatch(first) and HEX_ID.fullmatch(second) and first != second


async def test_a_well_formed_incoming_request_id_is_kept_and_anything_else_replaced(
    client: AsyncClient,
) -> None:
    kept = await client.get("/health", headers={"X-Request-ID": "caller-42.a_b"})
    replaced = await client.get("/health", headers={"X-Request-ID": "no spaces <script>"})
    assert kept.headers["X-Request-ID"] == "caller-42.a_b"
    assert HEX_ID.fullmatch(replaced.headers["X-Request-ID"])


async def test_a_blocked_request_and_its_security_event_share_the_id(make_client: ClientFactory) -> None:
    async with make_client(rate_limit_max_requests=1) as client:
        await client.get("/api/widgets")
        with structlog.testing.capture_logs(processors=[structlog.contextvars.merge_contextvars]) as logs:
            blocked = await client.get("/api/widgets")
    assert blocked.status_code == 429
    events = [entry for entry in logs if entry["event"] == "security_event"]
    assert [entry["request_id"] for entry in events] == [blocked.headers["X-Request-ID"]]


@pytest.fixture
def restore_logging() -> Iterator[None]:
    yield
    configure_logging(json_output=False)


async def test_production_logs_are_json_lines_with_the_request_id(
    capsys: pytest.CaptureFixture[str], restore_logging: None
) -> None:
    configure_logging(json_output=True)
    event = SecurityEvent(
        threat_type=ThreatType.BRUTE_FORCE,
        threat_level=ThreatLevel.HIGH,
        fingerprint=build_fingerprint("203.0.113.7", "test"),
        path="/auth/login",
        detail="test",
        occurred_at=1_800_000_000.0,
    )
    with structlog.contextvars.bound_contextvars(request_id="r-1"):
        await log_event(event)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert (line["event"], line["request_id"], line["level"]) == ("security_event", "r-1", "warning")
