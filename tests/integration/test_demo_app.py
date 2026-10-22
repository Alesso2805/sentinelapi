"""End-to-end tests against the demo FastAPI app.

Each test builds its own app (see conftest.py), so it gets its own
counters and its own SQLite database under pytest's `tmp_path`, with the
lifespan run as uvicorn would run it.
"""

from __future__ import annotations

from pathlib import Path

from httpx import AsyncClient

from .conftest import ClientFactory

ALICE = {"username": "alice@example.com", "password": "correct-horse-battery-staple"}


async def test_health_check(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_login_with_bad_credentials_is_rejected(client: AsyncClient) -> None:
    response = await client.post("/auth/login", json={**ALICE, "password": "wrong"})
    assert response.status_code == 401


async def test_login_success_issues_tokens(client: AsyncClient) -> None:
    response = await client.post("/auth/login", json=ALICE)
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body


async def test_repeated_failed_logins_eventually_blocked(client: AsyncClient) -> None:
    responses = [
        await client.post("/auth/login", json={"username": "nobody@example.com", "password": "guess"})
        for _ in range(12)
    ]
    assert responses[-1].status_code == 403


async def test_refresh_token_cannot_be_replayed(client: AsyncClient) -> None:
    login = await client.post("/auth/login", json=ALICE)
    headers = {"Authorization": f"Bearer {login.json()['refresh_token']}"}

    first = await client.post("/auth/refresh", headers=headers)
    second = await client.post("/auth/refresh", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 403


async def test_burst_of_requests_gets_rate_limited(client: AsyncClient) -> None:
    # Default limit is 60/min, but RateLimiter only blocks (HIGH) once the
    # overshoot itself exceeds the limit — i.e. past 2x max_requests (120).
    # Below that it's a MEDIUM, log-only event (see test_rate_limiter.py).
    statuses = [(await client.get("/health")).status_code for _ in range(125)]
    assert statuses[-1] == 429


async def test_apps_do_not_share_counters(make_client: ClientFactory) -> None:
    async with make_client() as first:
        for _ in range(125):
            await first.get("/health")
        assert (await first.get("/health")).status_code == 429

    async with make_client() as second:
        assert (await second.get("/health")).status_code == 200


async def test_shadow_mode_records_events_but_never_blocks(make_client: ClientFactory) -> None:
    async with make_client(enforce=False) as client:
        statuses = {(await client.get("/health")).status_code for _ in range(125)}
        events = (await client.get("/security/events")).json()

    assert statuses == {200}
    assert {(e["threat_type"], e["threat_level"]) for e in events} == {("rate_limit_exceeded", "high")}


async def test_blocking_events_reach_the_audit_trail(client: AsyncClient, tmp_path: Path) -> None:
    login = await client.post("/auth/login", json=ALICE)
    headers = {"Authorization": f"Bearer {login.json()['refresh_token']}"}
    await client.post("/auth/refresh", headers=headers)
    await client.post("/auth/refresh", headers=headers)

    events = (await client.get("/security/events")).json()

    assert [(e["threat_type"], e["threat_level"], e["path"]) for e in events] == [
        ("jwt_replay", "critical", "/auth/refresh")
    ]
    assert (tmp_path / "audit.db").exists()
