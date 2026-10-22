"""End-to-end tests against the demo FastAPI app.

Unlike the other test files, these need the full dependency set
(fastapi, httpx, sqlalchemy, aiosqlite) so they're pytest-based rather
than stdlib-unittest. Run them locally after `pip install -e ".[dev]"`:

    pytest tests/test_middleware_integration.py -v

They were written against the documented FastAPI/httpx APIs but not
executed in the sandbox this project was built in, which has no network
access to install these packages — see the project README for details.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from examples.demo_app.auth import _hash_password  # noqa: F401  (imported to confirm demo user setup)
from examples.demo_app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_login_with_bad_credentials_is_rejected(client: AsyncClient) -> None:
    response = await client.post("/auth/login", json={"username": "alice@example.com", "password": "wrong"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_success_issues_tokens(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/login",
        json={"username": "alice@example.com", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body


@pytest.mark.asyncio
async def test_repeated_failed_logins_eventually_blocked(client: AsyncClient) -> None:
    last_response = None
    for _ in range(12):
        last_response = await client.post(
            "/auth/login", json={"username": "nobody@example.com", "password": "guess"}
        )
    assert last_response is not None
    assert last_response.status_code == 403


@pytest.mark.asyncio
async def test_refresh_token_cannot_be_replayed(client: AsyncClient) -> None:
    login = await client.post(
        "/auth/login",
        json={"username": "alice@example.com", "password": "correct-horse-battery-staple"},
    )
    refresh_token = login.json()["refresh_token"]
    headers = {"Authorization": f"Bearer {refresh_token}"}

    first = await client.post("/auth/refresh", headers=headers)
    assert first.status_code == 200

    second = await client.post("/auth/refresh", headers=headers)
    assert second.status_code == 403  # SentinelMiddleware blocks the replay


@pytest.mark.asyncio
async def test_burst_of_requests_gets_rate_limited(client: AsyncClient) -> None:
    # Default limit is 60/min, but RateLimiter only blocks (HIGH) once the
    # overshoot itself exceeds the limit — i.e. past 2x max_requests (120).
    # Below that it's a MEDIUM, log-only event (see test_rate_limiter.py).
    last_response = None
    for _ in range(125):
        last_response = await client.get("/health")
    assert last_response is not None
    assert last_response.status_code == 429
