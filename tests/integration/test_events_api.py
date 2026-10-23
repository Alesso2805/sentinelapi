"""The demo's events API, for operators only (AR-14)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient

from .conftest import ALICE_LOGIN, OPERATOR, ClientFactory

# Behind a trusted proxy, so the attacker below and the operator are two clients,
# as they would be: the operator's own reads are not caught in the attacker's limit.
ATTACKER = {"X-Forwarded-For": "198.51.100.66"}


@pytest.fixture
async def client(make_client: ClientFactory) -> AsyncIterator[AsyncClient]:
    async with make_client(trusted_proxies=["127.0.0.1/32"]) as client:
        yield client


async def produce_events(client: AsyncClient) -> None:
    """One CRITICAL replay, then a burst: a MEDIUM at the 49th request and
    HIGHs from the 61st. The login comes first, since every request counts."""
    login = await client.post("/auth/login", json=ALICE_LOGIN, headers=ATTACKER)
    refresh = {**ATTACKER, "Authorization": f"Bearer {login.json()['refresh_token']}"}
    await client.post("/auth/refresh", headers=refresh)
    await client.post("/auth/refresh", headers=refresh)
    for _ in range(61):
        await client.get("/api/widgets", headers=ATTACKER)


async def events(client: AsyncClient, **params: Any) -> Any:
    response = await client.get("/security/events", headers=OPERATOR, params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def test_nobody_but_the_operator_reads_the_events(make_client: ClientFactory) -> None:
    async with make_client() as client:
        assert (await client.get("/security/events")).status_code in (401, 403)
        wrong = {"Authorization": "Bearer guess"}
        assert (await client.get("/security/events", headers=wrong)).status_code == 401
    async with make_client(operator_token=None) as client:
        assert (await client.get("/security/events", headers=OPERATOR)).status_code == 401


async def test_filters_and_a_real_total(client: AsyncClient) -> None:
    await produce_events(client)
    everything = await events(client)
    critical = await events(client, threat_level="critical")
    rate_limited = await events(client, threat_type="rate_limit_exceeded")
    future = await events(client, since=(datetime.now(UTC) + timedelta(hours=1)).isoformat())

    assert everything["total"] == 3
    assert [(e["threat_type"], e["count"]) for e in critical["items"]] == [("jwt_replay", 1)]
    assert sorted(e["threat_level"] for e in rate_limited["items"]) == ["high", "medium"]
    assert future == {"total": 0, "items": []}


async def test_pages(client: AsyncClient) -> None:
    await produce_events(client)
    first = await events(client, limit=1)
    past_the_end = await events(client, offset=10)
    too_many = await client.get("/security/events", headers=OPERATOR, params={"limit": 101})

    assert (first["total"], len(first["items"])) == (3, 1)
    assert past_the_end == {"total": 3, "items": []}
    assert too_many.status_code == 422


async def test_events_carry_keyed_hashes_not_addresses(client: AsyncClient) -> None:
    await produce_events(client)
    for item in (await events(client))["items"]:
        assert len(item["fingerprint_key"]) == 32
        assert item["client_hash"]
        assert "198.51.100.66" not in repr(item)
