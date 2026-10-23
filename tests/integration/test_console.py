"""SEN-32: the attack console (ADR-0010)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from httpx import AsyncClient

from examples.demo_app.console import Console
from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import SecurityEvent, ThreatLevel, ThreatType

from .conftest import OPERATOR, ClientFactory


@pytest.fixture
async def console(make_client: ClientFactory) -> AsyncIterator[AsyncClient]:
    async with make_client(demo_mode=True) as client:
        assert (await client.get("/")).status_code == 200  # sets the session cookie
        yield client


async def run(client: AsyncClient, name: str) -> Any:
    response = await client.post(f"/demo/scenarios/{name}")
    assert response.status_code == 200, response.text
    return response.json()


async def test_the_page_is_served_with_a_strict_policy_and_a_private_session(
    make_client: ClientFactory,
) -> None:
    async with make_client(demo_mode=True) as client:
        response = await client.get("/")
    assert "Launch an attack" in response.text
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    cookie = response.headers["Set-Cookie"].lower()
    assert "sentinel_console=" in cookie and "httponly" in cookie and "samesite=strict" in cookie


async def test_the_burst_is_blocked_right_after_the_limit(console: AsyncClient) -> None:
    result = await run(console, "burst")
    outcomes = [step["outcome"] for step in result["steps"]]
    assert len(outcomes) == 70
    assert outcomes[48] == "warned"  # 80 % of 60
    assert outcomes[59] == "allowed" and outcomes[60:] == ["blocked"] * 10
    assert result["steps"][60]["status"] == 429 and result["steps"][60]["retry_after"] > 0
    assert "From request 61 on" in result["summary"]


async def test_stuffing_locks_the_account_though_no_address_failed_twice(console: AsyncClient) -> None:
    result = await run(console, "stuffing")
    steps = result["steps"]
    assert len({step["source"] for step in steps[:20]}) == 20
    assert [step["status"] for step in steps[:7]] == [401] * 7
    assert all(step["outcome"] == "blocked" for step in steps[7:20])
    assert steps[20]["request"].endswith("right password") and steps[20]["outcome"] == "blocked"
    assert "the 8th failure locked the account" in result["summary"]
    # SEN-43: the refused attempts count, so the attack that goes on turns CRITICAL.
    assert [step["level"] for step in steps[7:15]] == ["high"] * 7 + ["critical"]
    assert "From the 15th attempt the attack that goes on is CRITICAL" in result["summary"]


async def test_a_replayed_token_is_blocked_and_a_forged_one_rejected(console: AsyncClient) -> None:
    steps = (await run(console, "replay"))["steps"]
    assert [(s["status"], s["outcome"]) for s in steps] == [
        (200, "allowed"),
        (200, "allowed"),
        (403, "blocked"),
        (401, "rejected"),
    ]
    assert steps[2]["threat_type"] == "jwt_replay" and steps[2]["level"] == "critical"


async def test_every_run_starts_from_scratch(console: AsyncClient) -> None:
    first = await run(console, "stuffing")
    second = await run(console, "stuffing")
    assert first["steps"] == second["steps"]


async def test_runs_reach_the_real_audit_trail(console: AsyncClient) -> None:
    await run(console, "replay")
    page = (
        await console.get("/security/events", headers=OPERATOR, params={"threat_type": "jwt_replay"})
    ).json()
    assert page["total"] == 1


async def test_a_run_needs_the_console_session(make_client: ClientFactory) -> None:
    async with make_client(demo_mode=True) as client:
        assert (await client.post("/demo/scenarios/burst")).status_code == 400
        assert (await client.get("/demo/events")).status_code == 400


async def test_unknown_scenarios_are_refused(console: AsyncClient) -> None:
    assert (await console.post("/demo/scenarios/ddos")).status_code == 422


async def test_ten_runs_per_hour_per_address(console: AsyncClient) -> None:
    for _ in range(10):
        await run(console, "replay")
    refused = await console.post("/demo/scenarios/replay")
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) > 0


async def test_without_demo_mode_the_console_does_not_exist(make_client: ClientFactory) -> None:
    async with make_client() as client:
        assert (await client.get("/")).status_code == 404
        assert (await client.post("/demo/scenarios/burst")).status_code == 404
        assert (await client.get("/static/console.js")).status_code == 404


async def test_a_visitor_sees_only_their_own_events() -> None:
    console = Console()
    mine, theirs = console.subscribe("me"), console.subscribe("them")
    event = SecurityEvent(
        threat_type=ThreatType.JWT_REPLAY,
        threat_level=ThreatLevel.CRITICAL,
        fingerprint=build_fingerprint("198.51.100.200", "test"),
        path="/auth/refresh",
        detail="replayed",
        occurred_at=1_800_000_000.0,
    )
    console.publish("me", event)
    payload = json.loads(await asyncio.wait_for(mine.get(), timeout=1))
    assert (payload["threat_type"], payload["threat_level"]) == ("jwt_replay", "critical")
    assert "198.51.100.200" not in json.dumps(payload)
    assert theirs.empty()
    console.unsubscribe("me", mine)
    console.publish("me", event)  # nobody listening: dropped, no error
