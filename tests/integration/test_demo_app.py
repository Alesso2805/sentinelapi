"""End-to-end tests against the demo FastAPI app.

Each test builds its own app (see conftest.py), so it gets its own
counters and its own SQLite database under pytest's `tmp_path`, with the
lifespan run as uvicorn would run it.
"""

from __future__ import annotations

from pathlib import Path

import jwt
from httpx import AsyncClient

from .conftest import OPERATOR, ClientFactory

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
    assert [r.status_code for r in responses[:7]] == [401] * 7
    assert responses[-1].status_code == 429
    assert int(responses[-1].headers["Retry-After"]) > 0
    # Nothing an attacker could use: no count, no username.
    assert responses[-1].json() == {"detail": "Too many failed sign-in attempts. Try again later."}


async def test_the_right_password_does_not_lift_a_block(client: AsyncClient) -> None:
    for _ in range(12):
        await client.post("/auth/login", json={**ALICE, "password": "wrong"})
    response = await client.post("/auth/login", json=ALICE)
    assert response.status_code == 429


async def test_refresh_token_cannot_be_replayed(client: AsyncClient) -> None:
    login = await client.post("/auth/login", json=ALICE)
    headers = {"Authorization": f"Bearer {login.json()['refresh_token']}"}

    first = await client.post("/auth/refresh", headers=headers)
    second = await client.post("/auth/refresh", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 403


async def test_burst_of_requests_gets_rate_limited(client: AsyncClient) -> None:
    # The default limit is 60 per minute: the 61st request is blocked, and told when to retry.
    responses = [await client.get("/api/widgets") for _ in range(61)]
    assert {r.status_code for r in responses[:60]} == {404}
    assert responses[60].status_code == 429
    assert 1 <= int(responses[60].headers["Retry-After"]) <= 60


async def test_health_checks_are_never_rate_limited(client: AsyncClient) -> None:
    statuses = {(await client.get("/health")).status_code for _ in range(200)}
    assert statuses == {200}


async def test_apps_do_not_share_counters(make_client: ClientFactory) -> None:
    async with make_client() as first:
        for _ in range(60):
            await first.get("/api/widgets")
        assert (await first.get("/api/widgets")).status_code == 429

    async with make_client() as second:
        assert (await second.get("/api/widgets")).status_code == 404


async def test_shadow_mode_records_events_but_never_blocks(make_client: ClientFactory) -> None:
    async with make_client(enforce=False) as client:
        statuses = {(await client.get("/api/widgets")).status_code for _ in range(125)}
        page = (await client.get("/security/events", headers=OPERATOR)).json()

    assert statuses == {404}
    assert {(e["threat_type"], e["threat_level"]) for e in page["items"]} == {
        ("rate_limit_exceeded", "high"),
        ("rate_limit_exceeded", "medium"),
    }


async def test_blocking_events_reach_the_audit_trail(client: AsyncClient, tmp_path: Path) -> None:
    login = await client.post("/auth/login", json=ALICE)
    headers = {"Authorization": f"Bearer {login.json()['refresh_token']}"}
    await client.post("/auth/refresh", headers=headers)
    await client.post("/auth/refresh", headers=headers)

    page = (await client.get("/security/events", headers=OPERATOR)).json()

    assert [(e["threat_type"], e["threat_level"], e["path"]) for e in page["items"]] == [
        ("jwt_replay", "critical", "/auth/refresh")
    ]
    assert (tmp_path / "audit.db").exists()


async def test_forwarded_for_from_an_untrusted_peer_is_ignored(client: AsyncClient) -> None:
    # With no trusted proxy, every request below comes from the same client,
    # whatever address it claims.
    statuses = [
        (await client.get("/api/widgets", headers={"X-Forwarded-For": f"198.51.100.{i}"})).status_code
        for i in range(61)
    ]
    assert statuses[-1] == 429


async def test_clients_behind_a_trusted_proxy_get_their_own_limits(make_client: ClientFactory) -> None:
    # httpx's ASGI transport presents every request as coming from 127.0.0.1: here, the proxy.
    async with make_client(trusted_proxies=["127.0.0.1/32"]) as client:
        noisy = {"X-Forwarded-For": "203.0.113.66"}
        for _ in range(60):
            await client.get("/api/widgets", headers=noisy)
        assert (await client.get("/api/widgets", headers=noisy)).status_code == 429
        quiet = await client.get("/api/widgets", headers={"X-Forwarded-For": "203.0.113.67"})
        assert quiet.status_code == 404


async def test_tokens_are_signed_with_the_configured_secret(client: AsyncClient) -> None:
    login = await client.post("/auth/login", json=ALICE)
    assert (
        await client.get("/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"})
    ).json() == {"user": "alice@example.com"}
    forged = jwt.encode({"sub": "alice@example.com", "exp": 9_999_999_999}, "change-me", algorithm="HS256")
    assert (await client.get("/me", headers={"Authorization": f"Bearer {forged}"})).status_code == 401


async def test_audience_and_issuer_travel_end_to_end(make_client: ClientFactory) -> None:
    async with make_client(jwt_audience="sentinel-demo", jwt_issuer="https://sentinel.example") as client:
        login = await client.post("/auth/login", json=ALICE)
        headers = {"Authorization": f"Bearer {login.json()['refresh_token']}"}
        assert (await client.post("/auth/refresh", headers=headers)).status_code == 200
        assert (await client.post("/auth/refresh", headers=headers)).status_code == 403
