"""AR-13: no raw client address, username or token reaches the audit
table or the security log."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import structlog

from .conftest import ClientFactory

USERNAME = "alice@example.com"
# httpx's ASGI transport presents every request as coming from this address.
CLIENT_ADDRESS = "127.0.0.1"


async def test_no_raw_address_or_username_reaches_the_audit_trail(
    make_client: ClientFactory, tmp_path: Path
) -> None:
    with structlog.testing.capture_logs() as logs:
        async with make_client() as client:
            for _ in range(10):
                await client.post("/auth/login", json={"username": USERNAME, "password": "wrong"})
            login = await client.post(
                "/auth/login", json={"username": USERNAME, "password": "correct-horse-battery-staple"}
            )

    with sqlite3.connect(tmp_path / "audit.db") as db:
        rows = [repr(row) for row in db.execute("SELECT * FROM sentinel_security_events")]
    assert rows, "the scenario should have produced events"

    secrets = [USERNAME, CLIENT_ADDRESS]
    if login.status_code == 200:
        secrets.append(login.json()["refresh_token"])
    for secret in secrets:
        assert not [r for r in rows if secret in r], secret
        assert not [entry for entry in logs if secret in repr(entry)], secret
