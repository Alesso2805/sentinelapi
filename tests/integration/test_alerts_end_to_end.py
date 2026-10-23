"""A replayed refresh token, or credential stuffing, in the demo reaches a real HTTP receiver."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from .conftest import ALICE_LOGIN, ClientFactory


@pytest.fixture
def receiver() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    received: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 (the standard library's name)
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append({"content_type": self.headers["Content-Type"], **json.loads(body)})
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/hook", received
    server.shutdown()


async def test_a_replayed_token_reaches_the_webhook_once(
    make_client: ClientFactory, receiver: tuple[str, list[dict[str, Any]]]
) -> None:
    url, received = receiver
    async with make_client(alert_webhook_url=url) as client:
        login = await client.post("/auth/login", json=ALICE_LOGIN)
        refresh = {"Authorization": f"Bearer {login.json()['refresh_token']}"}
        await client.post("/auth/refresh", headers=refresh)
        for _ in range(5):  # the same attacker, five replays: one alert
            await client.post("/auth/refresh", headers=refresh)
    # Leaving the client ran the shutdown, which gives queued alerts time to go out.
    assert len(received) == 1
    assert received[0]["content_type"] == "application/json"
    assert "CRITICAL jwt replay on /auth/refresh" in received[0]["text"]


async def test_credential_stuffing_reaches_the_webhook_once(
    make_client: ClientFactory, receiver: tuple[str, list[dict[str, Any]]]
) -> None:
    """One account, a new address every time, attempts going on after the lock."""
    url, received = receiver
    wrong = {**ALICE_LOGIN, "password": "wrong"}
    # httpx's ASGI transport presents every request as coming from 127.0.0.1: here, the proxy.
    async with make_client(alert_webhook_url=url, trusted_proxies=["127.0.0.1/32"]) as client:
        for i in range(20):
            await client.post("/auth/login", json=wrong, headers={"X-Forwarded-For": f"198.51.100.{i}"})
    assert len(received) == 1
    assert "CRITICAL brute force on /auth/login" in received[0]["text"]
    assert ALICE_LOGIN["username"] not in received[0]["text"]
