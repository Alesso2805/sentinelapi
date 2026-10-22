"""AR-15: the middleware never reads the request body."""

from __future__ import annotations

from starlette.types import Message, Receive, Scope, Send

from sentinelapi.detectors.rate_limiter import RateLimiter
from sentinelapi.middleware import SentinelMiddleware
from sentinelapi.storage.memory_backend import InMemoryBackend


async def app_that_ignores_the_body(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def test_the_middleware_never_reads_the_request_body() -> None:
    middleware = SentinelMiddleware(app_that_ignores_the_body, rate_limiter=RateLimiter(InMemoryBackend()))
    handed_out: list[Message] = []
    sent: list[Message] = []

    async def receive() -> Message:
        message: Message = {"type": "http.request", "body": b'{"password": "hunter2"}', "more_body": False}
        handed_out.append(message)
        return message

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/auth/login",
        "raw_path": b"/auth/login",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"user-agent", b"test"), (b"content-type", b"application/json")],
        "client": ("203.0.113.7", 50000),
        "server": ("testserver", 80),
    }
    await middleware(scope, receive, send)

    assert sent[0]["status"] == 200
    assert handed_out == []
