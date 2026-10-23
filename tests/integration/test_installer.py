"""SEN-22: install_sentinel, as an integrator uses it (ADR-0007)."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import StreamingResponse
from httpx import ASGITransport, AsyncClient

from sentinelapi.config import SentinelSettings
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.integration import install_sentinel

README = Path(__file__).resolve().parents[2] / "README.md"


def settings(**overrides: Any) -> SentinelSettings:
    return SentinelSettings(_env_file=None, backend="memory", audit=False, **overrides)


@asynccontextmanager
async def running(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            yield client


def readme_snippet() -> str:
    section = README.read_text(encoding="utf-8").split("## Use it in your app", 1)[1]
    match = re.search(r"```python\n(.*?)```", section, re.S)
    assert match, "the README's integration snippet"
    return match.group(1)


async def test_the_readme_snippet_works_as_written(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_AUDIT", "false")  # the snippet reads settings from the environment
    namespace: dict[str, Any] = {"passwords_match": lambda username, password: password == "right"}
    exec(compile(readme_snippet(), str(README), "exec"), namespace)

    async with running(namespace["app"]) as client:
        assert (await client.post("/login", json={"username": "ana", "password": "right"})).status_code == 200
        statuses = [
            (await client.post("/login", json={"username": "ana", "password": "wrong"})).status_code
            for _ in range(9)
        ]
        assert statuses[:7] == [401] * 7
        assert statuses[-1] == 429
        # Blocked: the right password does not get in either.
        assert (await client.post("/login", json={"username": "ana", "password": "right"})).status_code == 429


async def test_streaming_responses_and_background_tasks_pass_through() -> None:
    app = FastAPI()
    install_sentinel(app, settings())
    ran: list[str] = []

    @app.get("/stream")
    async def stream(background: BackgroundTasks) -> StreamingResponse:
        background.add_task(ran.append, "background")

        async def chunks() -> AsyncIterator[bytes]:
            for i in range(3):
                yield f"chunk{i};".encode()

        return StreamingResponse(chunks(), background=background)

    async with running(app) as client:
        response = await client.get("/stream")

    assert response.text == "chunk0;chunk1;chunk2;"
    assert ran == ["background"]


async def test_a_failing_on_event_never_fails_the_request() -> None:
    async def broken(event: SecurityEvent) -> None:
        raise RuntimeError("the app's sink is down")

    app = FastAPI()
    install_sentinel(app, settings(rate_limit_max_requests=2), on_event=broken)

    async with running(app) as client:
        statuses = [(await client.get("/anything")).status_code for _ in range(3)]

    assert statuses == [404, 404, 429]


async def test_the_apps_own_lifespan_still_runs() -> None:
    steps: list[str] = []

    @asynccontextmanager
    async def own(app: FastAPI) -> AsyncIterator[None]:
        steps.append("app started")
        yield
        steps.append("app stopped")

    app = FastAPI(lifespan=own)
    sentinel = install_sentinel(app, settings())
    closed: list[bool] = []

    async def close() -> None:
        closed.append(True)

    sentinel.backend.close = close  # type: ignore[attr-defined]  # what RedisBackend has
    async with running(app):
        pass

    assert steps == ["app started", "app stopped"]
    assert closed == [True]


async def test_the_installer_leaves_sentinel_in_app_state() -> None:
    app = FastAPI()
    sentinel = install_sentinel(app, settings())
    assert app.state.sentinel is sentinel


async def test_in_signal_mode_the_guard_hands_the_app_a_challenge() -> None:
    app = FastAPI()
    sentinel = install_sentinel(app, settings(brute_force_account_action="signal"))
    asked: list[bool] = []

    @app.post("/login/{username}")
    async def login(username: str, request: Request) -> dict[str, bool]:
        verdict = await sentinel.login_guard.check(request, username)
        asked.append(bool(verdict and verdict.challenge_required))
        await sentinel.login_guard.failed(request, username)
        return {}

    async with running(app) as client:
        for _ in range(9):
            await client.post("/login/bob")
    # Never locked; from the 8th failure on, the app is told to ask for a challenge.
    assert asked == [False] * 8 + [True]
