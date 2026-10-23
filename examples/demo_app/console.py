"""The attack console (ADR-0010): three attacks a visitor can launch from a
browser and watch get caught.

They run on the server, against SentinelAPI's real detectors, from simulated
addresses in the ranges reserved for documentation (RFC 5737): a browser
cannot spread credential stuffing over twenty addresses, and the demo must
not let a client choose its own address (ADR-0004). Each run gets a sandbox,
fresh detectors on a memory backend of their own, so visitors never
interfere and every run starts the same way; every verdict still reaches
the log, the audit trail and the visitor's own live stream.

The routes exist only with SENTINEL_DEMO_MODE=true.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import secrets
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any, Literal

import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel
from starlette.responses import HTMLResponse, Response, StreamingResponse
from starlette.staticfiles import StaticFiles

from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import SecurityEvent, ThreatLevel
from sentinelapi.integration import Sandbox, Sentinel

from .auth import _issue_tokens, get_sentinel

STATIC = Path(__file__).parent / "static"
SESSION_COOKIE = "sentinel_console"
RUNS_PER_HOUR = 10
# The page loads its own script and style and talks to its own origin, nothing else.
PAGE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

Outcome = Literal["allowed", "rejected", "warned", "blocked"]
Report = Callable[[SecurityEvent], Awaitable[None]]


class Step(BaseModel):
    number: int
    source: str
    request: str
    status: int
    outcome: Outcome
    threat_type: str | None = None
    level: str | None = None
    detail: str | None = None
    retry_after: int | None = None


class ScenarioResult(BaseModel):
    scenario: str
    title: str
    summary: str
    steps: list[Step]


class Console:
    """Each visitor's live stream, keyed by the console's session cookie:
    a visitor sees their own runs' events and nobody else's."""

    def __init__(self) -> None:
        self._streams: dict[str, set[asyncio.Queue[str]]] = defaultdict(set)

    def subscribe(self, session: str) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=500)
        self._streams[session].add(queue)
        return queue

    def unsubscribe(self, session: str, queue: asyncio.Queue[str]) -> None:
        self._streams[session].discard(queue)
        if not self._streams[session]:
            del self._streams[session]

    def publish(self, session: str, event: SecurityEvent) -> None:
        payload = json.dumps(
            {
                "threat_type": event.threat_type.value,
                "threat_level": event.threat_level.value,
                "path": event.path,
                "detail": event.detail,
                "occurred_at": event.occurred_at,
            }
        )
        for queue in self._streams.get(session, ()):
            with contextlib.suppress(asyncio.QueueFull):  # a stalled tab loses events, never the server
                queue.put_nowait(payload)


def _step(
    number: int, source: str, request: str, event: SecurityEvent | None, *, quiet: int, flagged: int
) -> Step:
    """The answer the request would have got: `quiet` when SentinelAPI had
    nothing to say, `flagged` when it reported without blocking, and its own
    429 or 403 when it blocked."""

    def answered(status: int, outcome: Outcome, **more: Any) -> Step:
        return Step(number=number, source=source, request=request, status=status, outcome=outcome, **more)

    if event is None:
        return answered(quiet, "allowed" if quiet < 400 else "rejected")
    details = {
        "threat_type": event.threat_type.value,
        "level": event.threat_level.value,
        "detail": event.detail,
    }
    if event.is_blocking():
        status = 403 if event.threat_type.value == "jwt_replay" else 429
        return answered(status, "blocked", retry_after=math.ceil(event.retry_after or 0) or None, **details)
    return answered(flagged, "warned" if flagged < 400 else "rejected", **details)


async def burst(sandbox: Sandbox, sentinel: Sentinel, report: Report) -> ScenarioResult:
    limit = sentinel.settings.rate_limit_max_requests
    source = "203.0.113.10"
    fingerprint = build_fingerprint(source, "attack-console/burst")
    steps = []
    for number in range(1, limit + 11):
        event = await sandbox.rate_limiter.check(fingerprint, "/api/orders")
        if event is not None:
            await report(event)
        steps.append(_step(number, source, "GET /api/orders", event, quiet=200, flagged=200))
    first_block = next(s for s in steps if s.outcome == "blocked")
    warned = [s.number for s in steps if s.outcome == "warned"]
    return ScenarioResult(
        scenario="burst",
        title="Burst",
        summary=(
            f"{limit} requests passed, with a warning at request {warned[0]}. From request "
            f"{first_block.number} on, every one got 429 and was told to retry in"
            f" {first_block.retry_after} s."
        ),
        steps=steps,
    )


async def stuffing(sandbox: Sandbox, sentinel: Sentinel, report: Report) -> ScenarioResult:
    account = "victim@example.com"
    detector = sandbox.brute_force
    steps = []
    for number in range(1, 21):
        source = f"198.51.100.{number}"
        fingerprint = build_fingerprint(source, "attack-console/stuffing")
        request = f"POST /auth/login as {account}, wrong password"
        verdict = await detector.check(fingerprint, account, "/auth/login")
        if verdict is not None:
            await report(verdict)
            if verdict.is_blocking():
                steps.append(_step(number, source, request, verdict, quiet=401, flagged=401))
                continue
        event = await detector.record_failure(fingerprint, account, "/auth/login")
        if event is not None:
            await report(event)
        steps.append(_step(number, source, request, event, quiet=401, flagged=401))

    owner = build_fingerprint("192.0.2.25", "attack-console/owner")
    verdict = await detector.check(owner, account, "/auth/login")
    if verdict is not None:
        await report(verdict)
    steps.append(
        _step(
            21,
            "192.0.2.25",
            f"POST /auth/login as {account}, right password",
            verdict,
            quiet=200,
            flagged=200,
        )
    )

    locked_at = next(s.number for s in steps if s.outcome == "blocked")
    critical_at = next((s.number for s in steps if s.level == ThreatLevel.CRITICAL.value), None)
    going_on = (
        f" From the {critical_at}th attempt the attack that goes on is CRITICAL: the webhook hears of it."
        if critical_at
        else ""
    )
    minutes = sentinel.settings.brute_force_window_seconds // 60
    owner_step = steps[-1]
    ending = (
        f"So was its owner with the right password: the lock holds for {minutes} minutes, the price of "
        "stopping stuffing without a CAPTCHA (ADR-0005)."
        if owner_step.outcome == "blocked"
        else "Its owner got in with the right password."
    )
    return ScenarioResult(
        scenario="stuffing",
        title="Credential stuffing",
        summary=(
            f"No address failed more than once, yet the {locked_at}th failure locked the account: "
            f"the next {20 - locked_at} attempts were refused before their password was checked."
            f"{going_on} {ending}"
        ),
        steps=steps,
    )


async def replay(sandbox: Sandbox, sentinel: Sentinel, report: Report) -> ScenarioResult:
    tokens = _issue_tokens(sentinel.settings, "alice@example.com")
    owner, attacker = "203.0.113.20", "198.51.100.200"
    steps = [
        Step(
            number=1,
            source=owner,
            request="POST /auth/login as alice@example.com",
            status=200,
            outcome="allowed",
        )
    ]

    async def redeem(number: int, source: str, token: str, request: str) -> None:
        fingerprint = build_fingerprint(source, f"attack-console/replay/{source}")
        event = await sandbox.jwt_replay.check(token, fingerprint, "/auth/refresh")
        if event is not None:
            await report(event)
        steps.append(_step(number, source, request, event, quiet=200, flagged=401))

    await redeem(2, owner, tokens.refresh_token, "POST /auth/refresh, the owner rotates the token")
    await redeem(3, attacker, tokens.refresh_token, "POST /auth/refresh, a stolen copy replayed")
    forged = jwt.encode(
        {"sub": "alice@example.com", "jti": "forged", "exp": 9_999_999_999},
        "a-guessed-key-0123456789abcdef!!",
    )
    await redeem(4, attacker, forged, "POST /auth/refresh, a token signed with a guessed key")
    return ScenarioResult(
        scenario="replay",
        title="Token replay",
        summary=(
            "The owner rotated the refresh token once. The stolen copy, replayed from another address, "
            "got 403 as likely token theft, and a token signed with a guessed key was rejected as invalid."
        ),
        steps=steps,
    )


SCENARIOS = {"burst": burst, "stuffing": stuffing, "replay": replay}

router = APIRouter(tags=["attack console"])


@router.post("/demo/scenarios/{name}", response_model=ScenarioResult)
async def run_scenario(
    name: Literal["burst", "stuffing", "replay"],
    request: Request,
    sentinel: Annotated[Sentinel, Depends(get_sentinel)],
) -> ScenarioResult:
    session = request.cookies.get(SESSION_COOKIE)
    if not session:
        raise HTTPException(status_code=400, detail="Open the console first.")
    # 10 runs per hour per visitor's address, counted in the app's own backend.
    visitor = sentinel.login_guard.fingerprint(request)
    key = f"demo:runs:{visitor.client}"
    if await sentinel.backend.incr_with_expiry(key, 3600) > RUNS_PER_HOUR:
        wait = math.ceil(await sentinel.backend.ttl(key))
        raise HTTPException(
            status_code=429,
            detail=f"{RUNS_PER_HOUR} attacks per hour; try again in {math.ceil(wait / 60)} minutes.",
            headers={"Retry-After": str(wait)},
        )
    console: Console = request.app.state.console

    async def report(event: SecurityEvent) -> None:
        await sentinel.report(event)
        console.publish(session, event)

    return await SCENARIOS[name](sentinel.sandbox(), sentinel, report)


async def page(request: Request) -> Response:
    sentinel: Sentinel = request.app.state.sentinel
    response = HTMLResponse((STATIC / "console.html").read_text(encoding="utf-8"), headers=PAGE_HEADERS)
    session = request.cookies.get(SESSION_COOKIE) or secrets.token_urlsafe(24)
    response.set_cookie(
        SESSION_COOKIE,
        session,
        httponly=True,
        samesite="strict",
        secure=sentinel.settings.env == "production",
    )
    return response


async def events(request: Request) -> Response:
    session = request.cookies.get(SESSION_COOKIE)
    if not session:
        return Response("Open the console first.", status_code=400)
    console: Console = request.app.state.console
    queue = console.subscribe(session)

    async def stream() -> AsyncIterator[str]:
        try:
            yield ": connected\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield ": keep-alive\n\n"  # proxies close idle connections
                    continue
                yield f"data: {payload}\n\n"
        finally:
            console.unsubscribe(session, queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def install_console(app: FastAPI) -> None:
    app.state.console = Console()
    app.include_router(router)
    app.add_route("/", page, include_in_schema=False)
    app.add_route("/demo/events", events, include_in_schema=False)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
