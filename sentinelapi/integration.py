"""One call that wires SentinelAPI into a Starlette or FastAPI app (ADR-0007).

    app = FastAPI()
    sentinel = install_sentinel(app)

and, in the login endpoint, `await sentinel.login_guard.check(request, username)`
before the password check, then `.failed(...)` or `.succeeded(...)` after it.

This is the only module that constructs backends and detectors (AR-18), so
every detector of an app counts in the same backend and reports to the
same sinks.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any, NamedTuple

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request

from sentinelapi.audit.sink import DatabaseAuditSink
from sentinelapi.client_address import ClientResolver
from sentinelapi.clock import SYSTEM_CLOCK, Clock
from sentinelapi.config import SentinelSettings
from sentinelapi.detectors.brute_force import AccountAction, BruteForceDetector
from sentinelapi.detectors.jwt_replay import JWTReplayDetector
from sentinelapi.detectors.rate_limiter import RateLimiter
from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent
from sentinelapi.logging_config import log_event, security_logger
from sentinelapi.middleware import SentinelMiddleware
from sentinelapi.privacy import Pseudonymizer
from sentinelapi.storage.backend import CounterBackend
from sentinelapi.storage.memory_backend import InMemoryBackend

OnEvent = Callable[[SecurityEvent], Awaitable[None]]

LOGIN_BLOCKED = "Too many failed sign-in attempts. Try again later."


class LoginGuard:
    """What a login endpoint calls around its own password check (ADR-0003,
    ADR-0005). A blocked attempt raises a 429 with Retry-After and one fixed
    message, the same whether the account exists or not."""

    def __init__(self, sentinel: Sentinel) -> None:
        self._sentinel = sentinel

    async def check(self, request: Request, username: str) -> None:
        """Before the password: refuses a blocked source or a locked account,
        even if the password turns out to be right."""
        detector = self._sentinel.brute_force
        await self._refuse_if_blocking(
            await detector.check(self.fingerprint(request), username, request.url.path)
        )

    async def failed(self, request: Request, username: str) -> None:
        detector = self._sentinel.brute_force
        event = await detector.record_failure(self.fingerprint(request), username, request.url.path)
        await self._refuse_if_blocking(event)

    async def succeeded(self, request: Request, username: str) -> None:
        await self._sentinel.brute_force.record_success(self.fingerprint(request), username)

    def fingerprint(self, request: Request) -> RequestFingerprint:
        return self._sentinel.client_resolver.fingerprint(
            peer=request.client.host if request.client else None,
            forwarded_for=",".join(request.headers.getlist("x-forwarded-for")),
            user_agent=request.headers.get("user-agent", ""),
        )

    async def _refuse_if_blocking(self, event: SecurityEvent | None) -> None:
        if event is None:
            return
        await self._sentinel.report(event)
        if event.is_blocking() and self._sentinel.settings.enforce:
            retry_after = max(1, math.ceil(event.retry_after or 1))
            raise HTTPException(
                status_code=429, detail=LOGIN_BLOCKED, headers={"Retry-After": str(retry_after)}
            )


class Sentinel:
    """What `install_sentinel` returns: the pieces an app may need afterwards."""

    def __init__(self, settings: SentinelSettings, *, on_event: OnEvent | None, clock: Clock) -> None:
        self.settings = settings
        self.backend = _backend(settings, clock)
        self.client_resolver = ClientResolver(settings.trusted_proxies)
        self.rate_limiter, self.brute_force, self.jwt_replay = _detectors(settings, self.backend, clock)
        self._clock = clock
        self.pseudonymize = Pseudonymizer(settings.audit_hash_key)
        self.audit = (
            DatabaseAuditSink(
                settings.database_url,
                self.pseudonymize,
                aggregate_seconds=settings.audit_aggregate_seconds,
                max_groups=settings.audit_queue_size,
                clock=clock,
            )
            if settings.audit
            else None
        )
        self.login_guard = LoginGuard(self)
        self._on_event = on_event

    def sandbox(self) -> Sandbox:
        """Fresh detectors with this app's settings, on a memory backend of
        their own: for demonstrations that must not touch real clients'
        counters and must start the same way every time (ADR-0010)."""
        return Sandbox(*_detectors(self.settings, InMemoryBackend(clock=self._clock), self._clock))

    async def report(self, event: SecurityEvent) -> None:
        """Every event: the log line first, then the audit table, then the
        app's own `on_event`. A failing sink is logged and never stops the
        others, nor the request."""
        await log_event(event, self.pseudonymize)
        sinks = [s for s in (self.audit, self._on_event) if s is not None]
        for sink in sinks:
            try:
                await sink(event)
            except Exception:
                await security_logger.aexception("security_event_sink_failed", sink=type(sink).__name__)

    async def ready(self) -> dict[str, bool]:
        """What /ready reports: the counter backend answers, and the audit
        database is reachable and migrated. Each check gets two seconds."""
        checks = {"backend": _check(getattr(self.backend, "ping", None))}
        if self.audit is not None:
            checks["database"] = _check(self.audit.ready)
        results = await asyncio.gather(*checks.values())
        return dict(zip(checks, results, strict=True))

    async def start(self) -> None:
        if self.pseudonymize.ephemeral:
            await security_logger.awarning(
                "audit_hash_key_not_set",
                hint="set SENTINEL_AUDIT_HASH_KEY: without it, hashes change at every restart",
            )
        if self.audit is not None:
            await self.audit.start()

    async def close(self) -> None:
        if self.audit is not None:
            await self.audit.close()
        close = getattr(self.backend, "close", None)
        if close is not None:
            await close()


def install_sentinel(
    app: Starlette,
    settings: SentinelSettings | None = None,
    *,
    on_event: OnEvent | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> Sentinel:
    """Adds the middleware, starts and stops SentinelAPI with the app's
    lifespan, and leaves the result in `app.state.sentinel`."""
    sentinel = Sentinel(settings or SentinelSettings(), on_event=on_event, clock=clock)
    app.add_middleware(
        SentinelMiddleware,
        rate_limiter=sentinel.rate_limiter,
        jwt_replay_detector=sentinel.jwt_replay,
        jwt_replay_paths=sentinel.settings.jwt_replay_paths,
        enforce=sentinel.settings.enforce,
        on_event=sentinel.report,
        client_resolver=sentinel.client_resolver,
    )

    app_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: Any) -> AsyncIterator[Any]:
        await sentinel.start()
        try:
            async with app_lifespan(app) as state:
                yield state
        finally:
            await sentinel.close()

    app.router.lifespan_context = lifespan
    app.state.sentinel = sentinel
    return sentinel


class Sandbox(NamedTuple):
    rate_limiter: RateLimiter
    brute_force: BruteForceDetector
    jwt_replay: JWTReplayDetector


def _detectors(settings: SentinelSettings, backend: CounterBackend, clock: Clock) -> Sandbox:
    rate_limiter = RateLimiter(
        backend,
        max_requests=settings.rate_limit_max_requests,
        window_seconds=settings.rate_limit_window_seconds,
        warn_at=settings.rate_limit_warn_at,
        path_limits=settings.rate_limit_paths,
        exempt_paths=settings.rate_limit_exempt_paths,
        clock=clock,
    )
    brute_force = BruteForceDetector(
        backend,
        window_seconds=settings.brute_force_window_seconds,
        per_source_medium=settings.brute_force_per_source_medium,
        per_source_high=settings.brute_force_per_source_high,
        per_username_high=settings.brute_force_per_username_high,
        per_username_critical=settings.brute_force_per_username_critical,
        account_action=AccountAction(settings.brute_force_account_action),
        clock=clock,
    )
    jwt_replay = JWTReplayDetector(
        backend,
        secret=settings.jwt_secret,
        algorithms=settings.jwt_algorithms,
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        clock=clock,
    )
    return Sandbox(rate_limiter, brute_force, jwt_replay)


def _backend(settings: SentinelSettings, clock: Clock) -> CounterBackend:
    if settings.backend == "redis":
        from sentinelapi.storage.redis_backend import RedisBackend

        return RedisBackend(settings.redis_url)
    return InMemoryBackend(clock=clock)


async def _check(probe: Callable[[], Awaitable[bool]] | None) -> bool:
    if probe is None:
        return True
    try:
        return await asyncio.wait_for(probe(), timeout=2)
    except Exception:
        return False
