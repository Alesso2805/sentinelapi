"""Run with: uvicorn examples.demo_app.main:app --reload
(from the repo root, with the package installed — see README).

This wires every SentinelAPI piece into one small, runnable app:
- RateLimiter + JWTReplayDetector via SentinelMiddleware (blanket coverage)
- BruteForceDetector called explicitly from /auth/login (see auth.py)
- Every event persisted to the audit DB; the HIGH/CRITICAL ones are
  viewable at GET /security/events
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sentinelapi.audit.db import create_engine_and_sessionmaker, init_models, session_scope
from sentinelapi.audit.repository import SecurityEventRepository
from sentinelapi.client_address import ClientResolver
from sentinelapi.config import SentinelSettings
from sentinelapi.detectors.brute_force import AccountAction, BruteForceDetector
from sentinelapi.detectors.jwt_replay import JWTReplayDetector
from sentinelapi.detectors.rate_limiter import RateLimiter
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.logging_config import configure_logging
from sentinelapi.middleware import SentinelMiddleware
from sentinelapi.storage.backend import CounterBackend
from sentinelapi.storage.memory_backend import InMemoryBackend

from .auth import JWT_SECRET
from .auth import router as auth_router

_security = HTTPBearer()


def create_app(settings: SentinelSettings | None = None) -> FastAPI:
    """Each call builds its own backend, detectors and audit engine, so
    tests can run against a fresh app with their own database."""
    settings = settings or SentinelSettings()
    engine, session_factory = create_engine_and_sessionmaker(settings.database_url)

    async def persist_event(event: SecurityEvent) -> None:
        async with session_scope(session_factory) as session:
            await SecurityEventRepository(session).add(event)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await init_models(engine)
        yield
        await engine.dispose()

    app = FastAPI(title="SentinelAPI demo", lifespan=lifespan)

    # --- Wiring: backend choice is driven by SENTINEL_BACKEND. "memory" needs
    # nothing else running (what you get with a plain `uvicorn` run); "redis"
    # is what docker-compose sets, since in-memory counts don't cross the
    # process boundary the moment you run more than one worker.
    backend: CounterBackend
    if settings.backend == "redis":
        from sentinelapi.storage.redis_backend import RedisBackend

        backend = RedisBackend(settings.redis_url)
    else:
        backend = InMemoryBackend()

    rate_limiter = RateLimiter(
        backend,
        max_requests=settings.rate_limit_max_requests,
        window_seconds=settings.rate_limit_window_seconds,
        warn_at=settings.rate_limit_warn_at,
        path_limits=settings.rate_limit_paths,
        exempt_paths=settings.rate_limit_exempt_paths,
    )
    brute_force_detector = BruteForceDetector(
        backend,
        window_seconds=settings.brute_force_window_seconds,
        per_source_medium=settings.brute_force_per_source_medium,
        per_source_high=settings.brute_force_per_source_high,
        per_username_high=settings.brute_force_per_username_high,
        per_username_critical=settings.brute_force_per_username_critical,
        account_action=AccountAction(settings.brute_force_account_action),
    )
    jwt_replay_detector = JWTReplayDetector(backend, secret=JWT_SECRET)
    client_resolver = ClientResolver(settings.trusted_proxies)

    app.state.brute_force_detector = brute_force_detector
    app.state.client_resolver = client_resolver
    app.state.persist_event = persist_event

    app.add_middleware(
        SentinelMiddleware,
        rate_limiter=rate_limiter,
        jwt_replay_detector=jwt_replay_detector,
        jwt_replay_paths=settings.jwt_replay_paths,
        enforce=settings.enforce,
        on_event=persist_event,
        client_resolver=client_resolver,
    )

    app.include_router(auth_router)

    @app.get("/me")
    async def me(creds: Annotated[HTTPAuthorizationCredentials, Depends(_security)]) -> dict[str, str]:
        try:
            payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid access token") from None
        return {"user": payload["sub"]}

    @app.get("/security/events")
    async def recent_security_events() -> list[dict[str, str | float]]:
        """Demo-only admin view — put real auth in front of this before
        shipping; it's here so you can *see* SentinelAPI working."""
        async with session_scope(session_factory) as session:
            rows = await SecurityEventRepository(session).recent_critical(limit=50)
            return [
                {
                    "threat_type": r.threat_type,
                    "threat_level": r.threat_level,
                    "path": r.path,
                    "detail": r.detail,
                    "occurred_at": r.occurred_at,
                }
                for r in rows
            ]

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


configure_logging(json_output=False)  # pretty console output for the demo; True in prod
app = create_app()
