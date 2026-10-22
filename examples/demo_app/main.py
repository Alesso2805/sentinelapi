"""Run with: uvicorn examples.demo_app.main:app --reload
(from the repo root, with the package installed — see README).

This wires every SentinelAPI piece into one small, runnable app:
- RateLimiter + JWTReplayDetector via SentinelMiddleware (blanket coverage)
- BruteForceDetector called explicitly from /auth/login (see auth.py)
- Every HIGH/CRITICAL event persisted to the audit DB and viewable at
  GET /security/events
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sentinelapi.audit.db import create_engine_and_sessionmaker, init_models, session_scope
from sentinelapi.audit.repository import SecurityEventRepository
from sentinelapi.config import SentinelSettings
from sentinelapi.detectors.brute_force import BruteForceDetector
from sentinelapi.detectors.jwt_replay import JWTReplayDetector
from sentinelapi.detectors.rate_limiter import RateLimiter
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.logging_config import configure_logging
from sentinelapi.middleware import SentinelMiddleware
from sentinelapi.storage.memory_backend import InMemoryBackend

from .auth import JWT_SECRET
from .auth import router as auth_router

settings = SentinelSettings()
configure_logging(json_output=False)  # pretty console output for the demo; True in prod

engine, session_factory = create_engine_and_sessionmaker(settings.database_url)


async def persist_event(event: SecurityEvent) -> None:
    async with session_scope(session_factory) as session:
        await SecurityEventRepository(session).add(event)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models(engine)
    yield
    await engine.dispose()


app = FastAPI(title="SentinelAPI demo", lifespan=lifespan)

# --- Wiring: backend choice is driven by SENTINEL_BACKEND. "memory" needs
# nothing else running (what you get with a plain `uvicorn` run); "redis"
# is what docker-compose sets, since in-memory counts don't cross the
# process boundary the moment you run more than one worker.
if settings.backend == "redis":
    from sentinelapi.storage.redis_backend import RedisBackend

    backend = RedisBackend(settings.redis_url)
else:
    backend = InMemoryBackend()

rate_limiter = RateLimiter(
    backend,
    max_requests=settings.rate_limit_max_requests,
    window_seconds=settings.rate_limit_window_seconds,
)
brute_force_detector = BruteForceDetector(
    backend,
    window_seconds=settings.brute_force_window_seconds,
    per_fingerprint_medium=settings.brute_force_per_fingerprint_medium,
    per_fingerprint_high=settings.brute_force_per_fingerprint_high,
    per_username_high=settings.brute_force_per_username_high,
    per_username_critical=settings.brute_force_per_username_critical,
)
jwt_replay_detector = JWTReplayDetector(backend, secret=JWT_SECRET)

app.state.brute_force_detector = brute_force_detector
app.state.persist_event = persist_event

app.add_middleware(
    SentinelMiddleware,
    rate_limiter=rate_limiter,
    jwt_replay_detector=jwt_replay_detector,
    jwt_replay_paths=settings.jwt_replay_paths,
    enforce=settings.enforce,
    on_event=persist_event,
)

app.include_router(auth_router)

_security = HTTPBearer()


@app.get("/me")
async def me(creds: HTTPAuthorizationCredentials = Depends(_security)) -> dict:
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid access token") from None
    return {"user": payload["sub"]}


@app.get("/security/events")
async def recent_security_events() -> list[dict]:
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
async def health() -> dict:
    return {"status": "ok"}
