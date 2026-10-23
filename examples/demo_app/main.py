"""Run with: uvicorn examples.demo_app.main:app --reload
(from the repo root, with the package installed — see README).

The demo is SentinelAPI's first integrator, wired the way the README
tells any app to be:
- `install_sentinel` adds the rate limiter and the replay check to every
  request, and the audit trail;
- /auth/login calls `sentinel.login_guard` around its password check
  (see auth.py);
- GET /security/events lets an operator, and nobody else, read the
  audit trail.
"""

from __future__ import annotations

import hmac
from datetime import datetime
from importlib.metadata import version
from typing import Annotated, cast

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from sentinelapi.audit.models import SecurityEventLog
from sentinelapi.config import SentinelSettings
from sentinelapi.domain.entities import ThreatLevel, ThreatType
from sentinelapi.integration import Sentinel, install_sentinel
from sentinelapi.logging_config import configure_logging

from .auth import decode_token
from .auth import router as auth_router
from .console import install_console

_security = HTTPBearer()


class Health(BaseModel):
    status: str


class Readiness(BaseModel):
    status: str
    checks: dict[str, str]


class Me(BaseModel):
    user: str


class Event(BaseModel):
    """One audit row. The hashes are keyed (ADR-0006): they let an
    operator correlate events without holding an address or an account."""

    threat_type: ThreatType
    threat_level: ThreatLevel
    path: str
    detail: str
    count: int
    occurred_at: datetime
    last_occurred_at: datetime
    fingerprint_key: str
    client_hash: str | None
    subject_hash: str | None

    @classmethod
    def of(cls, row: SecurityEventLog) -> Event:
        return cls.model_validate(row, from_attributes=True)


class EventPage(BaseModel):
    total: int
    items: list[Event]


def get_sentinel(request: Request) -> Sentinel:
    return cast(Sentinel, request.app.state.sentinel)


def require_operator(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(_security)],
    sentinel: Annotated[Sentinel, Depends(get_sentinel)],
) -> None:
    expected = sentinel.settings.operator_token
    if not expected or not hmac.compare_digest(creds.credentials.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Operator token required")


def create_app(settings: SentinelSettings | None = None) -> FastAPI:
    """Each call builds its own SentinelAPI, so tests can run against a
    fresh app with their own counters and their own database."""
    settings = settings or SentinelSettings()
    # JSON lines in production, for a log aggregator; readable ones on a laptop.
    configure_logging(json_output=settings.env == "production")
    app = FastAPI(title="SentinelAPI demo", version=version("sentinelapi"))
    install_sentinel(app, settings)
    app.include_router(auth_router)
    if settings.demo_mode:
        install_console(app)

    @app.get("/me", response_model=Me)
    async def me(
        creds: Annotated[HTTPAuthorizationCredentials, Depends(_security)],
        sentinel: Annotated[Sentinel, Depends(get_sentinel)],
    ) -> Me:
        try:
            payload = decode_token(sentinel.settings, creds.credentials)
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid access token") from None
        return Me(user=payload["sub"])

    @app.get("/security/events", response_model=EventPage, dependencies=[Depends(require_operator)])
    async def security_events(
        sentinel: Annotated[Sentinel, Depends(get_sentinel)],
        threat_type: ThreatType | None = None,
        threat_level: ThreatLevel | None = None,
        since: datetime | None = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> EventPage:
        if sentinel.audit is None:
            return EventPage(total=0, items=[])
        # The sink writes in the background (ADR-0006); a demo shows what just happened.
        await sentinel.audit.flush(everything=True)
        rows, total = await sentinel.audit.search(
            threat_type=threat_type.value if threat_type else None,
            threat_level=threat_level.value if threat_level else None,
            since=since,
            offset=offset,
            limit=limit,
        )
        return EventPage(total=total, items=[Event.of(row) for row in rows])

    @app.get("/health", response_model=Health)
    async def health() -> Health:
        """Liveness: the process answers. Never rate limited."""
        return Health(status="ok")

    @app.get("/ready", response_model=Readiness, responses={503: {"model": Readiness}})
    async def ready(sentinel: Annotated[Sentinel, Depends(get_sentinel)], response: Response) -> Readiness:
        """Readiness: Redis answers and the audit database is reachable and migrated (SEN-30)."""
        checks = await sentinel.ready()
        if not all(checks.values()):
            response.status_code = 503
        return Readiness(
            status="ready" if all(checks.values()) else "unavailable",
            checks={name: "ok" if ok else "failing" for name, ok in checks.items()},
        )

    return app


app = create_app()
