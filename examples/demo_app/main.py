"""Run with: uvicorn examples.demo_app.main:app --reload
(from the repo root, with the package installed — see README).

The demo is SentinelAPI's first integrator, wired the way the README
tells any app to be:
- `install_sentinel` adds the rate limiter and the replay check to every
  request, and the audit trail;
- /auth/login calls `sentinel.login_guard` around its password check
  (see auth.py);
- GET /security/events shows the HIGH/CRITICAL events the audit kept.
"""

from __future__ import annotations

from typing import Annotated, cast

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sentinelapi.config import SentinelSettings
from sentinelapi.integration import Sentinel, install_sentinel
from sentinelapi.logging_config import configure_logging

from .auth import decode_token
from .auth import router as auth_router

_security = HTTPBearer()


def get_sentinel(request: Request) -> Sentinel:
    return cast(Sentinel, request.app.state.sentinel)


def create_app(settings: SentinelSettings | None = None) -> FastAPI:
    """Each call builds its own SentinelAPI, so tests can run against a
    fresh app with their own counters and their own database."""
    app = FastAPI(title="SentinelAPI demo")
    install_sentinel(app, settings)
    app.include_router(auth_router)

    @app.get("/me")
    async def me(
        creds: Annotated[HTTPAuthorizationCredentials, Depends(_security)],
        sentinel: Annotated[Sentinel, Depends(get_sentinel)],
    ) -> dict[str, str]:
        try:
            payload = decode_token(sentinel.settings, creds.credentials)
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid access token") from None
        return {"user": payload["sub"]}

    @app.get("/security/events")
    async def recent_security_events(
        sentinel: Annotated[Sentinel, Depends(get_sentinel)],
    ) -> list[dict[str, str]]:
        """Demo-only admin view — put real auth in front of this before
        shipping; it's here so you can *see* SentinelAPI working."""
        if sentinel.audit is None:
            return []
        return [
            {
                "threat_type": r.threat_type,
                "threat_level": r.threat_level,
                "path": r.path,
                "detail": r.detail,
                "occurred_at": r.occurred_at.isoformat(),
            }
            for r in await sentinel.audit.recent_critical(limit=50)
        ]

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


configure_logging(json_output=False)  # pretty console output for the demo; True in prod
app = create_app()
