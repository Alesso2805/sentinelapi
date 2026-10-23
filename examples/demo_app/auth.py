"""Demo login/refresh endpoints showing how an app wires into SentinelAPI.

Password hashing here is sha256+salt purely so this demo has zero extra
dependencies. Use passlib/bcrypt or argon2 for real password storage —
sha256 alone is not an acceptable password hash in production.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Annotated, Any, cast

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from sentinelapi.clock import SYSTEM_CLOCK
from sentinelapi.config import SentinelSettings
from sentinelapi.integration import Sentinel

router = APIRouter(prefix="/auth", tags=["auth"])

ACCESS_TOKEN_TTL_SECONDS = 15 * 60
REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60


def _hash_password(password: str, salt: str = "demo-salt") -> str:
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


_USERS = {
    "alice@example.com": _hash_password("correct-horse-battery-staple"),
}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str


def _issue_tokens(settings: SentinelSettings, username: str) -> TokenResponse:
    """Signed with SENTINEL_JWT_SECRET, the key the replay detector verifies with."""
    now = int(SYSTEM_CLOCK.now())
    claims: dict[str, Any] = {"sub": username}
    if settings.jwt_audience:
        claims["aud"] = settings.jwt_audience
    if settings.jwt_issuer:
        claims["iss"] = settings.jwt_issuer
    algorithm = settings.jwt_algorithms[0]
    access = jwt.encode(
        {**claims, "type": "access", "exp": now + ACCESS_TOKEN_TTL_SECONDS},
        settings.jwt_secret,
        algorithm=algorithm,
    )
    refresh = jwt.encode(
        {**claims, "type": "refresh", "jti": str(uuid.uuid4()), "exp": now + REFRESH_TOKEN_TTL_SECONDS},
        settings.jwt_secret,
        algorithm=algorithm,
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


def decode_token(settings: SentinelSettings, token: str) -> dict[str, Any]:
    payload: dict[str, Any] = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=list(settings.jwt_algorithms),
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    return payload


def get_sentinel(request: Request) -> Sentinel:
    return cast(Sentinel, request.app.state.sentinel)


def get_settings(request: Request) -> SentinelSettings:
    return get_sentinel(request).settings


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    sentinel: Annotated[Sentinel, Depends(get_sentinel)],
) -> TokenResponse:
    guard = sentinel.login_guard
    # Before the password: a blocked source or account stays blocked even
    # when the attacker finally guesses right (ADR-0005). Blocked → 429.
    await guard.check(request, payload.username)

    stored_hash = _USERS.get(payload.username)
    if stored_hash is None or stored_hash != _hash_password(payload.password):
        await guard.failed(request, payload.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    await guard.succeeded(request, payload.username)
    return _issue_tokens(sentinel.settings, payload.username)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request, settings: Annotated[SentinelSettings, Depends(get_settings)]
) -> TokenResponse:
    """No replay check here on purpose: SentinelMiddleware already ran
    JWTReplayDetector against this exact path (it's in jwt_replay_paths)
    before the request ever reached this handler. If we're executing this
    line, the token has already been proven single-use this request."""
    auth_header = request.headers.get("authorization", "")
    token = auth_header.split(" ", 1)[1] if auth_header.lower().startswith("bearer ") else ""

    try:
        payload = decode_token(settings, token)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from None

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    return _issue_tokens(settings, payload["sub"])
