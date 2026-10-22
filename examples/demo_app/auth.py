"""Demo login/refresh endpoints showing how an app wires into SentinelAPI.

Password hashing here is sha256+salt purely so this demo has zero extra
dependencies. Use passlib/bcrypt or argon2 for real password storage —
sha256 alone is not an acceptable password hash in production.
"""

from __future__ import annotations

import hashlib
import math
import time
import uuid
from typing import Annotated, cast

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from sentinelapi.client_address import ClientResolver
from sentinelapi.detectors.brute_force import BruteForceDetector
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.logging_config import security_logger

router = APIRouter(prefix="/auth", tags=["auth"])

JWT_SECRET = "change-me"  # override via SentinelSettings.jwt_secret / env in real use
ACCESS_TOKEN_TTL_SECONDS = 15 * 60
REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60


def _hash_password(password: str, salt: str = "demo-salt") -> str:
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


# Demo-only in-memory user store.
_USERS = {
    "alice@example.com": _hash_password("correct-horse-battery-staple"),
}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str


def _issue_tokens(username: str) -> TokenResponse:
    now = int(time.time())
    access = jwt.encode(
        {"sub": username, "type": "access", "exp": now + ACCESS_TOKEN_TTL_SECONDS},
        JWT_SECRET,
        algorithm="HS256",
    )
    refresh = jwt.encode(
        {
            "sub": username,
            "type": "refresh",
            "jti": str(uuid.uuid4()),
            "exp": now + REFRESH_TOKEN_TTL_SECONDS,
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


def get_brute_force_detector(request: Request) -> BruteForceDetector:
    return cast(BruteForceDetector, request.app.state.brute_force_detector)


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    detector: Annotated[BruteForceDetector, Depends(get_brute_force_detector)],
) -> TokenResponse:
    resolver = cast(ClientResolver, request.app.state.client_resolver)
    fingerprint = resolver.fingerprint(
        peer=request.client.host if request.client else None,
        forwarded_for=",".join(request.headers.getlist("x-forwarded-for")),
        user_agent=request.headers.get("user-agent", ""),
    )

    # Before the password: a blocked source or account stays blocked even
    # when the attacker finally guesses right (ADR-0005).
    await _refuse_if_blocking(
        request, await detector.check(fingerprint, payload.username, path="/auth/login")
    )

    stored_hash = _USERS.get(payload.username)
    if stored_hash is None or stored_hash != _hash_password(payload.password):
        event = await detector.record_failure(fingerprint, payload.username, path="/auth/login")
        await _refuse_if_blocking(request, event)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    await detector.record_success(fingerprint, payload.username)
    return _issue_tokens(payload.username)


async def _refuse_if_blocking(request: Request, event: SecurityEvent | None) -> None:
    if event is None:
        return
    await security_logger.awarning(
        "security_event",
        threat_type=event.threat_type.value,
        threat_level=event.threat_level.value,
        path=event.path,
        fingerprint=event.fingerprint.key,
        detail=event.detail,
    )
    await request.app.state.persist_event(event)
    if event.is_blocking():
        # The same answer whether the account exists or not, with nothing an
        # attacker could use: no count, no username, no axis.
        retry_after = max(1, math.ceil(event.retry_after or 1))
        raise HTTPException(
            status_code=429,
            detail="Too many failed sign-in attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request) -> TokenResponse:
    """No replay check here on purpose: SentinelMiddleware already ran
    JWTReplayDetector against this exact path (it's in jwt_replay_paths)
    before the request ever reached this handler. If we're executing this
    line, the token has already been proven single-use this request."""
    auth_header = request.headers.get("authorization", "")
    token = auth_header.split(" ", 1)[1] if auth_header.lower().startswith("bearer ") else ""

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from None

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    return _issue_tokens(payload["sub"])
