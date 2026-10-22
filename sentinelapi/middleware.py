"""The FastAPI-facing adapter. Everything security-relevant it does is
delegated to the framework-agnostic detectors in `detectors/` — this file
is deliberately "thin": its only job is translating a Starlette Request
into the detectors' vocabulary (RequestFingerprint) and translating their
verdicts (SecurityEvent) back into HTTP responses + audit log writes.

Scope note: rate limiting and JWT-replay checks apply cleanly to *every*
request, so they live here in blanket middleware. Brute-force detection
needs to know whether a login attempt succeeded or failed — information
middleware doesn't have without parsing the response body, which is
fragile. So brute-force is intentionally NOT in this middleware; it's
exposed as `BruteForceDetector` for your login endpoint to call directly
(see examples/demo_app/auth.py for the pattern).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.detectors.jwt_replay import JWTReplayDetector
from sentinelapi.detectors.rate_limiter import RateLimiter
from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent
from sentinelapi.logging_config import security_logger

OnEvent = Callable[[SecurityEvent], Awaitable[None]]


class SentinelMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        rate_limiter: RateLimiter,
        jwt_replay_detector: JWTReplayDetector | None = None,
        jwt_replay_paths: tuple[str, ...] = (),
        enforce: bool = True,
        on_event: OnEvent | None = None,
    ) -> None:
        super().__init__(app)
        self._rate_limiter = rate_limiter
        self._jwt_replay_detector = jwt_replay_detector
        self._jwt_replay_paths = set(jwt_replay_paths)
        self._enforce = enforce
        self._on_event = on_event

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        fingerprint = build_fingerprint(
            ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
        )

        blocking_response = await self._check_rate_limit(request, fingerprint)
        if blocking_response is not None:
            return blocking_response

        if request.url.path in self._jwt_replay_paths and self._jwt_replay_detector is not None:
            blocking_response = await self._check_jwt_replay(request, fingerprint)
            if blocking_response is not None:
                return blocking_response

        return await call_next(request)

    async def _check_rate_limit(self, request: Request, fingerprint: RequestFingerprint) -> Response | None:
        event = await self._rate_limiter.check(fingerprint, request.url.path)
        return await self._handle_event(event)

    async def _check_jwt_replay(self, request: Request, fingerprint: RequestFingerprint) -> Response | None:
        detector = self._jwt_replay_detector
        auth_header = request.headers.get("authorization", "")
        if detector is None or not auth_header.lower().startswith("bearer "):
            return None  # no token to check; let the normal auth dependency reject it
        token = auth_header.split(" ", 1)[1]

        event = await detector.check(token, fingerprint, request.url.path)
        return await self._handle_event(event)

    async def _handle_event(self, event: SecurityEvent | None) -> Response | None:
        if event is None:
            return None

        await security_logger.awarning(
            "security_event",
            threat_type=event.threat_type.value,
            threat_level=event.threat_level.value,
            path=event.path,
            fingerprint=event.fingerprint.key,
            detail=event.detail,
        )
        if self._on_event is not None:
            await self._on_event(event)

        if self._enforce and event.is_blocking():
            status_code = 429 if event.threat_type.value == "rate_limit_exceeded" else 403
            return JSONResponse(
                status_code=status_code,
                content={"detail": "Request blocked by SentinelAPI", "reason": event.threat_type.value},
            )
        return None
