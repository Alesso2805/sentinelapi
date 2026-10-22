"""The ASGI-facing adapter. Everything security-relevant it does is
delegated to the framework-agnostic detectors in `detectors/` — this file
is deliberately "thin": its only job is translating an ASGI scope into
the detectors' vocabulary (RequestFingerprint) and translating their
verdicts (SecurityEvent) back into HTTP responses and reported events.

It is a pure ASGI middleware (ADR-0007): it reads only the scope (path,
headers, client), never the body, and passes `receive` and `send` through
untouched, so streaming responses, background tasks and context variables
behave exactly as they would without it.

Scope note: rate limiting and JWT-replay checks apply cleanly to *every*
request, so they live here in blanket middleware. Brute-force detection
needs to know whether a login attempt succeeded or failed — information
middleware doesn't have without parsing the response body, which is
fragile. So brute-force is intentionally NOT in this middleware; it's
exposed as `LoginGuard` (see integration.py) for your login endpoint to
call directly.
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable

from starlette.datastructures import Headers
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from sentinelapi.client_address import ClientResolver
from sentinelapi.detectors.jwt_replay import JWTReplayDetector
from sentinelapi.detectors.rate_limiter import RateLimiter
from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent, ThreatType
from sentinelapi.logging_config import log_event, security_logger

OnEvent = Callable[[SecurityEvent], Awaitable[None]]


class SentinelMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        rate_limiter: RateLimiter,
        jwt_replay_detector: JWTReplayDetector | None = None,
        jwt_replay_paths: tuple[str, ...] = (),
        enforce: bool = True,
        on_event: OnEvent = log_event,
        client_resolver: ClientResolver | None = None,
    ) -> None:
        self._app = app
        self._rate_limiter = rate_limiter
        self._jwt_replay_detector = jwt_replay_detector
        self._jwt_replay_paths = set(jwt_replay_paths)
        self._enforce = enforce
        self._on_event = on_event
        self._client_resolver = client_resolver or ClientResolver()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        client = scope.get("client")
        fingerprint = self._client_resolver.fingerprint(
            peer=client[0] if client else None,
            forwarded_for=",".join(headers.getlist("x-forwarded-for")),
            user_agent=headers.get("user-agent", ""),
        )
        path: str = scope["path"]

        blocking_response = await self._handle(await self._rate_limiter.check(fingerprint, path))
        if blocking_response is None and path in self._jwt_replay_paths:
            blocking_response = await self._check_jwt_replay(headers, fingerprint, path)

        if blocking_response is not None:
            await blocking_response(scope, receive, send)
            return
        await self._app(scope, receive, send)

    async def _check_jwt_replay(
        self, headers: Headers, fingerprint: RequestFingerprint, path: str
    ) -> Response | None:
        detector = self._jwt_replay_detector
        auth_header = headers.get("authorization", "")
        if detector is None or not auth_header.lower().startswith("bearer "):
            return None  # no token to check; let the normal auth dependency reject it
        token = auth_header.split(" ", 1)[1]
        return await self._handle(await detector.check(token, fingerprint, path))

    async def _handle(self, event: SecurityEvent | None) -> Response | None:
        if event is None:
            return None
        try:
            await self._on_event(event)
        except Exception:
            # Reporting must never decide a request: the verdict below stands either way.
            await security_logger.aexception(
                "security_event_report_failed", threat_type=event.threat_type.value
            )

        if not (self._enforce and event.is_blocking()):
            return None
        rate_limited = event.threat_type is ThreatType.RATE_LIMIT_EXCEEDED
        headers = {}
        if event.retry_after is not None:
            headers["Retry-After"] = str(max(1, math.ceil(event.retry_after)))
        return JSONResponse(
            status_code=429 if rate_limited else 403,
            content={"detail": "Request blocked by SentinelAPI", "reason": event.threat_type.value},
            headers=headers,
        )
