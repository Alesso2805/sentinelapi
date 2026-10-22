"""Fixed-window rate limiting, scoped per fingerprint + path.

Deliberately simple: a true sliding-log limiter is more precise but needs
a sorted set per key. For abuse detection (as opposed to strict billing
enforcement) a fixed window with a short TTL catches the same bursts with
one INCR instead of a log of timestamps — a good trade-off for a backend
that has to stay cheap to run.
"""
from __future__ import annotations

from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.storage.backend import CounterBackend


class RateLimiter:
    def __init__(
        self,
        backend: CounterBackend,
        *,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self._backend = backend
        self._max_requests = max_requests
        self._window_seconds = window_seconds

    async def check(self, fingerprint: RequestFingerprint, path: str) -> SecurityEvent | None:
        key = f"rl:{fingerprint.key}:{path}"
        count = await self._backend.incr_with_expiry(key, self._window_seconds)

        if count <= self._max_requests:
            return None

        overshoot = count - self._max_requests
        level = ThreatLevel.HIGH if overshoot > self._max_requests else ThreatLevel.MEDIUM
        return SecurityEvent(
            threat_type=ThreatType.RATE_LIMIT_EXCEEDED,
            threat_level=level,
            fingerprint=fingerprint,
            path=path,
            detail=f"{count} requests in {self._window_seconds}s (limit {self._max_requests})",
        )
