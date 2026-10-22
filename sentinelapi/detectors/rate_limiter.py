"""Fixed-window rate limiting per client, plus stricter limits per path prefix.

Deliberately simple: a true sliding-log limiter is more precise but needs
a sorted set per key. For abuse detection (as opposed to strict billing
enforcement) a fixed window with a short TTL catches the same bursts with
one INCR instead of a log of timestamps — a good trade-off for a backend
that has to stay cheap to run.

Every request counts against the client's one counter, whatever its path:
counting per path would hand a client a fresh budget for every URL it
can invent. A configured prefix such as `/auth/` adds a second, stricter
counter for the paths under it.
"""

from __future__ import annotations

import math
from collections.abc import Collection, Mapping

from sentinelapi.clock import SYSTEM_CLOCK, Clock
from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.storage.backend import CounterBackend


def default_warn_at(limit: int) -> int:
    return math.ceil(limit * 0.8)


class RateLimiter:
    def __init__(
        self,
        backend: CounterBackend,
        *,
        max_requests: int = 60,
        window_seconds: int = 60,
        warn_at: int | None = None,
        path_limits: Mapping[str, int] | None = None,
        exempt_paths: Collection[str] = (),
        clock: Clock = SYSTEM_CLOCK,
    ) -> None:
        self._backend = backend
        self._clock = clock
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._warn_at = warn_at if warn_at is not None else default_warn_at(max_requests)
        # Longest prefix first, so `/auth/admin/` wins over `/auth/`.
        self._path_limits = sorted((path_limits or {}).items(), key=lambda item: -len(item[0]))
        self._exempt_paths = frozenset(exempt_paths)

    async def check(self, fingerprint: RequestFingerprint, path: str) -> SecurityEvent | None:
        if path in self._exempt_paths:
            return None
        events = [await self._count(fingerprint, path, None, self._max_requests, self._warn_at)]
        prefix = next((p for p, _ in self._path_limits if path.startswith(p)), None)
        if prefix is not None:
            limit = dict(self._path_limits)[prefix]
            events.append(await self._count(fingerprint, path, prefix, limit, default_warn_at(limit)))
        # The verdict that matters most: a block over a warning, then the longest wait.
        found = [e for e in events if e is not None]
        return max(found, key=lambda e: (e.is_blocking(), e.retry_after or 0.0), default=None)

    async def _count(
        self, fingerprint: RequestFingerprint, path: str, prefix: str | None, limit: int, warn_at: int
    ) -> SecurityEvent | None:
        key = f"rl:{fingerprint.client}" if prefix is None else f"rl:{fingerprint.client}:{prefix}"
        count = await self._backend.incr_with_expiry(key, self._window_seconds)
        scope = f"under {prefix}" if prefix is not None else "per client"
        if count > limit:
            return SecurityEvent(
                threat_type=ThreatType.RATE_LIMIT_EXCEEDED,
                threat_level=ThreatLevel.HIGH,
                fingerprint=fingerprint,
                path=path,
                occurred_at=self._clock.now(),
                detail=f"{count} requests in {self._window_seconds}s (limit {limit} {scope})",
                retry_after=await self._backend.ttl(key),
            )
        # Once per window, when the count first crosses the warning threshold.
        if count == warn_at + 1:
            return SecurityEvent(
                threat_type=ThreatType.RATE_LIMIT_EXCEEDED,
                threat_level=ThreatLevel.MEDIUM,
                fingerprint=fingerprint,
                path=path,
                occurred_at=self._clock.now(),
                detail=f"{count} requests in {self._window_seconds}s, near the limit of {limit} {scope}",
            )
        return None
