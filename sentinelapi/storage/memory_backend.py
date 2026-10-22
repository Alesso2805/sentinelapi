"""In-process implementation of CounterBackend.

No external services required. This is what the test suite and the demo
app use by default. Swap in `RedisBackend` (see redis_backend.py) for any
deployment with more than one worker process, since counts here don't
cross process boundaries.
"""

from __future__ import annotations

import asyncio
import heapq

from sentinelapi.clock import SYSTEM_CLOCK, Clock

# Expired keys are swept at most this often, so memory follows the keys
# that are still live, not every client and path ever seen.
SWEEP_INTERVAL_SECONDS = 1.0


class InMemoryBackend:
    """Counter store backed by a plain dict. The asyncio.Lock makes it safe
    across the tasks of one event loop, not across threads or processes."""

    def __init__(self, *, clock: Clock = SYSTEM_CLOCK, max_keys: int = 100_000) -> None:
        self._clock = clock
        self._max_keys = max_keys
        self._counters: dict[str, tuple[int, float]] = {}  # key -> (count, expires_at)
        self._values: dict[str, tuple[str, float]] = {}  # key -> (value, expires_at)
        self._lock = asyncio.Lock()
        self._last_sweep = clock.monotonic()

    def __len__(self) -> int:
        return len(self._counters) + len(self._values)

    async def incr_with_expiry(self, key: str, window_seconds: int) -> int:
        async with self._lock:
            now = self._before_write()
            count, expires_at = self._counters.get(key, (0, 0.0))
            if now >= expires_at:
                # ADR-0002: the first hit opens the window; later hits never extend it.
                count, expires_at = 0, now + window_seconds
            self._counters[key] = (count + 1, expires_at)
            return count + 1

    async def get(self, key: str) -> int:
        async with self._lock:
            count, expires_at = self._counters.get(key, (0, 0.0))
            return count if self._clock.monotonic() < expires_at else 0

    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool:
        async with self._lock:
            now = self._before_write()
            existing = self._values.get(key)
            if existing is not None and now < existing[1]:
                return False
            self._values[key] = (value, now + ttl_seconds)
            return True

    async def reset(self, key: str) -> None:
        async with self._lock:
            self._counters.pop(key, None)
            self._values.pop(key, None)

    def _before_write(self) -> float:
        now = self._clock.monotonic()
        if now - self._last_sweep >= SWEEP_INTERVAL_SECONDS or len(self) >= self._max_keys:
            self._sweep(now)
        return now

    def _sweep(self, now: float) -> None:
        self._last_sweep = now
        for store in (self._counters, self._values):
            for key in [k for k, (_, expires_at) in store.items() if expires_at <= now]:
                del store[key]
        # Still full of live keys: drop the ones closest to expiring, which
        # matter least. A tenth of the room at once, so a flood of new keys
        # pays for one sweep per batch, not one per write.
        if len(self) >= self._max_keys:
            excess = len(self) - self._max_keys + max(1, self._max_keys // 10)
            live = [(e, k, "c") for k, (_, e) in self._counters.items()]
            live += [(e, k, "v") for k, (_, e) in self._values.items()]
            for _, key, kind in heapq.nsmallest(excess, live):
                (self._counters if kind == "c" else self._values).pop(key, None)
