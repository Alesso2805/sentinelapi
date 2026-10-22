"""In-process implementation of CounterBackend.

No external services required. This is what the test suite and the demo
app use by default. Swap in `RedisBackend` (see redis_backend.py) for any
deployment with more than one worker process, since counts here don't
cross process boundaries.
"""
from __future__ import annotations

import asyncio
import time


class InMemoryBackend:
    """Thread-/task-safe counter store backed by a plain dict + asyncio.Lock."""

    def __init__(self) -> None:
        self._counters: dict[str, tuple[int, float]] = {}  # key -> (count, expires_at)
        self._values: dict[str, tuple[str, float]] = {}  # key -> (value, expires_at)
        self._lock = asyncio.Lock()

    async def incr_with_expiry(self, key: str, window_seconds: int) -> int:
        async with self._lock:
            now = time.monotonic()
            count, expires_at = self._counters.get(key, (0, 0.0))
            if now >= expires_at:
                count = 0
            count += 1
            self._counters[key] = (count, now + window_seconds)
            return count

    async def get(self, key: str) -> int:
        async with self._lock:
            now = time.monotonic()
            count, expires_at = self._counters.get(key, (0, 0.0))
            if now >= expires_at:
                return 0
            return count

    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool:
        async with self._lock:
            now = time.monotonic()
            existing = self._values.get(key)
            if existing is not None and now < existing[1]:
                return False
            self._values[key] = (value, now + ttl_seconds)
            return True

    async def reset(self, key: str) -> None:
        async with self._lock:
            self._counters.pop(key, None)
            self._values.pop(key, None)
