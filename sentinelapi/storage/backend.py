"""Abstract counter/cache backend.

Detectors never talk to Redis or a dict directly — they talk to this
Protocol. That's what lets `InMemoryBackend` run in tests and CI with zero
external services, while `RedisBackend` handles the real multi-process
production case, without a single line of detector code changing.
"""

from __future__ import annotations

from typing import Protocol


class CounterBackend(Protocol):
    """Fixed-window counter storage (ADR-0002).

    Every method is `async` so a Redis-backed implementation can await the
    network call; `InMemoryBackend` just doesn't need to.
    """

    async def incr_with_expiry(self, key: str, window_seconds: int) -> int:
        """Atomically increment `key`. The first increment starts a window of
        `window_seconds`; later increments do not extend it. Returns the new
        count."""
        ...

    async def get(self, key: str) -> int:
        """Current count for `key`, or 0 if absent/expired."""
        ...

    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool:
        """Set `key` to `value` only if it doesn't already exist.
        Returns True if the value was set (i.e. `key` was absent).
        This is the primitive JWT-replay detection is built on."""
        ...

    async def reset(self, key: str) -> None:
        """Clear a key immediately (e.g. after a successful login)."""
        ...
