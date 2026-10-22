"""Redis implementation of CounterBackend, for production use.

Requires the `redis` package (redis-py's asyncio client, redis>=4.2).
It implements the same `CounterBackend` protocol as `InMemoryBackend`, so
the detectors don't know or care which one they're talking to, and
tests/contract runs the same suite against both.
"""

from __future__ import annotations

from redis.asyncio import Redis


class RedisBackend:
    """Atomic, multi-process-safe counters via Redis.

    Uses INCR + EXPIRE NX for fixed-window counters (ADR-0002: good enough
    for abuse detection, where the cost of occasionally under-counting at a
    window boundary is far lower than the cost of a stateful sliding log)
    and SET NX EX for the JWT-replay "have I seen this jti before" check.
    """

    def __init__(self, redis_url: str) -> None:
        self._redis: Redis = Redis.from_url(redis_url, decode_responses=True)

    async def incr_with_expiry(self, key: str, window_seconds: int) -> int:
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)  # only set TTL on first incr
            count, _ = await pipe.execute()
            return int(count)

    async def get(self, key: str) -> int:
        value = await self._redis.get(key)
        return int(value) if value is not None else 0

    async def set_if_absent(self, key: str, value: str, ttl_seconds: int) -> bool:
        result = await self._redis.set(key, value, nx=True, ex=ttl_seconds)
        return bool(result)

    async def reset(self, key: str) -> None:
        await self._redis.delete(key)

    async def close(self) -> None:
        await self._redis.aclose()
