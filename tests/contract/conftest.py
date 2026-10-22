from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest

from sentinelapi.storage.backend import CounterBackend
from sentinelapi.storage.memory_backend import InMemoryBackend


async def _memory() -> tuple[CounterBackend, Callable[[], Awaitable[None]]]:
    async def close() -> None:
        return None

    return InMemoryBackend(), close


async def _redis() -> tuple[CounterBackend, Callable[[], Awaitable[None]]]:
    url = os.environ.get("SENTINEL_TEST_REDIS_URL")
    if not url:
        pytest.skip("SENTINEL_TEST_REDIS_URL is not set (CI sets it)")
    from redis.asyncio import Redis

    from sentinelapi.storage.redis_backend import RedisBackend

    # A database of its own, emptied before each test.
    await Redis.from_url(url).flushdb()
    backend = RedisBackend(url)
    return backend, backend.close


# One factory per CounterBackend implementation; test_every_backend_is_covered
# fails when a new implementation has none.
FACTORIES: dict[str, Callable[[], Awaitable[tuple[CounterBackend, Callable[[], Awaitable[None]]]]]] = {
    "InMemoryBackend": _memory,
    "RedisBackend": _redis,
}


@pytest.fixture(params=sorted(FACTORIES))
async def backend(request: pytest.FixtureRequest) -> AsyncIterator[CounterBackend]:
    instance, close = await FACTORIES[request.param]()
    yield instance
    await close()
