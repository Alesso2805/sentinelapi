"""AR-07: every CounterBackend counts the same way (ADR-0002).

Windows here are one second long and the waits are real, so the same
tests run against Redis, whose clock cannot be faked.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import pkgutil

import sentinelapi.storage
from sentinelapi.storage.backend import CounterBackend

from .conftest import FACTORIES

PROTOCOL_METHODS = {"incr_with_expiry", "get", "set_if_absent", "reset"}


def test_every_backend_is_covered() -> None:
    implementations = set()
    for info in pkgutil.iter_modules(sentinelapi.storage.__path__, "sentinelapi.storage."):
        module = importlib.import_module(info.name)
        for name, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ == module.__name__ and name != "CounterBackend":
                if PROTOCOL_METHODS <= {n for n, _ in inspect.getmembers(cls, inspect.isfunction)}:
                    implementations.add(name)
    assert implementations == set(FACTORIES)


async def test_counts_within_a_window(backend: CounterBackend) -> None:
    assert [await backend.incr_with_expiry("k", 60) for _ in range(3)] == [1, 2, 3]
    assert await backend.get("k") == 3


async def test_unknown_keys_count_zero(backend: CounterBackend) -> None:
    assert await backend.get("never-seen") == 0


async def test_the_window_starts_with_the_first_hit_and_is_not_extended(backend: CounterBackend) -> None:
    assert await backend.incr_with_expiry("k", 1) == 1
    await asyncio.sleep(0.6)
    assert await backend.incr_with_expiry("k", 1) == 2
    await asyncio.sleep(0.6)
    # 1.2 s after the first hit: a fixed window has closed, whatever came in between.
    assert await backend.incr_with_expiry("k", 1) == 1


async def test_increments_are_atomic_under_concurrency(backend: CounterBackend) -> None:
    counts = await asyncio.gather(*(backend.incr_with_expiry("k", 60) for _ in range(50)))
    assert sorted(counts) == list(range(1, 51))


async def test_set_if_absent_succeeds_once(backend: CounterBackend) -> None:
    assert await backend.set_if_absent("jti", "a", 60) is True
    assert await backend.set_if_absent("jti", "b", 60) is False


async def test_set_if_absent_succeeds_again_after_its_ttl(backend: CounterBackend) -> None:
    assert await backend.set_if_absent("jti", "a", 1) is True
    await asyncio.sleep(1.2)
    assert await backend.set_if_absent("jti", "a", 1) is True


async def test_reset_clears_counters_and_values(backend: CounterBackend) -> None:
    await backend.incr_with_expiry("k", 60)
    await backend.set_if_absent("v", "x", 60)
    await backend.reset("k")
    await backend.reset("v")
    assert await backend.get("k") == 0
    assert await backend.set_if_absent("v", "x", 60) is True
