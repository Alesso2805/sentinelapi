import unittest

from sentinelapi.storage.memory_backend import InMemoryBackend
from tests.fakes import FakeClock


class TestInMemoryBackend(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.clock = FakeClock()
        self.backend = InMemoryBackend(clock=self.clock)

    async def test_a_busy_key_still_resets_when_its_window_ends(self) -> None:
        counts = []
        for _ in range(31):
            counts.append(await self.backend.incr_with_expiry("k", 60))
            self.clock.advance(2)
        self.assertEqual(counts[:30], list(range(1, 31)))
        self.assertEqual(counts[30], 1)  # 60 s after the first hit: a new window

    async def test_values_expire_with_the_clock(self) -> None:
        self.assertTrue(await self.backend.set_if_absent("jti", "a", 10))
        self.clock.advance(9)
        self.assertFalse(await self.backend.set_if_absent("jti", "a", 10))
        self.clock.advance(2)
        self.assertTrue(await self.backend.set_if_absent("jti", "a", 10))

    async def test_expired_keys_are_evicted(self) -> None:
        for i in range(10_000):
            await self.backend.incr_with_expiry(f"rl:{i}", 1)
        self.clock.advance(2)
        await self.backend.incr_with_expiry("rl:new", 1)
        self.assertEqual(len(self.backend), 1)

    async def test_live_keys_are_capped(self) -> None:
        backend = InMemoryBackend(clock=self.clock, max_keys=100)
        for i in range(1_000):
            await backend.incr_with_expiry(f"rl:{i}", 3600)
            await backend.set_if_absent(f"jti:{i}", "x", 3600)
        self.assertLessEqual(len(backend), 100)
        # The newest keys survive; the ones closest to expiring went first.
        self.assertEqual(await backend.get("rl:999"), 1)


if __name__ == "__main__":
    unittest.main()
