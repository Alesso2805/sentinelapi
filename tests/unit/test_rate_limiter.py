import unittest

from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.detectors.rate_limiter import RateLimiter
from sentinelapi.domain.entities import ThreatLevel, ThreatType
from sentinelapi.storage.memory_backend import InMemoryBackend
from tests.fakes import FakeClock


class TestRateLimiter(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.backend = InMemoryBackend()
        self.fp = build_fingerprint("203.0.113.7", "pytest-agent")

    async def test_requests_under_limit_pass_silently(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=5, window_seconds=60)
        for _ in range(5):
            event = await limiter.check(self.fp, "/api/widgets")
            self.assertIsNone(event)

    async def test_exceeding_limit_raises_medium_event(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=3, window_seconds=60)
        for _ in range(3):
            self.assertIsNone(await limiter.check(self.fp, "/api/widgets"))

        event = await limiter.check(self.fp, "/api/widgets")
        assert event is not None
        self.assertEqual(event.threat_type, ThreatType.RATE_LIMIT_EXCEEDED)
        self.assertEqual(event.threat_level, ThreatLevel.MEDIUM)

    async def test_severe_overshoot_escalates_to_high(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=3, window_seconds=60)
        event = None
        for _ in range(10):
            event = await limiter.check(self.fp, "/api/widgets")
        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.HIGH)

    async def test_limits_are_isolated_per_path(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=2, window_seconds=60)
        await limiter.check(self.fp, "/api/widgets")
        await limiter.check(self.fp, "/api/widgets")
        event_a = await limiter.check(self.fp, "/api/widgets")
        event_b = await limiter.check(self.fp, "/api/gadgets")

        assert event_a is not None  # third hit on /widgets: over the limit
        self.assertIsNone(event_b)  # first hit on /gadgets: fresh counter

    async def test_limits_are_isolated_per_fingerprint(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=1, window_seconds=60)
        other_fp = build_fingerprint("198.51.100.9", "pytest-agent")

        self.assertIsNone(await limiter.check(self.fp, "/api/widgets"))
        self.assertIsNone(await limiter.check(other_fp, "/api/widgets"))

    async def test_a_client_under_its_limit_is_never_blocked(self) -> None:
        """The audit's probe 1: one request every 2 s against 60 per 60 s,
        half the allowed rate, used to be blocked after 4 minutes."""
        clock = FakeClock()
        limiter = RateLimiter(InMemoryBackend(clock=clock), max_requests=60, window_seconds=60)
        events = []
        for _ in range(600):  # 20 minutes
            events.append(await limiter.check(self.fp, "/api/widgets"))
            clock.advance(2)
        self.assertEqual([e for e in events if e is not None], [])


if __name__ == "__main__":
    unittest.main()
