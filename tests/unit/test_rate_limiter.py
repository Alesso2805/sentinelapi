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

    async def test_requests_under_the_warning_threshold_pass_silently(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=5, window_seconds=60)
        for _ in range(4):  # 80 % of 5
            self.assertIsNone(await limiter.check(self.fp, "/api/widgets"))

    async def test_crossing_the_warning_threshold_logs_medium_once(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=10, window_seconds=60)
        events = [await limiter.check(self.fp, "/api/widgets") for _ in range(10)]
        levels = [e.threat_level if e else None for e in events]
        self.assertEqual(levels, [None] * 8 + [ThreatLevel.MEDIUM, None])

    async def test_the_request_after_the_limit_is_blocked(self) -> None:
        """SEN-18: with a limit of 60, the 61st request used to pass until the 121st."""
        limiter = RateLimiter(self.backend, max_requests=3, window_seconds=60)
        for _ in range(3):
            self.assertIsNone(await limiter.check(self.fp, "/api/widgets"))

        event = await limiter.check(self.fp, "/api/widgets")
        assert event is not None
        self.assertEqual(event.threat_type, ThreatType.RATE_LIMIT_EXCEEDED)
        self.assertEqual(event.threat_level, ThreatLevel.HIGH)
        assert event.retry_after is not None
        self.assertTrue(0 < event.retry_after <= 60)

    async def test_severe_overshoot_escalates_to_high(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=3, window_seconds=60)
        event = None
        for _ in range(10):
            event = await limiter.check(self.fp, "/api/widgets")
        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.HIGH)

    async def test_a_new_path_does_not_open_a_new_counter(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=2, window_seconds=60)
        await limiter.check(self.fp, "/api/widgets/1")
        await limiter.check(self.fp, "/api/widgets/2")
        event = await limiter.check(self.fp, "/api/widgets/3")
        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.HIGH)

    async def test_a_prefix_limit_is_stricter_than_the_client_limit(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=100, path_limits={"/auth/": 2})
        events = [await limiter.check(self.fp, "/auth/login") for _ in range(3)]
        assert events[2] is not None
        self.assertEqual(events[2].threat_level, ThreatLevel.HIGH)
        self.assertIn("/auth/", events[2].detail)
        self.assertIsNone(await limiter.check(self.fp, "/api/widgets"))

    async def test_exempt_paths_are_never_counted(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=1, exempt_paths={"/health"})
        for _ in range(10):
            self.assertIsNone(await limiter.check(self.fp, "/health"))
        self.assertIsNone(await limiter.check(self.fp, "/api/widgets"))

    async def test_retry_after_is_what_is_left_of_the_window(self) -> None:
        clock = FakeClock()
        backend = InMemoryBackend(clock=clock)
        limiter = RateLimiter(backend, max_requests=1, window_seconds=60, clock=clock)
        await limiter.check(self.fp, "/api/widgets")
        clock.advance(20)
        event = await limiter.check(self.fp, "/api/widgets")
        assert event is not None
        self.assertEqual(event.retry_after, 40)

    async def test_limits_are_isolated_per_fingerprint(self) -> None:
        limiter = RateLimiter(self.backend, max_requests=1, window_seconds=60)
        other_fp = build_fingerprint("198.51.100.9", "pytest-agent")

        self.assertIsNone(await limiter.check(self.fp, "/api/widgets"))
        self.assertIsNone(await limiter.check(other_fp, "/api/widgets"))

    async def test_a_new_user_agent_does_not_reset_the_count(self) -> None:
        """The audit's probe 3: 500 requests with a new User-Agent each used to raise no event."""
        limiter = RateLimiter(self.backend, max_requests=5, window_seconds=60)
        events = [
            await limiter.check(build_fingerprint("203.0.113.7", f"ua-{i}"), "/api") for i in range(500)
        ]
        self.assertEqual(sum(e is not None and e.is_blocking() for e in events), 495)

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
