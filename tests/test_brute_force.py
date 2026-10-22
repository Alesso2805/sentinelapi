import unittest

from sentinelapi.detectors.brute_force import BruteForceDetector
from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import ThreatLevel
from sentinelapi.storage.memory_backend import InMemoryBackend


class TestBruteForceDetector(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.backend = InMemoryBackend()
        self.detector = BruteForceDetector(
            self.backend,
            per_fingerprint_medium=3,
            per_fingerprint_high=6,
            per_username_high=5,
            per_username_critical=8,
        )

    async def test_few_failures_are_silent(self) -> None:
        fp = build_fingerprint("203.0.113.7", "ua")
        event = None
        for _ in range(2):
            event = await self.detector.record_failure(fp, "alice@example.com")
        self.assertIsNone(event)

    async def test_single_source_hammering_one_account_escalates(self) -> None:
        fp = build_fingerprint("203.0.113.7", "ua")
        event = None
        for _ in range(6):
            event = await self.detector.record_failure(fp, "alice@example.com")
        self.assertIsNotNone(event)
        self.assertEqual(event.threat_level, ThreatLevel.HIGH)

    async def test_credential_stuffing_from_many_ips_is_caught_by_username_axis(self) -> None:
        """The scenario a naive per-IP-only limiter would miss entirely:
        one attacker, one target account, eight different source IPs."""
        event = None
        for i in range(8):
            fp = build_fingerprint(f"203.0.113.{i}", "ua")  # different IP every time
            event = await self.detector.record_failure(fp, "bob@example.com")

        self.assertIsNotNone(event)
        self.assertEqual(event.threat_level, ThreatLevel.CRITICAL)
        self.assertIn("bob@example.com", event.detail)

    async def test_successful_login_clears_the_flag(self) -> None:
        fp = build_fingerprint("203.0.113.7", "ua")
        for _ in range(5):
            await self.detector.record_failure(fp, "carol@example.com")

        await self.detector.record_success(fp, "carol@example.com")

        # Same fingerprint/user, fresh start — two more failures shouldn't
        # immediately re-trigger the threshold that five already crossed.
        event = await self.detector.record_failure(fp, "carol@example.com")
        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()
