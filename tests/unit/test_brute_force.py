import unittest
from typing import Any

from sentinelapi.detectors.brute_force import AccountAction, BruteForceDetector
from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import ThreatLevel
from sentinelapi.storage.memory_backend import InMemoryBackend
from tests.fakes import FakeClock


class TestBruteForceDetector(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.clock = FakeClock()
        self.backend = InMemoryBackend(clock=self.clock)
        self.detector = self.make_detector()

    def make_detector(self, **overrides: Any) -> BruteForceDetector:
        return BruteForceDetector(
            self.backend,
            per_source_medium=3,
            per_source_high=6,
            per_username_high=5,
            per_username_critical=8,
            clock=self.clock,
            **overrides,
        )

    async def test_few_failures_are_silent(self) -> None:
        fp = build_fingerprint("203.0.113.7", "ua")
        event = None
        for _ in range(2):
            event = await self.detector.record_failure(fp, "alice@example.com")
        self.assertIsNone(event)
        self.assertIsNone(await self.detector.check(fp, "alice@example.com"))

    async def test_single_source_hammering_one_account_escalates(self) -> None:
        fp = build_fingerprint("203.0.113.7", "ua")
        event = None
        for _ in range(6):
            event = await self.detector.record_failure(fp, "alice@example.com")
        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.HIGH)

    async def test_one_source_against_many_accounts_is_caught_on_the_source_axis(self) -> None:
        """The case the source axis exists for; no test reached it before SEN-20."""
        fp = build_fingerprint("203.0.113.7", "ua")
        events = [await self.detector.record_failure(fp, f"user{i}@example.com") for i in range(6)]
        levels = [e.threat_level if e else None for e in events]
        self.assertEqual(
            levels, [None, None, ThreatLevel.MEDIUM, ThreatLevel.MEDIUM, ThreatLevel.MEDIUM, ThreatLevel.HIGH]
        )

    async def test_credential_stuffing_from_many_ips_is_caught_by_username_axis(self) -> None:
        """The scenario a naive per-IP-only limiter would miss entirely:
        one attacker, one target account, eight different source IPs."""
        event = None
        for i in range(8):
            fp = build_fingerprint(f"203.0.113.{i}", "ua")  # different IP every time
            event = await self.detector.record_failure(fp, "bob@example.com")

        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.CRITICAL)
        self.assertNotIn("bob@example.com", event.detail)

    async def test_a_blocked_source_is_refused_even_with_the_right_password(self) -> None:
        """The audit's probe 7: a blocked attacker who guessed right used to get in."""
        fp = build_fingerprint("203.0.113.7", "ua")
        for i in range(6):
            await self.detector.record_failure(fp, f"user{i}@example.com")
        verdict = await self.detector.check(fp, "alice@example.com")
        assert verdict is not None
        self.assertTrue(verdict.is_blocking())
        self.assertEqual(verdict.retry_after, 900)

    async def test_a_locked_account_is_refused_from_any_source(self) -> None:
        for i in range(5):
            await self.detector.record_failure(build_fingerprint(f"198.51.100.{i}", "ua"), "bob@example.com")
        verdict = await self.detector.check(build_fingerprint("192.0.2.1", "owner"), "bob@example.com")
        assert verdict is not None
        self.assertEqual(verdict.threat_level, ThreatLevel.HIGH)
        self.assertFalse(verdict.challenge_required)

    async def test_signal_mode_asks_for_a_challenge_instead_of_locking(self) -> None:
        detector = self.make_detector(account_action=AccountAction.SIGNAL)
        for i in range(5):
            await detector.record_failure(build_fingerprint(f"198.51.100.{i}", "ua"), "bob@example.com")
        verdict = await detector.check(build_fingerprint("192.0.2.1", "owner"), "bob@example.com")
        assert verdict is not None
        self.assertFalse(verdict.is_blocking())
        self.assertTrue(verdict.challenge_required)

    async def test_case_and_spaces_do_not_split_one_account(self) -> None:
        """The audit's probe 4: four spellings of one account used to count apart."""
        spellings = ["bob@example.com", "Bob@example.com", " BOB@EXAMPLE.COM", "bob@Example.com "]
        event = None
        for i in range(8):
            event = await self.detector.record_failure(
                build_fingerprint(f"198.51.100.{i}", "ua"), spellings[i % 4]
            )
        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.CRITICAL)

    async def test_a_case_sensitive_app_can_bring_its_own_normalizer(self) -> None:
        detector = self.make_detector(normalize=str.strip)
        for i in range(4):
            await detector.record_failure(build_fingerprint(f"198.51.100.{i}", "ua"), "Bob")
        verdict = await detector.check(build_fingerprint("192.0.2.1", "ua"), "bob")
        self.assertIsNone(verdict)

    async def test_successful_login_clears_the_flag(self) -> None:
        fp = build_fingerprint("203.0.113.7", "ua")
        for _ in range(5):
            await self.detector.record_failure(fp, "carol@example.com")

        await self.detector.record_success(fp, "carol@example.com")

        # Same fingerprint/user, fresh start — two more failures shouldn't
        # immediately re-trigger the threshold that five already crossed.
        event = await self.detector.record_failure(fp, "carol@example.com")
        self.assertIsNone(event)

    async def test_the_owners_login_does_not_erase_what_other_sources_tried(self) -> None:
        """The audit's probe 5: the victim's own success used to wipe the attack's count."""
        for i in range(4):
            await self.detector.record_failure(
                build_fingerprint(f"198.51.100.{i}", "ua"), "carol@example.com"
            )
        await self.detector.record_success(build_fingerprint("192.0.2.1", "owner"), "carol@example.com")
        event = await self.detector.record_failure(
            build_fingerprint("198.51.100.99", "ua"), "carol@example.com"
        )
        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.HIGH)

    async def test_an_attacker_cannot_clear_its_record_with_an_account_of_its_own(self) -> None:
        fp = build_fingerprint("203.0.113.7", "ua")
        for i in range(5):
            await self.detector.record_failure(fp, f"victim{i}@example.com")
        await self.detector.record_success(fp, "attacker@example.com")
        event = await self.detector.record_failure(fp, "victim9@example.com")
        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.HIGH)

    async def test_the_block_lifts_when_its_window_ends(self) -> None:
        fp = build_fingerprint("203.0.113.7", "ua")
        for i in range(6):
            await self.detector.record_failure(fp, f"user{i}@example.com")
        self.assertIsNotNone(await self.detector.check(fp, "alice@example.com"))
        self.clock.advance(901)
        self.assertIsNone(await self.detector.check(fp, "alice@example.com"))


if __name__ == "__main__":
    unittest.main()
