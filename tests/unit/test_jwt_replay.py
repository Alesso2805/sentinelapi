import time
import unittest
import uuid

import jwt

from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.detectors.jwt_replay import JWTReplayDetector
from sentinelapi.domain.entities import ThreatLevel, ThreatType
from sentinelapi.storage.memory_backend import InMemoryBackend
from tests.fakes import FakeClock

SECRET = "test-secret-do-not-use-in-production-0123456789"


def make_refresh_token(*, jti: str | None = None, expires_in: int = 3600) -> str:
    payload = {
        "sub": "user-123",
        "jti": jti if jti is not None else str(uuid.uuid4()),
        "exp": int(time.time()) + expires_in,
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


class TestJWTReplayDetector(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.backend = InMemoryBackend()
        self.detector = JWTReplayDetector(self.backend, secret=SECRET)
        self.fp = build_fingerprint("203.0.113.7", "ua")

    async def test_first_use_of_a_token_is_clean(self) -> None:
        token = make_refresh_token()
        event = await self.detector.check(token, self.fp)
        self.assertIsNone(event)

    async def test_second_use_of_the_same_token_is_flagged_critical(self) -> None:
        token = make_refresh_token()
        first = await self.detector.check(token, self.fp)
        second = await self.detector.check(token, self.fp)

        self.assertIsNone(first)
        assert second is not None
        self.assertEqual(second.threat_type, ThreatType.JWT_REPLAY)
        self.assertEqual(second.threat_level, ThreatLevel.CRITICAL)

    async def test_replay_from_a_different_fingerprint_is_still_caught(self) -> None:
        """This is the actual attack scenario: victim's client uses the
        token once, then a stolen copy gets replayed from an attacker's
        machine with a different IP/User-Agent entirely."""
        token = make_refresh_token()
        attacker_fp = build_fingerprint("198.51.100.66", "curl/8.0")

        await self.detector.check(token, self.fp)
        event = await self.detector.check(token, attacker_fp)

        assert event is not None
        self.assertEqual(event.threat_level, ThreatLevel.CRITICAL)

    async def test_expired_token_is_flagged_low_not_replay(self) -> None:
        token = make_refresh_token(expires_in=-10)  # already expired
        event = await self.detector.check(token, self.fp)

        assert event is not None
        self.assertEqual(event.threat_type, ThreatType.JWT_INVALID)
        self.assertEqual(event.threat_level, ThreatLevel.LOW)

    async def test_tampered_signature_is_flagged_invalid(self) -> None:
        token = make_refresh_token() + "tampered"
        event = await self.detector.check(token, self.fp)

        assert event is not None
        self.assertEqual(event.threat_type, ThreatType.JWT_INVALID)

    async def test_token_without_jti_cannot_be_verified_single_use(self) -> None:
        payload = {"sub": "user-123", "exp": int(time.time()) + 3600}
        token = jwt.encode(payload, SECRET, algorithm="HS256")

        event = await self.detector.check(token, self.fp)
        assert event is not None
        self.assertEqual(event.threat_type, ThreatType.JWT_INVALID)
        self.assertIn("jti", event.detail)

    async def test_a_token_without_exp_is_flagged(self) -> None:
        """SEN-21: a token without `exp` used to be remembered for one hour only."""
        token = jwt.encode({"sub": "user-123", "jti": str(uuid.uuid4())}, SECRET, algorithm="HS256")
        event = await self.detector.check(token, self.fp)
        assert event is not None
        self.assertEqual(event.threat_type, ThreatType.JWT_INVALID)
        self.assertIn("exp", event.detail)

    async def test_a_used_token_is_refused_for_its_whole_life(self) -> None:
        clock = FakeClock()
        detector = JWTReplayDetector(InMemoryBackend(clock=clock), secret=SECRET, clock=clock)
        token = make_refresh_token(expires_in=7 * 24 * 3600)
        self.assertIsNone(await detector.check(token, self.fp))
        clock.advance(2 * 3600)  # past the hour a token used to be remembered for
        event = await detector.check(token, self.fp)
        assert event is not None
        self.assertEqual(event.threat_type, ThreatType.JWT_REPLAY)

    async def test_a_jti_that_is_not_a_string_is_flagged(self) -> None:
        token = jwt.encode({"jti": 42, "exp": int(time.time()) + 60}, SECRET, algorithm="HS256")
        event = await self.detector.check(token, self.fp)
        assert event is not None
        self.assertEqual(event.threat_type, ThreatType.JWT_INVALID)

    async def test_audience_and_issuer_are_checked_when_set(self) -> None:
        detector = JWTReplayDetector(InMemoryBackend(), secret=SECRET, audience="demo", issuer="sentinel")

        def token(**claims: object) -> str:
            payload = {"jti": str(uuid.uuid4()), "exp": int(time.time()) + 60, **claims}
            return jwt.encode(payload, SECRET, algorithm="HS256")

        self.assertIsNone(await detector.check(token(aud="demo", iss="sentinel"), self.fp))
        for wrong in (token(aud="other", iss="sentinel"), token(aud="demo", iss="other"), token()):
            event = await detector.check(wrong, self.fp)
            assert event is not None
            self.assertEqual(event.threat_type, ThreatType.JWT_INVALID)


if __name__ == "__main__":
    unittest.main()
