import time
import unittest
import uuid

import jwt

from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.detectors.jwt_replay import JWTReplayDetector
from sentinelapi.domain.entities import ThreatLevel, ThreatType
from sentinelapi.storage.memory_backend import InMemoryBackend

SECRET = "test-secret-do-not-use-in-prod"


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


if __name__ == "__main__":
    unittest.main()
