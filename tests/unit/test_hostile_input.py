"""AR-08: no detector raises on attacker-controlled input."""

from __future__ import annotations

import pytest

from sentinelapi.detectors.brute_force import BruteForceDetector
from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.detectors.jwt_replay import JWTReplayDetector
from sentinelapi.detectors.rate_limiter import RateLimiter
from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.storage.memory_backend import InMemoryBackend

# What a JSON body or a URL path can carry, lone surrogates included.
TEXT = ["", "x" * 1_000_000, "\x00\x01\x1b[31m", "ñandú 雪", "\udcff", "../../etc/passwd", "a.b.c"]
# What a header can carry: Starlette decodes headers as Latin-1.
HEADER_VALUES = ["", "a.b.c", "x" * 1_000_000, "\x00", "eyJ.eyJ.sig", "ÿþ\x7f", "Bearer Bearer"]

FINGERPRINT = build_fingerprint("203.0.113.7", "test")


@pytest.mark.parametrize("path", TEXT, ids=range(len(TEXT)))
async def test_rate_limiter(path: str) -> None:
    event = await RateLimiter(InMemoryBackend(), max_requests=1).check(FINGERPRINT, path)
    assert event is None or isinstance(event, SecurityEvent)


@pytest.mark.parametrize("username", TEXT, ids=range(len(TEXT)))
async def test_brute_force(username: str) -> None:
    detector = BruteForceDetector(InMemoryBackend())
    events = [await detector.record_failure(FINGERPRINT, username) for _ in range(20)]
    assert all(e is None or isinstance(e, SecurityEvent) for e in events)
    await detector.record_success(FINGERPRINT, username)


@pytest.mark.parametrize("token", HEADER_VALUES, ids=range(len(HEADER_VALUES)))
async def test_jwt_replay(token: str) -> None:
    event = await JWTReplayDetector(InMemoryBackend(), secret="s" * 32).check(token, FINGERPRINT)
    assert isinstance(event, SecurityEvent)


@pytest.mark.parametrize("user_agent", HEADER_VALUES, ids=range(len(HEADER_VALUES)))
def test_fingerprint(user_agent: str) -> None:
    assert len(build_fingerprint("203.0.113.7", user_agent).key) == 32
