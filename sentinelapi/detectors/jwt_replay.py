"""Detects reuse of single-use JWTs via their `jti` claim.

Important scoping note, because getting this wrong is a classic mistake:
this detector is NOT meant to be applied to ordinary short-lived access
tokens. Access tokens are presented on every single API call by design —
treating that as "replay" would flag 100% of legitimate traffic.

It's built for tokens that are supposed to be redeemed exactly once:
refresh tokens under rotation, password-reset links, email-verification
links, magic-login links. A reused (already-rotated) refresh token in
particular is one of the strongest signals of token theft there is —
it means someone has a copy of a token the legitimate client already
exchanged for a new one.
"""

from __future__ import annotations

import time

import jwt

from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.storage.backend import CounterBackend

DEFAULT_TTL_SECONDS = 3600


class JWTReplayDetector:
    def __init__(
        self,
        backend: CounterBackend,
        *,
        secret: str,
        algorithms: tuple[str, ...] = ("HS256",),
    ) -> None:
        self._backend = backend
        self._secret = secret
        self._algorithms = list(algorithms)

    async def check(
        self, token: str, fingerprint: RequestFingerprint, path: str = "/refresh"
    ) -> SecurityEvent | None:
        try:
            payload = jwt.decode(token, self._secret, algorithms=self._algorithms)
        except jwt.ExpiredSignatureError:
            return SecurityEvent(
                threat_type=ThreatType.JWT_INVALID,
                threat_level=ThreatLevel.LOW,
                fingerprint=fingerprint,
                path=path,
                detail="expired token presented",
            )
        except jwt.InvalidTokenError as exc:
            return SecurityEvent(
                threat_type=ThreatType.JWT_INVALID,
                threat_level=ThreatLevel.MEDIUM,
                fingerprint=fingerprint,
                path=path,
                detail=f"invalid token signature/claims: {exc}",
            )

        jti = payload.get("jti")
        if not jti:
            return SecurityEvent(
                threat_type=ThreatType.JWT_INVALID,
                threat_level=ThreatLevel.MEDIUM,
                fingerprint=fingerprint,
                path=path,
                detail="token has no 'jti' claim; single-use cannot be enforced",
            )

        exp = payload.get("exp")
        ttl_seconds = max(int(exp - time.time()), 1) if exp else DEFAULT_TTL_SECONDS

        first_use = await self._backend.set_if_absent(f"jwt:jti:{jti}", fingerprint.key, ttl_seconds)
        if not first_use:
            return SecurityEvent(
                threat_type=ThreatType.JWT_REPLAY,
                threat_level=ThreatLevel.CRITICAL,
                fingerprint=fingerprint,
                path=path,
                detail=f"token jti={jti[:8]}... was already redeemed \u2014 likely token theft",
            )
        return None
