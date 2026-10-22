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

A used `jti` is remembered until the token's own `exp`, so a token is
refused for as long as it would otherwise be valid. That is why `exp` is
required: without it there is no "as long as" to remember.
"""

from __future__ import annotations

import math

import jwt

from sentinelapi.clock import SYSTEM_CLOCK, Clock
from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.storage.backend import CounterBackend


class JWTReplayDetector:
    def __init__(
        self,
        backend: CounterBackend,
        *,
        secret: str,
        algorithms: tuple[str, ...] = ("HS256",),
        audience: str | None = None,
        issuer: str | None = None,
        clock: Clock = SYSTEM_CLOCK,
    ) -> None:
        self._backend = backend
        self._clock = clock
        self._secret = secret
        self._algorithms = list(algorithms)
        self._audience = audience
        self._issuer = issuer

    async def check(
        self, token: str, fingerprint: RequestFingerprint, path: str = "/refresh"
    ) -> SecurityEvent | None:
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            return self._event(fingerprint, path, ThreatLevel.LOW, "expired token presented")
        except jwt.MissingRequiredClaimError as exc:
            return self._event(
                fingerprint, path, ThreatLevel.MEDIUM, f"invalid token: no '{exc.claim}' claim"
            )
        except jwt.InvalidTokenError as exc:
            # The exception's name only: its message may quote the token.
            return self._event(fingerprint, path, ThreatLevel.MEDIUM, f"invalid token: {type(exc).__name__}")

        jti, exp = payload["jti"], payload["exp"]
        if not isinstance(jti, str) or not jti:
            return self._event(fingerprint, path, ThreatLevel.MEDIUM, "invalid token: 'jti' is not a string")

        ttl_seconds = max(math.ceil(exp - self._clock.now()), 1)
        first_use = await self._backend.set_if_absent(f"jwt:jti:{jti}", fingerprint.key, ttl_seconds)
        if not first_use:
            return SecurityEvent(
                threat_type=ThreatType.JWT_REPLAY,
                threat_level=ThreatLevel.CRITICAL,
                fingerprint=fingerprint,
                path=path,
                occurred_at=self._clock.now(),
                detail="a single-use token was presented again — likely token theft",
            )
        return None

    def _event(
        self, fingerprint: RequestFingerprint, path: str, level: ThreatLevel, detail: str
    ) -> SecurityEvent:
        return SecurityEvent(
            threat_type=ThreatType.JWT_INVALID,
            threat_level=level,
            fingerprint=fingerprint,
            path=path,
            occurred_at=self._clock.now(),
            detail=detail,
        )
