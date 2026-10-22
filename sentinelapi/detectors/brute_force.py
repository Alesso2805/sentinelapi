"""Failed-authentication tracking, on two axes at once.

Tracking only "failures per IP" misses credential stuffing, where an
attacker spreads one target account's login attempts across many IPs to
stay under any single-IP rate limit. Tracking only "failures per
username" misses a single attacker brute-forcing many accounts from one
machine. So this detector tracks both and returns whichever signal is
stronger.
"""
from __future__ import annotations

from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.storage.backend import CounterBackend


class BruteForceDetector:
    def __init__(
        self,
        backend: CounterBackend,
        *,
        window_seconds: int = 900,  # 15 minutes
        per_fingerprint_medium: int = 5,
        per_fingerprint_high: int = 10,
        per_username_high: int = 8,
        per_username_critical: int = 15,
    ) -> None:
        self._backend = backend
        self._window_seconds = window_seconds
        self._per_fingerprint_medium = per_fingerprint_medium
        self._per_fingerprint_high = per_fingerprint_high
        self._per_username_high = per_username_high
        self._per_username_critical = per_username_critical

    async def record_failure(
        self, fingerprint: RequestFingerprint, username: str, path: str = "/login"
    ) -> SecurityEvent | None:
        fp_key = f"bf:fp:{fingerprint.key}"
        user_key = f"bf:user:{username}"

        fp_count = await self._backend.incr_with_expiry(fp_key, self._window_seconds)
        user_count = await self._backend.incr_with_expiry(user_key, self._window_seconds)

        # Username-targeted signal takes priority: it's the stronger
        # indicator of a real, distributed attack rather than one person
        # fat-fingering their own password.
        if user_count >= self._per_username_critical:
            return SecurityEvent(
                threat_type=ThreatType.BRUTE_FORCE,
                threat_level=ThreatLevel.CRITICAL,
                fingerprint=fingerprint,
                path=path,
                detail=f"{user_count} failed attempts against '{username}' from multiple sources",
            )
        if user_count >= self._per_username_high:
            return SecurityEvent(
                threat_type=ThreatType.BRUTE_FORCE,
                threat_level=ThreatLevel.HIGH,
                fingerprint=fingerprint,
                path=path,
                detail=f"{user_count} failed attempts against '{username}' (possible credential stuffing)",
            )
        if fp_count >= self._per_fingerprint_high:
            return SecurityEvent(
                threat_type=ThreatType.BRUTE_FORCE,
                threat_level=ThreatLevel.HIGH,
                fingerprint=fingerprint,
                path=path,
                detail=f"{fp_count} failed attempts from a single source",
            )
        if fp_count >= self._per_fingerprint_medium:
            return SecurityEvent(
                threat_type=ThreatType.BRUTE_FORCE,
                threat_level=ThreatLevel.MEDIUM,
                fingerprint=fingerprint,
                path=path,
                detail=f"{fp_count} failed attempts from a single source",
            )
        return None

    async def record_success(self, fingerprint: RequestFingerprint, username: str) -> None:
        """Clear counters on a successful login so a legitimate user who
        mistyped their password a few times isn't left flagged."""
        await self._backend.reset(f"bf:fp:{fingerprint.key}")
        await self._backend.reset(f"bf:user:{username}")
