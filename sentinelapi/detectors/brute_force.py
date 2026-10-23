"""Failed-authentication tracking, on two axes at once (ADR-0005).

Tracking only "failures per source" misses credential stuffing, where an
attacker spreads one target account's login attempts across many
addresses to stay under any single-address limit. Tracking only
"failures per account" misses a single attacker brute-forcing many
accounts from one machine. So this detector tracks both:

- the source axis, keyed on the client's address (ADR-0004). The source
  is the attacker, so a blocked source is refused outright;
- the account axis, keyed on a hash of the normalized username. The
  account is the victim, so what a block means is a setting: `lock` it for
  the window, or `signal` that the app should ask for a challenge.

The login calls `check` before verifying the password, so a block holds
even when the attacker finally guesses right, then `record_failure` or
`record_success` after.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from enum import StrEnum
from typing import NamedTuple

from sentinelapi.clock import SYSTEM_CLOCK, Clock
from sentinelapi.domain.entities import RequestFingerprint, SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.storage.backend import CounterBackend


class AccountAction(StrEnum):
    LOCK = "lock"
    SIGNAL = "signal"


def normalize_username(username: str) -> str:
    """`Bob@Example.com ` and `bob@example.com` are one account. Apps whose
    usernames are case-sensitive pass their own normalizer."""
    return username.strip().casefold()


class BruteForceDetector:
    def __init__(
        self,
        backend: CounterBackend,
        *,
        window_seconds: int = 900,
        per_source_medium: int = 5,
        per_source_high: int = 10,
        per_username_high: int = 8,
        per_username_critical: int = 15,
        account_action: AccountAction = AccountAction.LOCK,
        normalize: Callable[[str], str] = normalize_username,
        clock: Clock = SYSTEM_CLOCK,
    ) -> None:
        self._backend = backend
        self._clock = clock
        self._window_seconds = window_seconds
        self._per_source_medium = per_source_medium
        self._per_source_high = per_source_high
        self._per_username_high = per_username_high
        self._per_username_critical = per_username_critical
        self._account_action = account_action
        self._normalize = normalize

    async def check(
        self, fingerprint: RequestFingerprint, username: str, path: str = "/login"
    ) -> SecurityEvent | None:
        """Before the password is verified. A blocking event means: refuse
        this attempt, whether the password is right or not."""
        keys = self._keys(fingerprint, username)
        source_failures = await self._backend.get(keys.source)
        if source_failures >= self._per_source_high:
            detail = f"source blocked after {source_failures} failed attempts"
            return await self._event(fingerprint, path, ThreatLevel.HIGH, detail, keys, blocked=keys.source)
        account_failures = await self._backend.get(keys.account)
        if account_failures >= self._per_username_high:
            if self._account_action is AccountAction.LOCK:
                # A refused attempt still counts against the account, so an attack that
                # goes on reaches CRITICAL; the window does not move (ADR-0002).
                account_failures = await self._backend.incr_with_expiry(keys.account, self._window_seconds)
            return await self._account_event(fingerprint, path, account_failures, keys, refusing=True)
        return None

    async def record_failure(
        self, fingerprint: RequestFingerprint, username: str, path: str = "/login"
    ) -> SecurityEvent | None:
        keys = self._keys(fingerprint, username)
        source_failures = await self._backend.incr_with_expiry(keys.source, self._window_seconds)
        account_failures = await self._backend.get(keys.account)
        # On a locked account, `check` already counted this attempt; in shadow mode
        # it gets here too, and must not count twice.
        if self._account_action is not AccountAction.LOCK or account_failures < self._per_username_high:
            account_failures = await self._backend.incr_with_expiry(keys.account, self._window_seconds)
        await self._backend.incr_with_expiry(keys.pair, self._window_seconds)

        # The account signal takes priority: it's the stronger indicator of a
        # real, distributed attack rather than one person fat-fingering their
        # own password.
        if account_failures >= self._per_username_high:
            return await self._account_event(fingerprint, path, account_failures, keys, refusing=False)
        if source_failures >= self._per_source_high:
            detail = f"{source_failures} failed attempts from a single source"
            return await self._event(fingerprint, path, ThreatLevel.HIGH, detail, keys, blocked=keys.source)
        if source_failures >= self._per_source_medium:
            detail = f"{source_failures} failed attempts from a single source"
            return await self._event(fingerprint, path, ThreatLevel.MEDIUM, detail, keys)
        return None

    async def record_success(self, fingerprint: RequestFingerprint, username: str) -> None:
        """Take back the failures this source made against this account, so a
        user who mistyped a few times is not left flagged. Only those: the
        owner's login must not erase what other sources tried, and an
        attacker must not clear its record by signing into an account of its own."""
        keys = self._keys(fingerprint, username)
        mistakes = await self._backend.get(keys.pair)
        if mistakes:
            await self._backend.decrement(keys.source, mistakes)
            await self._backend.decrement(keys.account, mistakes)
        await self._backend.reset(keys.pair)

    def _keys(self, fingerprint: RequestFingerprint, username: str) -> _Keys:
        # A hash, so a 1 MB username is a 32-character key and no username is
        # stored in the backend or carried by an event.
        normalized = self._normalize(username).encode("utf-8", "surrogatepass")
        account = hashlib.sha256(normalized).hexdigest()[:32]
        return _Keys(
            source=f"bf:src:{fingerprint.client}",
            account=f"bf:acct:{account}",
            pair=f"bf:pair:{fingerprint.client}:{account}",
            subject=account,
        )

    async def _account_event(
        self, fingerprint: RequestFingerprint, path: str, failures: int, keys: _Keys, *, refusing: bool
    ) -> SecurityEvent:
        if self._account_action is AccountAction.SIGNAL:
            detail = f"{failures} failed attempts against one account: ask for a challenge"
            return await self._event(fingerprint, path, ThreatLevel.MEDIUM, detail, keys, challenge=True)
        level = ThreatLevel.CRITICAL if failures >= self._per_username_critical else ThreatLevel.HIGH
        if refusing:
            detail = f"account locked, {failures} attempts against it in this window"
        else:
            detail = f"{failures} failed attempts against one account (possible credential stuffing)"
        return await self._event(fingerprint, path, level, detail, keys, blocked=keys.account)

    async def _event(
        self,
        fingerprint: RequestFingerprint,
        path: str,
        level: ThreatLevel,
        detail: str,
        keys: _Keys,
        *,
        blocked: str | None = None,
        challenge: bool = False,
    ) -> SecurityEvent:
        return SecurityEvent(
            threat_type=ThreatType.BRUTE_FORCE,
            threat_level=level,
            fingerprint=fingerprint,
            path=path,
            occurred_at=self._clock.now(),
            detail=detail,
            retry_after=await self._backend.ttl(blocked) if blocked else None,
            challenge_required=challenge,
            subject=keys.subject,
        )


class _Keys(NamedTuple):
    source: str
    account: str
    pair: str
    subject: str  # an opaque id of the account: never the username
