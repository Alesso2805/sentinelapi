"""Keyed hashes for what identifies a person (ADR-0006).

The audit trail and the security log must let a reviewer say "these 40
failures came from one address and hit one account" without holding the
address or the account. A plain SHA-256 will not do: every IPv4 address
can be hashed in minutes, so the hash is the address. An HMAC under
SENTINEL_AUDIT_HASH_KEY gives the same correlation and cannot be reversed
without the key.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets


class Pseudonymizer:
    def __init__(self, key: str | None) -> None:
        # Without a key, one per process: correlation holds until a restart.
        # Production refuses to start without one.
        self.ephemeral = key is None
        self._key = key.encode("utf-8") if key is not None else secrets.token_bytes(32)

    def __call__(self, value: str | None) -> str | None:
        if value is None:
            return None
        digest = hmac.new(self._key, value.encode("utf-8", "surrogatepass"), hashlib.sha256)
        return digest.hexdigest()[:32]
