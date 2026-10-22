"""Builds a privacy-conscious fingerprint for incoming requests.

We hash IP + User-Agent (+ optional user id) instead of storing them raw,
so audit logs are useful for correlation ("same fingerprint hit 40 failed
logins") without becoming a raw trove of PII.
"""

from __future__ import annotations

import hashlib

from sentinelapi.domain.entities import RequestFingerprint


def build_fingerprint(ip: str, user_agent: str, user_id: str | None = None) -> RequestFingerprint:
    raw = f"{ip}|{user_agent}|{user_id or ''}"
    key = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return RequestFingerprint(key=key, ip=ip, user_id=user_id)
