"""Builds a privacy-conscious fingerprint for incoming requests.

We hash IP + User-Agent (+ optional user id) instead of storing them raw,
so audit logs are useful for correlation ("same fingerprint hit 40 failed
logins") without becoming a raw trove of PII. Limits never count on that
hash, since the client picks its User-Agent: they count on `client`, the
address itself (ADR-0004).
"""

from __future__ import annotations

import hashlib
import ipaddress

from sentinelapi.domain.entities import RequestFingerprint


def network_key(address: str) -> str:
    """The address, or its /64 for IPv6: one host usually owns a whole /64,
    so counting single IPv6 addresses would give it billions of fresh budgets."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def build_fingerprint(ip: str, user_agent: str, user_id: str | None = None) -> RequestFingerprint:
    raw = f"{ip}|{user_agent}|{user_id or ''}"
    key = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:32]
    return RequestFingerprint(key=key, ip=ip, client=network_key(ip), user_id=user_id)
