"""Who is asking: the client's address, through the proxies you trust (ADR-0004).

Behind a reverse proxy every request arrives from the proxy, and the real
address is in X-Forwarded-For. Any client can send that header too, so it
is believed only from a trusted proxy, and only its right-most hops: each
trusted proxy appends the address it saw, while everything to the left of
the first address no trusted proxy wrote was written by the client.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import RequestFingerprint

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(cidrs: Iterable[str]) -> tuple[Network, ...]:
    """Raises ValueError for anything that is not an address or a network."""
    return tuple(ipaddress.ip_network(cidr.strip(), strict=False) for cidr in cidrs)


def parse_address(value: str) -> Address | None:
    """An address as proxies write it: bare, `[v6]:port` or `v4:port`."""
    text = value.strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1:
        text = text.partition(":")[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


class ClientResolver:
    def __init__(self, trusted_proxies: Iterable[str] = ()) -> None:
        self._trusted = parse_networks(trusted_proxies)

    def address(self, peer: str | None, forwarded_for: str | None = None) -> str:
        if peer is None:
            return "unknown"
        if not self._is_trusted(parse_address(peer)):
            return peer
        hops = [hop for hop in (forwarded_for or "").split(",") if hop.strip()]
        for hop in reversed(hops):
            address = parse_address(hop)
            if address is None:
                break  # not an address: no trusted proxy wrote this, so stop believing the header
            if not self._is_trusted(address):
                return str(address)
        return peer

    def fingerprint(
        self, peer: str | None, forwarded_for: str | None, user_agent: str, user_id: str | None = None
    ) -> RequestFingerprint:
        return build_fingerprint(self.address(peer, forwarded_for), user_agent, user_id)

    def _is_trusted(self, address: Address | None) -> bool:
        return address is not None and any(address in network for network in self._trusted)
