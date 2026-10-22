from __future__ import annotations

import ipaddress

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SentinelSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # Storage backend: "memory" (single-process, dev/demo) or "redis" (production)
    backend: str = "memory"
    redis_url: str = "redis://localhost:6379/0"

    # Audit log database (any SQLAlchemy async URL — sqlite+aiosqlite for
    # local/dev, postgresql+asyncpg for production)
    database_url: str = "sqlite+aiosqlite:///./sentinelapi_audit.db"

    # Proxies whose X-Forwarded-For is believed, as CIDRs (ADR-0004). Empty: no
    # proxy, so the direct peer is the client and the header is ignored.
    trusted_proxies: tuple[str, ...] = ()

    # Rate limiting
    rate_limit_max_requests: int = 60
    rate_limit_window_seconds: int = 60

    # Brute force
    brute_force_window_seconds: int = 900
    brute_force_per_fingerprint_medium: int = 5
    brute_force_per_fingerprint_high: int = 10
    brute_force_per_username_high: int = 8
    brute_force_per_username_critical: int = 15

    # JWT replay — must match the secret/algorithm your app issues tokens with
    jwt_secret: str = "change-me"
    jwt_algorithms: tuple[str, ...] = ("HS256",)

    # Paths the JWT-replay detector should actually check (typically just
    # your refresh/redeem endpoints — see jwt_replay.py for why)
    jwt_replay_paths: tuple[str, ...] = ("/auth/refresh",)

    # If True, HIGH/CRITICAL events return 429/403 instead of just logging
    enforce: bool = True

    @field_validator("trusted_proxies")
    @classmethod
    def _trusted_proxies_are_networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for cidr in value:
            ipaddress.ip_network(cidr.strip(), strict=False)  # ValueError names the bad entry
        return value
