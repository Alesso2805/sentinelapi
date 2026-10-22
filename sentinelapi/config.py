from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SentinelSettings(BaseSettings):
    # An empty variable means "use the default", as in .env.example.
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_", env_file=".env", extra="ignore", env_ignore_empty=True
    )

    # Storage backend: "memory" (single-process, dev/demo) or "redis" (production)
    backend: str = "memory"
    redis_url: str = "redis://localhost:6379/0"

    # Audit log database (any SQLAlchemy async URL — sqlite+aiosqlite for
    # local/dev, postgresql+asyncpg for production)
    database_url: str = "sqlite+aiosqlite:///./sentinelapi_audit.db"
    # false: events are only logged, never written to a database
    audit: bool = True
    # The Postgres role the app connects as: `sentinel migrate` grants it INSERT and
    # SELECT on the audit table and nothing else, so the trail is append-only (AR-12)
    audit_app_role: str | None = None
    # The key of the hashes that stand for addresses and accounts in the audit trail and
    # the log (ADR-0006). Unset: a random key per process, so correlation stops at a restart
    audit_hash_key: str | None = None
    # `sentinel purge` deletes events older than this
    audit_retention_days: int = 90
    # Identical events within this window become one row with a count (ADR-0006)
    audit_aggregate_seconds: int = 60
    # Groups waiting to be written; past it, new ones are dropped and the drop is logged
    audit_queue_size: int = 10_000

    # Proxies whose X-Forwarded-For is believed, as CIDRs (ADR-0004). Empty: no
    # proxy, so the direct peer is the client and the header is ignored.
    trusted_proxies: tuple[str, ...] = ()

    # Rate limiting
    rate_limit_max_requests: int = 60
    rate_limit_window_seconds: int = 60
    # A MEDIUM warning when a client's count first passes it; 80 % of the limit if unset
    rate_limit_warn_at: int | None = None
    # Never counted: health checks must not be limited with the traffic they watch
    rate_limit_exempt_paths: tuple[str, ...] = ("/health", "/ready")
    # Stricter limits per path prefix, on top of the per-client one, e.g. {"/auth/": 10}
    rate_limit_paths: dict[str, int] = Field(default_factory=dict)

    # Brute force
    brute_force_window_seconds: int = 900
    brute_force_per_source_medium: int = 5
    brute_force_per_source_high: int = 10
    brute_force_per_username_high: int = 8
    brute_force_per_username_critical: int = 15
    # ADR-0005. "lock": a targeted account is refused from every source until its
    # window ends. "signal": events ask the app for a challenge (CAPTCHA, MFA) instead.
    brute_force_account_action: Literal["lock", "signal"] = "lock"

    # JWT replay — must match the secret/algorithm your app issues tokens with
    jwt_secret: str = "change-me"
    jwt_algorithms: tuple[str, ...] = ("HS256",)
    # Checked when set: a token for another audience or from another issuer is invalid
    jwt_audience: str | None = None
    jwt_issuer: str | None = None

    # Paths the JWT-replay detector should actually check (typically just
    # your refresh/redeem endpoints — see jwt_replay.py for why)
    jwt_replay_paths: tuple[str, ...] = ("/auth/refresh",)

    # The bearer token of the demo's events API (SEN-26). Unset: nobody reads the events
    operator_token: str | None = None

    # If True, HIGH/CRITICAL events return 429/403 instead of just logging
    enforce: bool = True

    @field_validator("trusted_proxies")
    @classmethod
    def _trusted_proxies_are_networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for cidr in value:
            ipaddress.ip_network(cidr.strip(), strict=False)  # ValueError names the bad entry
        return value
