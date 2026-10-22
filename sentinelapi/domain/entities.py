"""Framework-agnostic domain types for SentinelAPI.

Nothing in this module imports FastAPI, SQLAlchemy, or Redis on purpose:
the detection logic should be testable on its own, independent of
whatever web framework or storage backend it's wired into.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ThreatLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(StrEnum):
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    BRUTE_FORCE = "brute_force"
    JWT_REPLAY = "jwt_replay"
    JWT_INVALID = "jwt_invalid"


@dataclass(frozen=True, slots=True)
class RequestFingerprint:
    """Cheap, privacy-conscious identity for a request.

    We deliberately avoid storing raw IP + User-Agent long-term; callers are
    expected to pass in an already-hashed identifier (see `fingerprint.py`).
    """

    key: str  # e.g. sha256(ip + ua + optional_user_id)[:32]
    ip: str
    user_id: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """A single detector verdict, ready to be logged and/or acted on."""

    threat_type: ThreatType
    threat_level: ThreatLevel
    fingerprint: RequestFingerprint
    path: str
    detail: str
    occurred_at: float  # seconds since the epoch, from the detector's Clock (AR-16)

    def is_blocking(self) -> bool:
        return self.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
