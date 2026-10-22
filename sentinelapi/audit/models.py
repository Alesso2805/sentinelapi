from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import CheckConstraint, DateTime, Dialect, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from sentinelapi.domain.entities import ThreatLevel, ThreatType


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator[datetime]):
    """timestamptz, always returned aware. SQLite keeps no time zone, so a
    naive value coming back from it is UTC, which is how it was written."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return value.astimezone(UTC) if value is not None and value.tzinfo is not None else value

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def _one_of(column: str, values: type[ThreatType] | type[ThreatLevel]) -> str:
    return f"{column} IN ({', '.join(repr(v.value) for v in values)})"


class SecurityEventLog(Base):
    """Durable audit trail of every detector verdict, blocking or not.

    Kept append-only on purpose: this table is what you hand to a
    security review or an incident postmortem, so nothing here should
    ever be updated or deleted by application code. The migrations make
    that a database permission for the app's role (AR-12).
    """

    __tablename__ = "sentinel_security_events"
    __table_args__ = (
        CheckConstraint(_one_of("threat_type", ThreatType), name="ck_sentinel_security_events_threat_type"),
        CheckConstraint(
            _one_of("threat_level", ThreatLevel), name="ck_sentinel_security_events_threat_level"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    threat_type: Mapped[str] = mapped_column(String(32), index=True)
    threat_level: Mapped[str] = mapped_column(String(16), index=True)
    fingerprint_key: Mapped[str] = mapped_column(String(32), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    path: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str] = mapped_column(String(512))
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, server_default=func.now())
