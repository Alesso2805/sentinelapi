from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Float, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SecurityEventLog(Base):
    """Durable audit trail of every detector verdict, blocking or not.

    Kept append-only on purpose: this table is what you hand to a
    security review or an incident postmortem, so nothing here should
    ever be updated or deleted by application code.
    """

    __tablename__ = "sentinel_security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    threat_type: Mapped[str] = mapped_column(String(32), index=True)
    threat_level: Mapped[str] = mapped_column(String(16), index=True)
    fingerprint_key: Mapped[str] = mapped_column(String(32), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    path: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str] = mapped_column(String(512))
    occurred_at: Mapped[float] = mapped_column(Float, index=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
