"""The audit table: one row per security event.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from sentinelapi.audit.migrations.grants import grant_append_only

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TABLE = "sentinel_security_events"
# Frozen here on purpose: a migration describes the schema of its day.
THREAT_TYPES = ("rate_limit_exceeded", "brute_force", "jwt_replay", "jwt_invalid")
THREAT_LEVELS = ("none", "low", "medium", "high", "critical")
INDEXED = ("threat_type", "threat_level", "fingerprint_key", "occurred_at")


def _one_of(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("threat_type", sa.String(32), nullable=False),
        sa.Column("threat_level", sa.String(16), nullable=False),
        sa.Column("fingerprint_key", sa.String(32), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(128), nullable=True),
        sa.Column("path", sa.String(256), nullable=False),
        sa.Column("detail", sa.String(512), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(_one_of("threat_type", THREAT_TYPES), name=f"ck_{TABLE}_threat_type"),
        sa.CheckConstraint(_one_of("threat_level", THREAT_LEVELS), name=f"ck_{TABLE}_threat_level"),
    )
    for column in INDEXED:
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    grant_append_only(TABLE)


def downgrade() -> None:
    for column in INDEXED:
        op.drop_index(f"ix_{TABLE}_{column}", table_name=TABLE)
    op.drop_table(TABLE)
