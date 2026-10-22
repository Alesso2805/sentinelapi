"""Identical events folded into one row: a count and the last one's time (ADR-0006, SEN-25).

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

TABLE = "sentinel_security_events"


def upgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.add_column(sa.Column("count", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("last_occurred_at", sa.DateTime(timezone=True), nullable=True))
    # Rows written before this revision were one event each.
    op.execute(f"UPDATE {TABLE} SET last_occurred_at = occurred_at")
    with op.batch_alter_table(TABLE) as batch:
        batch.alter_column("last_occurred_at", nullable=False, existing_type=sa.DateTime(timezone=True))
        batch.alter_column("count", server_default=None, existing_type=sa.Integer())
        batch.create_check_constraint(f"ck_{TABLE}_count", "count >= 1")


def downgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_constraint(f"ck_{TABLE}_count", type_="check")
        batch.drop_column("last_occurred_at")
        batch.drop_column("count")
