"""Keyed hashes instead of raw addresses and user ids (ADR-0006).

Revision ID: 0002
Revises: 0001

Rows written before this revision keep NULL hashes: the raw values they
held are dropped on purpose, and cannot be hashed without being read.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TABLE = "sentinel_security_events"
HASHED = ("client_hash", "subject_hash")


def upgrade() -> None:
    # batch_alter_table: SQLite rebuilds the table, Postgres alters it in place.
    with op.batch_alter_table(TABLE) as batch:
        for column in HASHED:
            batch.add_column(sa.Column(column, sa.String(64), nullable=True))
        batch.drop_column("ip")
        batch.drop_column("user_id")
    for column in HASHED:
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])


def downgrade() -> None:
    for column in HASHED:
        op.drop_index(f"ix_{TABLE}_{column}", table_name=TABLE)
    with op.batch_alter_table(TABLE) as batch:
        batch.add_column(sa.Column("ip", sa.String(64), nullable=False, server_default="redacted"))
        batch.add_column(sa.Column("user_id", sa.String(128), nullable=True))
        for column in HASHED:
            batch.drop_column(column)
    with op.batch_alter_table(TABLE) as batch:
        batch.alter_column("ip", server_default=None)
