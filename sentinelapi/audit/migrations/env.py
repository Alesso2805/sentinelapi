"""Alembic environment for SentinelAPI's own tables (ADR-0006).

They keep their own version table, so these migrations live next to the
app's in the same database without either history seeing the other.
Run them through `sentinelapi.audit.migrate` or `sentinel migrate`,
which hand this environment an open connection.
"""

from __future__ import annotations

from alembic import context

from sentinelapi.audit.migrations import VERSION_TABLE
from sentinelapi.audit.models import Base

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("run SentinelAPI's migrations with `sentinel migrate` or sentinelapi.audit.migrate")

context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    version_table=VERSION_TABLE,
    # Only SentinelAPI's tables: the app's own are not ours to compare or touch.
    include_name=lambda name, type_, _: type_ != "table" or name in Base.metadata.tables,
    render_as_batch=connection.dialect.name == "sqlite",
)
with context.begin_transaction():
    context.run_migrations()
