"""The app's role may add rows and read them, nothing else (AR-12).

Migrations run as the table's owner; the app connects as another role,
named by `sentinel migrate --app-role` or SENTINEL_AUDIT_APP_ROLE. Every
migration that creates a table calls `grant_append_only` for it.
"""

from __future__ import annotations

import re

from alembic import context, op

_ROLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")


def grant_append_only(table: str) -> None:
    role = context.config.attributes.get("app_role")
    if not role or op.get_bind().dialect.name != "postgresql":
        return
    if not _ROLE.fullmatch(role):
        raise ValueError(f"not a role name: {role!r}")
    op.execute(f'GRANT SELECT, INSERT ON {table} TO "{role}"')
