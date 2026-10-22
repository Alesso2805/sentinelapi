"""AR-11 and AR-12: the audit table comes from migrations, reversible and
append-only for the app's role. SEN-23 replaces these placeholders with
the checks on a real Postgres."""

from __future__ import annotations

from pathlib import Path

import pytest

AUDIT = Path(__file__).resolve().parents[2] / "sentinelapi" / "audit"


@pytest.mark.xfail(strict=True, reason="SEN-23: the table is created with create_all at startup")
def test_the_audit_table_has_a_migration_history() -> None:  # AR-11
    assert (AUDIT / "migrations").is_dir()


@pytest.mark.xfail(strict=True, reason="SEN-23: no database role is limited to INSERT and SELECT")
def test_the_app_role_cannot_rewrite_the_audit_trail() -> None:  # AR-12
    assert (AUDIT / "migrations").is_dir()
