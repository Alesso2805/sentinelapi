from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

# The demo's default audit database, relative to where the demo runs. A test
# that writes here is sharing state with the developer's own demo runs.
DEMO_DATABASE = Path("sentinelapi_audit.db")


def _snapshot() -> tuple[int, int] | None:
    if not DEMO_DATABASE.exists():
        return None
    stat = DEMO_DATABASE.stat()
    return stat.st_size, stat.st_mtime_ns


@pytest.fixture(scope="session", autouse=True)
def demo_database_untouched() -> Iterator[None]:
    before = _snapshot()
    yield
    assert _snapshot() == before, f"a test wrote to {DEMO_DATABASE}; use the integration fixtures instead"
