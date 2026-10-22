"""AR-10: production refuses unsafe settings."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from sentinelapi.config import SentinelSettings

UNSAFE: list[dict[str, Any]] = [
    {"jwt_secret": "change-me"},
    {"jwt_secret": "change-me-in-production"},
    {"jwt_secret": "too-short"},
]


@pytest.mark.xfail(strict=True, reason="SEN-27: there is no production mode yet")
@pytest.mark.parametrize("unsafe", UNSAFE, ids=[str(u) for u in UNSAFE])
def test_production_refuses_unsafe_settings(unsafe: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SentinelSettings(_env_file=None, **{"env": "production", **unsafe})
