"""AR-09: every setting is listed in .env.example."""

from __future__ import annotations

from pathlib import Path

from sentinelapi.config import SentinelSettings

ENV_EXAMPLE = Path(__file__).resolve().parents[2] / ".env.example"


def test_every_setting_is_in_env_example() -> None:
    lines = ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
    documented = {line.split("=", 1)[0].strip() for line in lines if "=" in line and not line.startswith("#")}
    expected = {f"SENTINEL_{name.upper()}" for name in SentinelSettings.model_fields}
    assert sorted(expected - documented) == []
