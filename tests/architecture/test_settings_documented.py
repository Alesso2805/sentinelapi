"""AR-09: every setting is listed in .env.example and in the README's configuration tables."""

from __future__ import annotations

import re
from pathlib import Path

from sentinelapi.config import SentinelSettings

ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / ".env.example"
README = ROOT / "README.md"
EXPECTED = {f"SENTINEL_{name.upper()}" for name in SentinelSettings.model_fields}


def test_every_setting_is_in_env_example() -> None:
    lines = ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
    documented = {line.split("=", 1)[0].strip() for line in lines if "=" in line and not line.startswith("#")}
    assert sorted(EXPECTED - documented) == []


def test_every_setting_is_in_the_readme_and_no_other() -> None:
    section = README.read_text(encoding="utf-8").split("\n## Configuration\n", 1)[1].split("\n## ", 1)[0]
    documented = set(re.findall(r"^\| `(SENTINEL_\w+)` \|", section, re.M))
    assert sorted(EXPECTED - documented) == [], "missing from README's Configuration"
    assert sorted(documented - EXPECTED) == [], "in README's Configuration, but not a setting"
