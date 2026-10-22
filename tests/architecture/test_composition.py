"""AR-18: only sentinelapi/integration.py constructs backends and
detectors, so an integrator cannot wire a detector to the wrong backend."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONSTRUCTED_ONLY_BY_THE_INSTALLER = {
    "InMemoryBackend",
    "RedisBackend",
    "RateLimiter",
    "BruteForceDetector",
    "JWTReplayDetector",
}
INSTALLER = ROOT / "sentinelapi" / "integration.py"


def constructions(path: Path) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else ""
            )
            if name in CONSTRUCTED_ONLY_BY_THE_INSTALLER:
                found.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno} {name}")
    return found


def test_only_the_installer_constructs_backends_and_detectors() -> None:
    files = [
        p for d in ("sentinelapi", "examples") for p in sorted((ROOT / d).rglob("*.py")) if p != INSTALLER
    ]
    assert [c for path in files for c in constructions(path)] == []
