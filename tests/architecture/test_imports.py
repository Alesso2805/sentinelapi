"""AR-01 to AR-03: what the framework-free layers may import.

Allowlists, not denylists: a new I/O library imported by mistake fails
here without anyone adding it to a list.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "sentinelapi"


def imports_in(source: str, package: str) -> set[str]:
    """Absolute names of every module `source` imports, relative imports
    resolved against `package`, the package the source belongs to."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                names.add(node.module or "")
            else:
                parts = package.split(".")
                base = parts[: len(parts) - (node.level - 1)]
                names.add(".".join([*base, *([node.module] if node.module else [])]))
    return names


def _package_of(path: Path) -> str:
    parts = path.relative_to(ROOT).with_suffix("").parts
    return ".".join(parts[:-1])


def _within(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(module == p or module.startswith(p + ".") for p in prefixes)


def forbidden(imports: set[str], allowed: tuple[str, ...]) -> list[str]:
    return sorted(
        m for m in imports if m.split(".")[0] not in sys.stdlib_module_names and not _within(m, allowed)
    )


def violations(files: list[Path], allowed: tuple[str, ...]) -> list[str]:
    return [
        f"{path.relative_to(ROOT).as_posix()} imports {module}"
        for path in files
        for module in forbidden(imports_in(path.read_text(encoding="utf-8"), _package_of(path)), allowed)
    ]


def test_domain_imports_only_the_standard_library() -> None:  # AR-01
    files = sorted((PACKAGE / "domain").rglob("*.py"))
    assert files
    assert violations(files, ("sentinelapi.domain",)) == []


def test_detectors_import_only_the_standard_library_pyjwt_and_the_domain() -> None:  # AR-02
    files = sorted((PACKAGE / "detectors").rglob("*.py"))
    assert files
    allowed = (
        "jwt",
        "sentinelapi.clock",
        "sentinelapi.domain",
        "sentinelapi.storage.backend",
        "sentinelapi.detectors",
    )
    assert violations(files, allowed) == []


def test_the_storage_port_imports_only_the_standard_library() -> None:  # AR-03
    assert violations([PACKAGE / "storage" / "backend.py"], ()) == []


def test_the_check_sees_third_party_and_relative_imports() -> None:
    source = "import os\nimport fastapi\nfrom ..storage import backend\nfrom . import entities\n"
    assert forbidden(imports_in(source, "sentinelapi.domain"), ("sentinelapi.domain",)) == [
        "fastapi",
        "sentinelapi.storage",
    ]
