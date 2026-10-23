"""AR-19: every test the README's Guarantees name is defined in a file its row links."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def guarantees() -> list[str]:
    section = (ROOT / "README.md").read_text(encoding="utf-8").split("\n## Guarantees\n", 1)[1]
    rows = section.split("\n## ", 1)[0].splitlines()
    found = [row for row in rows if row.startswith("| ") and not row.startswith(("| Guarantee ", "| ---"))]
    assert found, "README › Guarantees has no rows"
    return found


def test_every_guarantee_names_tests_that_exist() -> None:
    problems = []
    for row in guarantees():
        files = [ROOT / link for link in re.findall(r"\]\(([^)#]+)\)", row)]
        problems += [f"broken link {f.relative_to(ROOT)}" for f in files if not f.is_file()]
        sources = "\n".join(f.read_text(encoding="utf-8") for f in files if f.is_file())
        names = re.findall(r"`(test_\w+)`", row)
        if not names:
            problems.append(f"names no test: {row[:70]}")
        problems += [n for n in names if not re.search(rf"^\s*(async )?def {n}\(", sources, re.M)]
    assert problems == []
