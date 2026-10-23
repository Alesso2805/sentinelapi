"""Writes the demo app's OpenAPI document to docs/openapi.json (SEN-37).

    uv run python scripts/export_openapi.py        # or: make openapi

tests/integration/test_openapi_document.py fails when the file is not what
this script writes, so the published contract cannot drift from the code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "openapi.json"


def render() -> str:
    """The document of the demo with every route, the console's included."""
    sys.path.insert(0, str(ROOT))
    from examples.demo_app.main import create_app
    from sentinelapi.config import SentinelSettings

    app = create_app(SentinelSettings(_env_file=None, demo_mode=True))
    return json.dumps(app.openapi(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    DOCUMENT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {DOCUMENT.relative_to(ROOT)}")
