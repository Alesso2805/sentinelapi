"""docs/openapi.json is the demo app's current contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path

EXPORT_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "export_openapi.py"


def test_docs_openapi_json_is_what_the_demo_serves() -> None:
    spec = importlib.util.spec_from_file_location("export_openapi", EXPORT_SCRIPT)
    assert spec and spec.loader
    export = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(export)
    written = export.DOCUMENT.read_text(encoding="utf-8")
    assert written == export.render(), "docs/openapi.json is stale: run `make openapi`"
