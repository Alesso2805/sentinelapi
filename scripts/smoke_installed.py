"""Checks SentinelAPI as an integrator gets it from its wheel (SEN-36).

Run it with the Python of a fresh environment where only the wheel (with or
without extras) and httpx are installed, from a directory that is not the
repository, so nothing is imported from the source tree:

    python smoke_installed.py README.md [redis] [postgres] [sqlite]

It runs the README's integration snippet against the installed package and,
for each extra named, imports what that extra is for.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.resources
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

EXTRAS = {"redis": "sentinelapi.storage.redis_backend", "postgres": "asyncpg", "sqlite": "aiosqlite"}


async def run_snippet(readme: Path) -> None:
    from httpx import ASGITransport, AsyncClient

    snippet = re.search(
        r"```python\n(.*?)```", readme.read_text(encoding="utf-8").split("## Use it in your app")[1], re.S
    )
    assert snippet, "the README's integration snippet"
    namespace: dict[str, Any] = {"passwords_match": lambda username, password: password == "right"}
    exec(compile(snippet.group(1), str(readme), "exec"), namespace)
    app = namespace["app"]
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://smoke") as client:
            statuses = [
                (await client.post("/login", json={"username": "ana", "password": "wrong"})).status_code
                for _ in range(8)
            ]
            right = await client.post("/login", json={"username": "ana", "password": "right"})
    assert statuses[:7] == [401] * 7 and statuses[7] == 429, statuses
    assert right.status_code == 429, "the block must hold against the right password"


def main(readme: str, *extras: str) -> None:
    import sentinelapi

    location = Path(sentinelapi.__file__).resolve()
    assert "site-packages" in location.parts, f"imported from the source tree: {location}"
    assert importlib.resources.files("sentinelapi").joinpath("py.typed").is_file(), "py.typed"
    for extra in extras:
        importlib.import_module(EXTRAS[extra.strip("[]")])
    if "sqlite" in {e.strip("[]") for e in extras}:
        # The README's path: the wheel's own `sentinel migrate`, then the app.
        database = Path(tempfile.mkdtemp()) / "audit.db"
        os.environ["SENTINEL_DATABASE_URL"] = f"sqlite+aiosqlite:///{database.as_posix()}"
        scripts = Path(sys.executable).parent
        command = next(scripts / name for name in ("sentinel", "sentinel.exe") if (scripts / name).exists())
        subprocess.run([str(command), "migrate"], check=True)
    else:
        # Without the sqlite extra there is no driver for the default audit database.
        os.environ["SENTINEL_AUDIT"] = "false"
    asyncio.run(run_snippet(Path(readme)))
    print(f"ok: {location.parent}, extras {list(extras) or 'none'}")


if __name__ == "__main__":
    main(*sys.argv[1:])
