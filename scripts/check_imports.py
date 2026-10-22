"""Import every module of the library (AR-06).

Run it in an environment with only the required dependencies: a module
that needs an extra or a dev tool fails here, except the ones listed in
NEEDS_AN_EXTRA.
"""

from __future__ import annotations

import importlib
import pkgutil

import sentinelapi

# The Redis backend needs its extra; the Alembic environment runs only inside Alembic.
NEEDS_AN_EXTRA = {"sentinelapi.storage.redis_backend", "sentinelapi.audit.migrations.env"}


def main() -> None:
    modules = [m.name for m in pkgutil.walk_packages(sentinelapi.__path__, "sentinelapi.")]
    for name in modules:
        if name not in NEEDS_AN_EXTRA:
            importlib.import_module(name)
    print(f"imported {len(modules) - len(NEEDS_AN_EXTRA)} modules")


if __name__ == "__main__":
    main()
