"""How much latency SentinelAPI adds to a request.

Calls the ASGI app directly, with no network and no HTTP client, so what is
measured is the middleware and its backend, not the transport. Three apps
answer the same endpoint: without SentinelAPI, with it on the memory
backend, and with it on Redis (when SENTINEL_BENCH_REDIS_URL is set). The
limits are set high enough that nothing is blocked: every request pays the
full check, a counter increment included. The audit sink is off, since it
writes only when there is an event.

    uv run python benchmarks/overhead.py --requests 20000
"""

from __future__ import annotations

import argparse
import asyncio
import os
import platform
import statistics
import time
from collections.abc import Callable
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Scope

from sentinelapi.config import SentinelSettings
from sentinelapi.integration import install_sentinel

SCOPE: Scope = {
    "type": "http",
    "asgi": {"version": "3.0"},
    "http_version": "1.1",
    "method": "GET",
    "scheme": "http",
    "path": "/orders",
    "raw_path": b"/orders",
    "root_path": "",
    "query_string": b"",
    "headers": [(b"host", b"bench"), (b"user-agent", b"benchmark")],
    "client": ("203.0.113.7", 50000),
    "server": ("bench", 80),
}


async def orders(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def bare_app() -> Starlette:
    return Starlette(routes=[Route("/orders", orders)])


def protected_app(**settings: Any) -> Starlette:
    app = bare_app()
    install_sentinel(
        app,
        SentinelSettings(_env_file=None, audit=False, rate_limit_max_requests=10**9, **settings),
    )
    return app


async def one_request(app: ASGIApp) -> None:
    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        return None

    await app(dict(SCOPE), receive, send)


async def measure(app: Starlette, requests: int, warmup: int) -> list[float]:
    """Milliseconds per request, after a warm-up, inside the app's lifespan."""
    async with app.router.lifespan_context(app):
        for _ in range(warmup):
            await one_request(app)
        timings = []
        for _ in range(requests):
            start = time.perf_counter()
            await one_request(app)
            timings.append((time.perf_counter() - start) * 1000)
    return timings


def percentiles(timings: list[float]) -> tuple[float, float, float]:
    cuts = statistics.quantiles(timings, n=100)
    return cuts[49], cuts[94], cuts[98]


async def main(requests: int, warmup: int) -> None:
    configurations: list[tuple[str, Callable[[], Starlette]]] = [
        ("without SentinelAPI", bare_app),
        ("memory backend", protected_app),
    ]
    redis_url = os.environ.get("SENTINEL_BENCH_REDIS_URL")
    if redis_url:
        configurations.append(
            ("Redis, same host", lambda: protected_app(backend="redis", redis_url=redis_url))
        )

    results: dict[str, tuple[float, float, float]] = {}
    for name, build in configurations:
        results[name] = percentiles(await measure(build(), requests, warmup))

    base = results["without SentinelAPI"]
    machine = f"{platform.system()} {platform.release()}, {platform.machine()}, {os.cpu_count()} logical CPUs"
    print(f"Python {platform.python_version()}, {machine}.")
    print(f"{requests} requests per configuration, after {warmup} of warm-up.\n")
    print("| Configuration | p50 | p95 | p99 | Added at p50 | Added at p95 |")
    print("| --- | --- | --- | --- | --- | --- |")
    for name, (p50, p95, p99) in results.items():
        added = "-" if name == "without SentinelAPI" else f"{p50 - base[0]:.3f} ms"
        added95 = "-" if name == "without SentinelAPI" else f"{p95 - base[1]:.3f} ms"
        print(f"| {name} | {p50:.3f} ms | {p95:.3f} ms | {p99:.3f} ms | {added} | {added95} |")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--requests", type=int, default=20_000)
    parser.add_argument("--warmup", type=int, default=1_000)
    args = parser.parse_args()
    asyncio.run(main(args.requests, args.warmup))
