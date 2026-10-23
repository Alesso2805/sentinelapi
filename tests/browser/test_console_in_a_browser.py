"""The attack console in a real browser: it works with the keyboard alone,
its live stream arrives, and axe-core finds no serious or critical violation
before a run, after one, and in the dark theme.

Needs Chromium: `uv run playwright install chromium`. CI runs it in its own job.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from axe_playwright_python.async_playwright import Axe
from playwright.async_api import Page, async_playwright, expect

from examples.demo_app.main import create_app
from sentinelapi.audit.migrate import upgrade
from sentinelapi.config import SentinelSettings

pytestmark = pytest.mark.browser


@pytest.fixture
def server(tmp_path: Path) -> Iterator[str]:
    database_url = f"sqlite+aiosqlite:///{(tmp_path / 'audit.db').as_posix()}"
    asyncio.run(upgrade(database_url))
    app = create_app(
        SentinelSettings(
            _env_file=None,
            demo_mode=True,
            backend="memory",
            database_url=database_url,
            jwt_secret="browser-test-secret-0123456789abcdef",
        )
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        assert time.monotonic() < deadline, "the server did not start"
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


async def serious_violations(page: Page) -> list[str]:
    results = await Axe().run(page)
    return [
        f"{v['id']}: {v['help']}"
        for v in results.response["violations"]
        if v["impact"] in ("serious", "critical")
    ]


async def test_the_console_works_with_the_keyboard_and_passes_axe(server: str) -> None:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        try:
            page = await browser.new_page()
            await page.goto(server)
            await expect(page.locator("#stream-state")).to_contain_text("Live")
            assert await serious_violations(page) == []

            # The keyboard alone: past the skip link, the first attack's button.
            await page.keyboard.press("Tab")
            await page.keyboard.press("Tab")
            assert await page.evaluate("document.activeElement.dataset.scenario") == "burst"
            await page.keyboard.press("Enter")
            await expect(page.locator("#summary")).to_contain_text("From request 61 on")
            assert await page.locator("#steps tbody tr").count() == 70
            await expect(page.locator("#events li").first).to_contain_text("rate limit exceeded")
            assert await page.evaluate("document.activeElement.dataset.scenario") == "burst"
            assert await serious_violations(page) == []

            await page.emulate_media(color_scheme="dark")
            assert await serious_violations(page) == []
        finally:
            await browser.close()
