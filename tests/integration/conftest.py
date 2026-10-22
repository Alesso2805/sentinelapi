from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from examples.demo_app.main import create_app
from sentinelapi.audit.migrate import upgrade
from sentinelapi.config import SentinelSettings

TEST_JWT_SECRET = "integration-test-secret-0123456789abcdef"
TEST_OPERATOR_TOKEN = "integration-test-operator-token"
OPERATOR = {"Authorization": f"Bearer {TEST_OPERATOR_TOKEN}"}
ALICE_LOGIN = {"username": "alice@example.com", "password": "correct-horse-battery-staple"}

ClientFactory = Callable[..., AbstractAsyncContextManager[AsyncClient]]


@pytest.fixture
def make_client(tmp_path: Path) -> ClientFactory:
    @asynccontextmanager
    async def make(**overrides: Any) -> AsyncIterator[AsyncClient]:
        defaults: dict[str, Any] = {
            "backend": "memory",
            "jwt_secret": TEST_JWT_SECRET,
            "operator_token": TEST_OPERATOR_TOKEN,
            "database_url": f"sqlite+aiosqlite:///{(tmp_path / 'audit.db').as_posix()}",
        }
        settings = SentinelSettings(_env_file=None, **{**defaults, **overrides})
        await upgrade(settings.database_url)
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                yield client

    return make


@pytest.fixture
async def client(make_client: ClientFactory) -> AsyncIterator[AsyncClient]:
    async with make_client() as client:
        yield client
