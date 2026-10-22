from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sentinelapi.audit.models import Base


def create_engine_and_sessionmaker(database_url: str):
    engine = create_async_engine(database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return engine, session_factory


async def init_models(engine) -> None:
    """Creates tables if they don't exist. Fine for a demo/small service;
    swap for Alembic migrations before this touches a shared production
    database with other schema owners."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@asynccontextmanager
async def session_scope(session_factory) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session
