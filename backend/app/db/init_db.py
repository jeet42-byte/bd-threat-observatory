"""Create database schema and required extensions.

Day 1 uses ``create_all`` for simplicity; Alembic migrations are wired in
later. Safe to run repeatedly (idempotent).
"""
from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.db.database import Base, engine
from app.db import models  # noqa: F401  (register models on Base.metadata)


async def init_db() -> None:
    async with engine.begin() as conn:
        # pg_trgm powers fuzzy domain similarity on Postgres; skip on SQLite
        # (used for local demos / tests), which has no extension mechanism.
        if conn.dialect.name == "postgresql":
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm;"))
        await conn.run_sync(Base.metadata.create_all)
    print("[init_db] schema ready")


if __name__ == "__main__":
    asyncio.run(init_db())
