"""Entry point for a posture scan run (used by the posture cron and locally).

    python -m app.posture.run_posture

Needs outbound network to reach org domains and public DNS; runs on GitHub
Actions.
"""
from __future__ import annotations

import asyncio

from app.db.database import AsyncSessionLocal
from app.db.init_db import init_db
from app.collectors.ct_collector import seed_brands
from app.posture.collector import run_posture


async def main() -> int:
    await init_db()
    async with AsyncSessionLocal() as session:
        await seed_brands(session)
        stats = await run_posture(session)
    print(f"[run_posture] done: {stats.summary()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
