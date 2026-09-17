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
from app.posture.collector import load_targets, persist_posture, scan_targets


async def main() -> int:
    await init_db()
    # 1) Load targets (quick DB read).
    async with AsyncSessionLocal() as session:
        await seed_brands(session)
        targets = await load_targets(session)

    # 2) Probe every target (network only — no DB connection held).
    scored = scan_targets(targets)

    # 3) Persist (fast DB write phase).
    async with AsyncSessionLocal() as session:
        stats = await persist_posture(session, scored)
    print(f"[run_posture] done: {stats.summary()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
