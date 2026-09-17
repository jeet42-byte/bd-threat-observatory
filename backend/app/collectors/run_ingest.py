"""Entry point for a single ingestion run (used by the cron job and locally).

    python -m app.collectors.run_ingest

Steps: ensure schema -> seed brands -> collect from CT -> detect phishing.
Exits non-zero on fatal error so CI surfaces failures.
"""
from __future__ import annotations

import asyncio
import sys

from app.db.database import AsyncSessionLocal
from app.db.init_db import init_db
from app.collectors.ct_collector import ingest_from_crtsh, seed_brands
from app.phishing.detector import run_detection


async def main() -> int:
    await init_db()
    async with AsyncSessionLocal() as session:
        await seed_brands(session)
        stats = await ingest_from_crtsh(session)
        detect_stats = await run_detection(session)
    print(f"[run_ingest] ingest: {stats.summary()}")
    print(f"[run_ingest] detect: {detect_stats.summary()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:  # pragma: no cover
        print("[run_ingest] interrupted", file=sys.stderr)
        raise SystemExit(130)
