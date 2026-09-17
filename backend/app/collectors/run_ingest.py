"""Entry point for a single ingestion run (used by the cron job and locally).

    python -m app.collectors.run_ingest

Steps: fetch from CT (network) -> ensure schema -> seed brands -> persist ->
detect phishing. The slow crt.sh fetch happens BEFORE any database connection
is opened, so serverless Postgres never sees a long-idle connection.
Exits non-zero on fatal error so CI surfaces failures.
"""
from __future__ import annotations

import asyncio
import sys

from app.db.database import AsyncSessionLocal
from app.db.init_db import init_db
from app.collectors.ct_collector import (
    fetch_crtsh_rows,
    persist_crtsh_rows,
    seed_brands,
)
from app.phishing.detector import run_detection


async def main() -> int:
    # 1) Network phase first — no DB connection held during the slow fetch.
    rows, keyword_count = await fetch_crtsh_rows()

    # 2) DB phase — fast, all connections used freshly here.
    await init_db()
    async with AsyncSessionLocal() as session:
        await seed_brands(session)
        stats = await persist_crtsh_rows(session, rows, keyword_count)
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
