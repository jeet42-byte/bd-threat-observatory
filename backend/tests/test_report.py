"""Report generator test over in-process SQLite (network-free)."""
from __future__ import annotations

import asyncio
import os
import tempfile

_FD, _PATH = tempfile.mkstemp(suffix=".sqlite")
os.close(_FD)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_PATH}"

import pytest  # noqa: E402

from app.db.database import AsyncSessionLocal  # noqa: E402
from app.db.seed_mock import seed_mock  # noqa: E402
from app.report.generate import build_report  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _seed():
    asyncio.run(seed_mock())
    yield
    os.unlink(_PATH)


def test_report_contains_key_sections():
    async def _run() -> str:
        async with AsyncSessionLocal() as session:
            return await build_report(session)

    md = asyncio.run(_run())
    assert "# State of .bd Web Security" in md
    assert "## Posture grades" in md
    assert "Grade distribution" in md
    assert "Weakest postures" in md
    assert "## Phishing feed" in md
    # Seed produced 6 posture scans and 15 findings.
    assert "graded: **6**" in md
    assert "findings recorded: **15**" in md
