"""FastAPI application: the public read-only intelligence API.

Mostly read-only: it exposes what the ingestion + detection pipeline has found.
The one write is a community "report this scam" counter (POST /threats/{id}/report).
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import brands, posture, stats, submit, threats
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version="0.4.0",
    description=(
        "Passive security intelligence for Bangladesh's public web. "
        "Phishing/scam-domain feed derived from Certificate Transparency. "
        "OSINT only - no scanning or probing."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _ensure_schema() -> None:
    """Self-migrate on deploy: ensure new columns exist. Best-effort so the
    API still starts if the database is briefly unreachable."""
    try:
        from app.db.init_db import init_db

        await init_db()
    except Exception as exc:  # noqa: BLE001 - never block startup on this
        print(f"[startup] schema ensure skipped: {exc}")


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


api = settings.api_v1_prefix
app.include_router(threats.router, prefix=api)
app.include_router(brands.router, prefix=api)
app.include_router(stats.router, prefix=api)
app.include_router(posture.router, prefix=api)
app.include_router(submit.router, prefix=api)
