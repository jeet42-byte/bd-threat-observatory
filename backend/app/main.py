"""FastAPI application: the public read-only intelligence API.

Read-only by design: it exposes what the ingestion + detection pipeline has
found. All writes happen in the scheduled collectors, never over HTTP.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import brands, stats, threats
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version="0.3.0",
    description=(
        "Passive security intelligence for Bangladesh's public web. "
        "Phishing/scam-domain feed derived from Certificate Transparency. "
        "OSINT only - no scanning or probing."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


api = settings.api_v1_prefix
app.include_router(threats.router, prefix=api)
app.include_router(brands.router, prefix=api)
app.include_router(stats.router, prefix=api)
