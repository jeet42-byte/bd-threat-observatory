"""/api/v1/stats - headline counts for the dashboard."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import BrandCount, ConfidenceCount, StatsOut
from app.db.database import get_session
from app.db.models import Brand, Certificate, Domain, ThreatFinding

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsOut)
async def get_stats(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> StatsOut:
    total_findings = (
        await session.execute(select(func.count()).select_from(ThreatFinding))
    ).scalar_one()
    total_domains = (
        await session.execute(select(func.count()).select_from(Domain))
    ).scalar_one()
    total_certificates = (
        await session.execute(select(func.count()).select_from(Certificate))
    ).scalar_one()

    by_conf = (
        await session.execute(
            select(ThreatFinding.confidence, func.count())
            .group_by(ThreatFinding.confidence)
        )
    ).all()

    top = (
        await session.execute(
            select(Brand.slug, Brand.name, func.count(ThreatFinding.id))
            .join(ThreatFinding, ThreatFinding.brand_id == Brand.id)
            .group_by(Brand.slug, Brand.name)
            .order_by(func.count(ThreatFinding.id).desc())
            .limit(10)
        )
    ).all()

    latest = (
        await session.execute(select(func.max(ThreatFinding.first_seen_at)))
    ).scalar_one()

    return StatsOut(
        total_findings=total_findings,
        total_domains=total_domains,
        total_certificates=total_certificates,
        by_confidence=[
            ConfidenceCount(confidence=c or "unknown", count=n) for c, n in by_conf
        ],
        top_brands=[
            BrandCount(brand_slug=s, brand_name=nm, count=n) for s, nm, n in top
        ],
        latest_finding_at=latest,
    )
