"""/api/v1/threats - the public phishing feed."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ThreatListOut, ThreatOut
from app.db.database import get_session
from app.db.models import Brand, Domain, ThreatFinding

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("", response_model=ThreatListOut)
async def list_threats(
    session: Annotated[AsyncSession, Depends(get_session)],
    brand: str | None = Query(default=None, description="Filter by brand slug"),
    confidence: str | None = Query(
        default=None, description="low | medium | high | critical"
    ),
    min_score: int = Query(default=0, ge=0, le=100),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> ThreatListOut:
    """Return scored phishing findings, newest first, with filters."""
    filters = [ThreatFinding.risk_score >= min_score]
    if confidence:
        filters.append(ThreatFinding.confidence == confidence)
    if status:
        filters.append(ThreatFinding.status == status)
    if brand:
        filters.append(Brand.slug == brand)

    base = (
        select(ThreatFinding, Domain, Brand)
        .join(Domain, ThreatFinding.domain_id == Domain.id)
        .join(Brand, ThreatFinding.brand_id == Brand.id)
        .where(*filters)
    )

    total = (
        await session.execute(
            select(func.count()).select_from(base.subquery())
        )
    ).scalar_one()

    rows = (
        await session.execute(
            base.order_by(
                ThreatFinding.risk_score.desc(),
                ThreatFinding.first_seen_at.desc(),
            )
            .limit(limit)
            .offset(offset)
        )
    ).all()

    items = [
        ThreatOut(
            id=f.id,
            domain=d.name,
            registrable_domain=d.registrable_domain,
            tld=d.tld,
            brand_slug=b.slug,
            brand_name=b.name,
            category=b.category,
            risk_score=f.risk_score,
            confidence=f.confidence,
            reasons=list(f.reasons or []),
            status=f.status,
            first_seen_at=f.first_seen_at,
            updated_at=f.updated_at,
        )
        for f, d, b in rows
    ]
    return ThreatListOut(total=total, limit=limit, offset=offset, items=items)
