"""/api/v1/threats - the public phishing feed."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ReportOut, ThreatListOut, ThreatOut
from app.db.database import get_session
from app.db.models import Brand, Certificate, Domain, ThreatFinding

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

    # Earliest certificate issuance per domain - our proxy for "domain went
    # live", shown instead of pipeline ingestion time.
    issued = (
        select(
            Certificate.domain_id.label("domain_id"),
            func.min(Certificate.not_before).label("issued_at"),
        )
        .group_by(Certificate.domain_id)
        .subquery()
    )

    base = (
        select(ThreatFinding, Domain, Brand, issued.c.issued_at)
        .join(Domain, ThreatFinding.domain_id == Domain.id)
        .join(Brand, ThreatFinding.brand_id == Brand.id)
        .join(issued, issued.c.domain_id == Domain.id, isouter=True)
        .where(*filters)
    )

    total = (
        await session.execute(
            select(func.count())
            .select_from(
                select(ThreatFinding.id)
                .join(Brand, ThreatFinding.brand_id == Brand.id)
                .where(*filters)
                .subquery()
            )
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
            report_count=f.report_count,
            issued_at=issued_at,
            first_seen_at=f.first_seen_at,
            updated_at=f.updated_at,
        )
        for f, d, b, issued_at in rows
    ]
    return ThreatListOut(total=total, limit=limit, offset=offset, items=items)


@router.post("/{finding_id}/report", response_model=ReportOut)
async def report_threat(
    finding_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ReportOut:
    """Record a community "this is a scam" report, incrementing the counter.

    A high count helps separate confirmed-abusive domains from false positives.
    No authentication (portfolio demo); treat the count as a community signal,
    not a verified figure.
    """
    finding = (
        await session.execute(
            select(ThreatFinding).where(ThreatFinding.id == finding_id)
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    finding.report_count = (finding.report_count or 0) + 1
    await session.commit()

    domain = (
        await session.execute(
            select(Domain.name).where(Domain.id == finding.domain_id)
        )
    ).scalar_one()
    return ReportOut(id=finding.id, domain=domain, report_count=finding.report_count)
