"""/api/v1/posture - the security-posture observatory."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import PostureFinding, PostureListOut, PostureOut
from app.db.database import get_session
from app.db.models import PostureScan

router = APIRouter(prefix="/posture", tags=["posture"])


@router.get("", response_model=PostureListOut)
async def list_posture(
    session: Annotated[AsyncSession, Depends(get_session)],
    category: str | None = Query(default=None),
    grade: str | None = Query(default=None),
    brand: str | None = Query(default=None),
) -> PostureListOut:
    filters = []
    if category:
        filters.append(PostureScan.category == category)
    if grade:
        filters.append(PostureScan.grade == grade)
    if brand:
        filters.append(PostureScan.brand_slug == brand)

    rows = (
        await session.execute(
            select(PostureScan)
            .where(*filters)
            .order_by(PostureScan.score.desc(), PostureScan.target)
        )
    ).scalars().all()

    dist = (
        await session.execute(
            select(PostureScan.grade, func.count()).group_by(PostureScan.grade)
        )
    ).all()
    avg = (
        await session.execute(select(func.avg(PostureScan.score)))
    ).scalar_one()

    items = [
        PostureOut(
            target=r.target,
            brand_slug=r.brand_slug,
            category=r.category,
            grade=r.grade,
            score=r.score,
            headers_score=r.headers_score,
            tls_score=r.tls_score,
            email_score=r.email_score,
            reachable=r.reachable,
            findings=[PostureFinding(**f) for f in (r.findings or [])],
            checked_at=r.checked_at,
        )
        for r in rows
    ]
    return PostureListOut(
        total=len(items),
        items=items,
        grade_distribution=[{"grade": g, "count": n} for g, n in sorted(dist)],
        average_score=round(float(avg), 1) if avg is not None else None,
    )
