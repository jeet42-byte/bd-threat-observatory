"""/api/v1/brands - the monitored brand list."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import BrandOut
from app.db.database import get_session
from app.db.models import Brand

router = APIRouter(prefix="/brands", tags=["brands"])


@router.get("", response_model=list[BrandOut])
async def list_brands(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[Brand]:
    rows = (
        await session.execute(select(Brand).order_by(Brand.category, Brand.name))
    ).scalars().all()
    return list(rows)
