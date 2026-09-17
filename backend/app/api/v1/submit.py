"""/api/v1/submit - community submission of a scam URL (e.g. from an SMS).

Fills the gap that Certificate Transparency can't: URLs people receive by text.
The submitted URL is run through the same matcher; if it impersonates a
monitored brand it is added to the live feed and its report counter bumped.

Matched-only by design: a submission that does not resemble a monitored brand
is not added, so the endpoint can't be used to inject arbitrary domains.
"""
from __future__ import annotations

from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import SubmitIn, SubmitOut
from app.db.database import get_session
from app.db.models import Brand, Domain, ThreatFinding
from app.phishing.matcher import best_match
from app.utils.domains import clean_name, registrable_and_tld

router = APIRouter(prefix="/submit", tags=["submit"])


def _host_from_url(raw: str) -> str | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    host = urlparse(raw).hostname
    return clean_name(host or "")


@router.post("", response_model=SubmitOut)
async def submit_scam(
    payload: SubmitIn,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SubmitOut:
    host = _host_from_url(payload.url)
    if not host:
        return SubmitOut(matched=False, message="Could not read a domain from that URL.")

    registrable, tld = registrable_and_tld(host)

    brand_rows = (await session.execute(select(Brand))).scalars().all()
    brands = [
        {
            "slug": b.slug,
            "keywords": list(b.keywords or []),
            "official_domains": list(b.official_domains or []),
        }
        for b in brand_rows
    ]
    slug_to = {b.slug: b for b in brand_rows}

    match = best_match(host, registrable, tld, brands)
    if match is None:
        return SubmitOut(
            matched=False,
            domain=host,
            message="Thanks - recorded, but this domain doesn't resemble a monitored brand, so it wasn't added to the feed.",
        )

    brand = slug_to[match.brand_slug]

    dom = (
        await session.execute(select(Domain).where(Domain.name == host))
    ).scalar_one_or_none()
    if dom is None:
        dom = Domain(
            name=host, registrable_domain=registrable, tld=tld, source="submission"
        )
        session.add(dom)
        await session.flush()

    finding = (
        await session.execute(
            select(ThreatFinding).where(
                ThreatFinding.brand_id == brand.id,
                ThreatFinding.domain_id == dom.id,
            )
        )
    ).scalar_one_or_none()

    if finding is None:
        finding = ThreatFinding(
            brand_id=brand.id,
            domain_id=dom.id,
            risk_score=match.score,
            confidence=match.confidence,
            reasons=match.reasons,
            status="new",
            report_count=1,
        )
        session.add(finding)
        created = True
    else:
        finding.report_count = (finding.report_count or 0) + 1
        finding.risk_score = match.score
        finding.confidence = match.confidence
        finding.reasons = match.reasons
        created = False

    await session.commit()

    verb = "added to" if created else "already in"
    return SubmitOut(
        matched=True,
        domain=host,
        brand_name=brand.name,
        risk_score=finding.risk_score,
        confidence=finding.confidence,
        report_count=finding.report_count,
        message=f"Flagged as {finding.confidence} impersonation of {brand.name} — {verb} the feed.",
    )
