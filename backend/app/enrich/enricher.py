"""Enrich current findings with RDAP + open-source threat intel.

Runs after detection. Bounded (``enrich_max_per_run``) and rate-limited so it
stays polite and within the job budget; skips findings enriched recently
(``enrich_ttl_days``). Network happens here, not while holding results - each
finding is fetched then written. Runs in GitHub Actions.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import Domain, ThreatFinding
from app.enrich import rdap, reputation

_GAP_SECONDS = 1.0


@dataclass
class EnrichStats:
    considered: int = 0
    enriched: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return f"considered={self.considered} enriched={self.enriched} errors={len(self.errors)}"


async def _targets(session: AsyncSession) -> list[tuple[int, str]]:
    """(finding_id, registrable_domain) for findings needing enrichment.

    Highest risk first; never enriched, or older than the TTL.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.enrich_ttl_days)
    rows = (
        await session.execute(
            select(ThreatFinding.id, Domain.registrable_domain)
            .join(Domain, ThreatFinding.domain_id == Domain.id)
            .where(
                or_(
                    ThreatFinding.enriched_at.is_(None),
                    ThreatFinding.enriched_at < cutoff,
                )
            )
            .order_by(ThreatFinding.risk_score.desc())
            .limit(settings.enrich_max_per_run)
        )
    ).all()
    return [(r[0], r[1]) for r in rows]


async def run_enrichment(session: AsyncSession) -> EnrichStats:
    stats = EnrichStats()
    targets = await _targets(session)
    stats.considered = len(targets)
    if not targets:
        print("[enrich] nothing to enrich")
        return stats

    timeout = httpx.Timeout(20.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for i, (finding_id, domain) in enumerate(targets):
            if i:
                await asyncio.sleep(_GAP_SECONDS)
            try:
                rd = await rdap.lookup(client, domain)
                intel = await reputation.lookup(client, domain)
            except Exception as exc:  # noqa: BLE001 - never abort the batch
                stats.errors.append(f"{domain}: {exc}")
                continue

            finding = (
                await session.execute(
                    select(ThreatFinding).where(ThreatFinding.id == finding_id)
                )
            ).scalar_one_or_none()
            if finding is None:
                continue
            finding.registrar = (rd.registrar or None)
            finding.registrant_org = (rd.registrant_org or None)
            finding.registrant_country = (rd.registrant_country or None)
            finding.domain_created_at = rd.created_at
            finding.intel = intel
            finding.enriched_at = datetime.now(timezone.utc)
            stats.enriched += 1

    await session.commit()
    print(f"[enrich] {stats.summary()}")
    return stats
