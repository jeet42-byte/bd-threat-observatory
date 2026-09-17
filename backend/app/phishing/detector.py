"""Database-facing phishing detector: score domains, persist ThreatFindings.

Reads the Domain and Brand tables the ingestion core fills, runs the pure
matcher over every domain, and upserts a ThreatFinding per (brand, domain).
Idempotent: an existing finding is updated in place, never duplicated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Brand, Domain, ThreatFinding
from app.phishing.matcher import best_match


@dataclass
class DetectStats:
    domains_scanned: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"scanned={self.domains_scanned} new_findings={self.findings_created} "
            f"updated_findings={self.findings_updated} errors={len(self.errors)}"
        )


async def _load_brands(session: AsyncSession) -> tuple[list[dict], dict[str, int]]:
    """Return (brand dicts for the matcher, slug -> brand_id map)."""
    rows = (await session.execute(select(Brand))).scalars().all()
    brand_dicts = [
        {
            "slug": b.slug,
            "keywords": list(b.keywords or []),
            "official_domains": list(b.official_domains or []),
        }
        for b in rows
    ]
    slug_to_id = {b.slug: b.id for b in rows}
    return brand_dicts, slug_to_id


async def run_detection(session: AsyncSession) -> DetectStats:
    """Score every domain and upsert findings. Returns run statistics."""
    stats = DetectStats()
    brands, slug_to_id = await _load_brands(session)
    if not brands:
        print("[detector] no brands in DB; run ingestion/seed first")
        return stats

    domains = (await session.execute(select(Domain))).scalars().all()
    for dom in domains:
        stats.domains_scanned += 1
        match = best_match(dom.name, dom.registrable_domain, dom.tld, brands)
        if match is None:
            continue
        brand_id = slug_to_id.get(match.brand_slug)
        if brand_id is None:  # pragma: no cover - slug always present
            continue

        existing = (
            await session.execute(
                select(ThreatFinding).where(
                    ThreatFinding.brand_id == brand_id,
                    ThreatFinding.domain_id == dom.id,
                )
            )
        ).scalar_one_or_none()

        if existing is None:
            session.add(
                ThreatFinding(
                    brand_id=brand_id,
                    domain_id=dom.id,
                    risk_score=match.score,
                    confidence=match.confidence,
                    reasons=match.reasons,
                    status="new",
                )
            )
            stats.findings_created += 1
        else:
            existing.risk_score = match.score
            existing.confidence = match.confidence
            existing.reasons = match.reasons
            existing.updated_at = datetime.now(timezone.utc)
            stats.findings_updated += 1

    await session.commit()
    print(f"[detector] {stats.summary()}")
    return stats
