"""Database-facing phishing detector: score domains, persist ThreatFindings.

Reads the Domain and Brand tables the ingestion core fills, runs the pure
matcher over every domain, and upserts a ThreatFinding per (brand, domain).
Idempotent: an existing finding is updated in place, never duplicated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Brand, Domain, ThreatFinding
from app.phishing.matcher import best_match


@dataclass
class DetectStats:
    domains_scanned: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    findings_removed: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"scanned={self.domains_scanned} new_findings={self.findings_created} "
            f"updated_findings={self.findings_updated} "
            f"removed_findings={self.findings_removed} errors={len(self.errors)}"
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

    # 1) Score every domain in memory (pure, no DB writes during the scan).
    domains = (await session.execute(select(Domain))).scalars().all()
    matched: dict[int, tuple[int, object]] = {}  # domain_id -> (brand_id, match)
    for dom in domains:
        stats.domains_scanned += 1
        match = best_match(dom.name, dom.registrable_domain, dom.tld, brands)
        if match is None:
            continue
        brand_id = slug_to_id.get(match.brand_slug)
        if brand_id is not None:
            matched[dom.id] = (brand_id, match)

    # 2) Load existing findings once; compute what to keep vs. remove.
    existing = (await session.execute(select(ThreatFinding))).scalars().all()
    existing_by_key = {(f.domain_id, f.brand_id): f for f in existing}
    wanted_keys = {(did, bid) for did, (bid, _m) in matched.items()}

    # Bulk-delete findings that are no longer valid (former false positives or
    # re-attributions), in chunks - no per-row round-trips.
    stale_ids = [f.id for key, f in existing_by_key.items() if key not in wanted_keys]
    for i in range(0, len(stale_ids), 5000):
        chunk = stale_ids[i : i + 5000]
        await session.execute(
            delete(ThreatFinding).where(ThreatFinding.id.in_(chunk))
        )
    stats.findings_removed = len(stale_ids)

    # 3) Upsert the current matches (one flush at commit).
    now = datetime.now(timezone.utc)
    for domain_id, (brand_id, match) in matched.items():
        finding = existing_by_key.get((domain_id, brand_id))
        if finding is None:
            session.add(
                ThreatFinding(
                    brand_id=brand_id,
                    domain_id=domain_id,
                    risk_score=match.score,
                    confidence=match.confidence,
                    reasons=match.reasons,
                    status="new",
                )
            )
            stats.findings_created += 1
        else:
            finding.risk_score = match.score
            finding.confidence = match.confidence
            finding.reasons = match.reasons
            finding.updated_at = now
            stats.findings_updated += 1

    await session.commit()
    print(f"[detector] {stats.summary()}")
    return stats
