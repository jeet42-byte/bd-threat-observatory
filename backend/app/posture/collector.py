"""Posture collector: probe monitored org domains, score, persist PostureScan.

Targets are the authoritative domains of the monitored brands (banks, MFS,
telcos, gov). Each is scored on headers + TLS + email auth and graded A-F.
Idempotent: one row per target, updated in place.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Brand, PostureScan
from app.posture import probes
from app.posture.scoring import assess


@dataclass
class PostureStats:
    targets: int = 0
    scanned: int = 0
    unreachable: int = 0
    created: int = 0
    updated: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"targets={self.targets} scanned={self.scanned} "
            f"unreachable={self.unreachable} new={self.created} upd={self.updated}"
        )


async def _targets(session: AsyncSession) -> list[dict]:
    """Distinct (target, brand_slug, category) from brand official domains."""
    brands = (await session.execute(select(Brand))).scalars().all()
    seen: dict[str, dict] = {}
    for b in brands:
        for dom in b.official_domains or []:
            dom = dom.lower().strip()
            # Score the registrable site; skip deep paths/subpaths.
            if dom and dom not in seen:
                seen[dom] = {
                    "target": dom,
                    "brand_slug": b.slug,
                    "category": b.category,
                }
    return list(seen.values())


def scan_targets(targets: list[dict]) -> list[dict]:
    """Probe each target and score it. Pure network + CPU, no database.

    Returns a list of {target, brand_slug, category, result, reachable}. Kept
    DB-free so the probing phase never holds a connection open (serverless
    Postgres closes idle connections).
    """
    scored: list[dict] = []
    for t in targets:
        host = t["target"]
        headers = probes.probe_headers(host)
        tls = probes.probe_tls(host)
        dns = probes.probe_dns(host)
        reachable = headers is not None or tls is not None
        scored.append(
            {
                "target": host,
                "brand_slug": t["brand_slug"],
                "category": t["category"],
                "result": assess(headers or {}, tls or {}, dns),
                "reachable": reachable,
            }
        )
    return scored


async def persist_posture(session: AsyncSession, scored: list[dict]) -> PostureStats:
    """Upsert already-scored posture results. Database only."""
    stats = PostureStats()
    stats.targets = len(scored)
    for item in scored:
        stats.scanned += 1
        if not item["reachable"]:
            stats.unreachable += 1
        result = item["result"]
        host = item["target"]

        existing = (
            await session.execute(
                select(PostureScan).where(PostureScan.target == host)
            )
        ).scalar_one_or_none()

        if existing is None:
            session.add(
                PostureScan(
                    target=host,
                    brand_slug=item["brand_slug"],
                    category=item["category"],
                    grade=result.grade,
                    score=result.score,
                    headers_score=result.headers_score,
                    tls_score=result.tls_score,
                    email_score=result.email_score,
                    findings=result.findings,
                    reachable=item["reachable"],
                )
            )
            stats.created += 1
        else:
            existing.brand_slug = item["brand_slug"]
            existing.category = item["category"]
            existing.grade = result.grade
            existing.score = result.score
            existing.headers_score = result.headers_score
            existing.tls_score = result.tls_score
            existing.email_score = result.email_score
            existing.findings = result.findings
            existing.reachable = item["reachable"]
            existing.checked_at = datetime.now(timezone.utc)
            stats.updated += 1

    await session.commit()
    print(f"[posture] {stats.summary()}")
    return stats


async def load_targets(session: AsyncSession) -> list[dict]:
    """Public wrapper: the posture targets (brands' official domains)."""
    return await _targets(session)


async def run_posture(session: AsyncSession) -> PostureStats:
    """Probe then persist using one session (convenience for local use)."""
    targets = await _targets(session)
    scored = scan_targets(targets)
    return await persist_posture(session, scored)
