"""Certificate Transparency collector: crt.sh -> Domain + Certificate rows.

This is the shared ingestion core. Both downstream products read what it
produces:

  * the phishing feed (Day 2) scores the discovered domains against brands
  * the posture observatory (Day 4) grades the discovered registrable domains

It is deliberately idempotent: certificates are de-duplicated by crt.sh entry
id, and domains by name, so re-running only adds what is genuinely new.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors import crtsh
from app.data.brands_seed import BRANDS
from app.db.models import Brand, Certificate, Domain
from app.utils.domains import (
    clean_name,
    parse_crtsh_timestamp,
    registrable_and_tld,
    split_names,
)


@dataclass
class IngestStats:
    keywords_queried: int = 0
    rows_fetched: int = 0
    domains_created: int = 0
    certificates_created: int = 0
    certificates_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"keywords={self.keywords_queried} rows={self.rows_fetched} "
            f"new_domains={self.domains_created} new_certs={self.certificates_created} "
            f"dup_certs={self.certificates_skipped} errors={len(self.errors)}"
        )


async def seed_brands(session: AsyncSession) -> int:
    """Insert any brands from the seed list that are not yet in the database."""
    existing = set(
        (await session.execute(select(Brand.slug))).scalars().all()
    )
    created = 0
    for entry in BRANDS:
        if entry["slug"] in existing:
            continue
        session.add(Brand(**entry))
        created += 1
    if created:
        await session.commit()
    print(f"[collector] seeded {created} new brand(s); {len(existing)} already present")
    return created


def _brand_keywords() -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for entry in BRANDS:
        for kw in entry["keywords"]:
            k = kw.lower().strip()
            if k and k not in seen:
                seen.add(k)
                ordered.append(k)
    return ordered


async def _get_or_create_domain(
    session: AsyncSession,
    cache: dict[str, Domain],
    name: str,
    stats: IngestStats,
) -> Domain:
    if name in cache:
        return cache[name]
    dom = (
        await session.execute(select(Domain).where(Domain.name == name))
    ).scalar_one_or_none()
    if dom is None:
        registrable, tld = registrable_and_tld(name)
        dom = Domain(
            name=name,
            registrable_domain=registrable,
            tld=tld,
            source="ct",
        )
        session.add(dom)
        await session.flush()  # assign PK for the certificate FK
        stats.domains_created += 1
    else:
        dom.last_seen_at = datetime.now(timezone.utc)
    cache[name] = dom
    return dom


async def fetch_crtsh_rows() -> tuple[list[dict], int]:
    """Fetch raw crt.sh rows for every brand keyword. No database involved.

    Kept separate from persistence so the (slow, minutes-long) network phase
    never holds a database connection open — important on serverless Postgres
    (e.g. Neon) that closes idle connections / scales compute to zero.
    """
    keywords = _brand_keywords()
    rows = await crtsh.search_keywords(keywords)
    return rows, len(keywords)


async def ingest_from_crtsh(session: AsyncSession) -> IngestStats:
    """Fetch from crt.sh then persist (convenience wrapper for local use)."""
    rows, keyword_count = await fetch_crtsh_rows()
    return await persist_crtsh_rows(session, rows, keyword_count)


async def persist_crtsh_rows(
    session: AsyncSession, rows: list[dict], keyword_count: int
) -> IngestStats:
    """Persist already-fetched crt.sh rows as new certs + domains."""
    stats = IngestStats()
    stats.keywords_queried = keyword_count
    stats.rows_fetched = len(rows)

    domain_cache: dict[str, Domain] = {}

    for row in rows:
        crtsh_id = row.get("id")
        if crtsh_id is None:
            continue

        # Skip certificates we already have (idempotent re-runs).
        exists = (
            await session.execute(
                select(func.count())
                .select_from(Certificate)
                .where(Certificate.crtsh_id == crtsh_id)
            )
        ).scalar_one()
        if exists:
            stats.certificates_skipped += 1
            continue

        # Discover every domain in the certificate (CN + all SANs). Each becomes
        # a Domain row so downstream products can see the full attack surface.
        names = split_names(row.get("name_value"))
        cn = clean_name(row.get("common_name", ""))
        if cn:
            names.add(cn)
        if not names:
            continue
        for name in names:
            await _get_or_create_domain(session, domain_cache, name, stats)

        # Anchor the certificate to its common name (or any discovered name).
        anchor = cn or next(iter(names))
        anchor_domain = domain_cache[anchor]

        session.add(
            Certificate(
                domain_id=anchor_domain.id,
                crtsh_id=crtsh_id,
                common_name=(row.get("common_name") or "")[:255] or None,
                issuer_name=(row.get("issuer_name") or "")[:500] or None,
                serial_number=(row.get("serial_number") or "")[:120] or None,
                not_before=parse_crtsh_timestamp(row.get("not_before")),
                not_after=parse_crtsh_timestamp(row.get("not_after")),
            )
        )
        stats.certificates_created += 1

    await session.commit()
    print(f"[collector] {stats.summary()}")
    return stats
