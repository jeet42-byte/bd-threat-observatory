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

from sqlalchemy import select
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


def _chunks(seq: list, size: int):
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _row_names(row: dict) -> set[str]:
    names = split_names(row.get("name_value"))
    cn = clean_name(row.get("common_name", ""))
    if cn:
        names.add(cn)
    return names


async def persist_crtsh_rows(
    session: AsyncSession, rows: list[dict], keyword_count: int
) -> IngestStats:
    """Persist already-fetched crt.sh rows as new certs + domains.

    Batched to keep the database phase fast over a remote/serverless Postgres:
    existing certificate ids and domains are looked up in chunked ``IN`` queries
    rather than one round-trip per row (crt.sh can return tens of thousands of
    rows for a popular brand).
    """
    stats = IngestStats()
    stats.keywords_queried = keyword_count
    stats.rows_fetched = len(rows)

    # De-duplicate incoming rows by crt.sh entry id.
    by_id: dict[int, dict] = {}
    for row in rows:
        cid = row.get("id")
        if cid is not None:
            by_id.setdefault(cid, row)

    # Which certificates do we already have? (chunked IN query)
    existing_ids: set[int] = set()
    all_ids = list(by_id)
    for chunk in _chunks(all_ids, 5000):
        found = (
            await session.execute(
                select(Certificate.crtsh_id).where(Certificate.crtsh_id.in_(chunk))
            )
        ).scalars().all()
        existing_ids.update(found)

    new_ids = [cid for cid in all_ids if cid not in existing_ids]
    stats.certificates_skipped = len(all_ids) - len(new_ids)

    # Collect every domain name referenced by the new certificates.
    names_by_id: dict[int, set[str]] = {}
    all_names: set[str] = set()
    for cid in new_ids:
        names = _row_names(by_id[cid])
        names_by_id[cid] = names
        all_names.update(names)

    # Load existing domains, then create the missing ones (one flush).
    name_to_domain: dict[str, Domain] = {}
    name_list = list(all_names)
    for chunk in _chunks(name_list, 5000):
        for dom in (
            await session.execute(select(Domain).where(Domain.name.in_(chunk)))
        ).scalars().all():
            name_to_domain[dom.name] = dom

    for name in all_names:
        if name not in name_to_domain:
            registrable, tld = registrable_and_tld(name)
            dom = Domain(
                name=name, registrable_domain=registrable, tld=tld, source="ct"
            )
            session.add(dom)
            name_to_domain[name] = dom
            stats.domains_created += 1
    await session.flush()  # assign domain PKs for the certificate FKs

    # Insert the new certificates, anchored to their common name / first SAN.
    for cid in new_ids:
        names = names_by_id[cid]
        if not names:
            continue
        row = by_id[cid]
        cn = clean_name(row.get("common_name", ""))
        anchor = cn if cn in name_to_domain else next(iter(names))
        session.add(
            Certificate(
                domain_id=name_to_domain[anchor].id,
                crtsh_id=cid,
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
