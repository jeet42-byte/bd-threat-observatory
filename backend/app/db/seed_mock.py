"""Insert synthetic domains + threat findings for demos and local development.

Lets the dashboard and API show realistic data before (or without) a live
Certificate Transparency run. Every domain here is fictional/illustrative.

    python -m app.db.seed_mock
"""
from __future__ import annotations

import asyncio

from sqlalchemy import select

from app.db.database import AsyncSessionLocal
from app.db.init_db import init_db
from app.db.models import Brand, Domain, PostureScan, ThreatFinding
from app.posture.scoring import assess
from app.collectors.ct_collector import seed_brands
from app.phishing.matcher import best_match
from app.data.brands_seed import BRANDS

# Fictional lookalike domains (illustrative; not real registrations).
MOCK_DOMAINS = [
    "secure-bkash-reward.xyz",
    "bkash-bonus-offer.top",
    "bkash-helpline-care.online",
    "nagad-cashback.online",
    "my-nagad-verify.click",
    "nagad-gift-winner.shop",
    "bkosh-helpline.info",
    "daraz-gift-winner.shop",
    "islamibank-otp-verify.top",
    "dbbl-rocket-refund.site",
    "grameenphone-recharge-bonus.xyz",
    "robi-lucky-draw.club",
    "banglalink-free-mb.link",
    "bracbank-secure-login.cyou",
    "citytouch-verify-account.buzz",
]


async def seed_mock() -> None:
    await init_db()
    async with AsyncSessionLocal() as session:
        await seed_brands(session)

        brand_rows = (await session.execute(select(Brand))).scalars().all()
        slug_to_id = {b.slug: b.id for b in brand_rows}

        created_domains = 0
        created_findings = 0
        for name in MOCK_DOMAINS:
            from app.utils.domains import registrable_and_tld

            registrable, tld = registrable_and_tld(name)

            dom = (
                await session.execute(select(Domain).where(Domain.name == name))
            ).scalar_one_or_none()
            if dom is None:
                dom = Domain(
                    name=name,
                    registrable_domain=registrable,
                    tld=tld,
                    source="seed",
                )
                session.add(dom)
                await session.flush()
                created_domains += 1

            match = best_match(name, registrable, tld, BRANDS)
            if match is None:
                continue
            brand_id = slug_to_id.get(match.brand_slug)
            if brand_id is None:
                continue
            exists = (
                await session.execute(
                    select(ThreatFinding).where(
                        ThreatFinding.brand_id == brand_id,
                        ThreatFinding.domain_id == dom.id,
                    )
                )
            ).scalar_one_or_none()
            if exists is None:
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
                created_findings += 1

        await session.commit()
        print(
            f"[seed_mock] domains+{created_domains} findings+{created_findings}"
        )
        await seed_posture(session)


# Synthetic posture inputs per target (illustrative, not measured).
MOCK_POSTURE = {
    "bkash.com": (
        {"Strict-Transport-Security": "max-age=63072000", "Content-Security-Policy": "default-src 'self'",
         "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
         "Permissions-Policy": "geolocation=()"},
        {"version": "TLSv1.3"}, {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject"},
    ),
    "grameenphone.com": (
        {"Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff",
         "X-Frame-Options": "SAMEORIGIN", "Referrer-Policy": "strict-origin"},
        {"version": "TLSv1.3"}, {"spf": "v=spf1 include:_spf", "dmarc": "v=DMARC1; p=quarantine"},
    ),
    "bracbank.com": (
        {"Strict-Transport-Security": "max-age=15768000", "X-Content-Type-Options": "nosniff"},
        {"version": "TLSv1.2"}, {"spf": "v=spf1 ~all", "dmarc": "v=DMARC1; p=none"},
    ),
    "nagad.com.bd": (
        {"X-Content-Type-Options": "nosniff"},
        {"version": "TLSv1.2"}, {"spf": "v=spf1", "dmarc": None},
    ),
    "sonalibank.com.bd": (
        {}, {"version": "TLSv1.2"}, {"spf": None, "dmarc": None},
    ),
    "ec.gov.bd": (
        {}, {"version": "TLSv1"}, {"spf": None, "dmarc": None},
    ),
}

# map target -> brand slug/category for display
def _posture_meta():
    meta = {}
    for entry in BRANDS:
        for dom in entry["official_domains"]:
            meta.setdefault(dom.lower(), (entry["slug"], entry["category"]))
    return meta


async def seed_posture(session) -> None:
    from sqlalchemy import select as _select
    meta = _posture_meta()
    created = 0
    for target, (headers, tls, dns) in MOCK_POSTURE.items():
        result = assess(headers, tls, dns)
        slug, category = meta.get(target, (None, "other"))
        existing = (
            await session.execute(_select(PostureScan).where(PostureScan.target == target))
        ).scalar_one_or_none()
        if existing is None:
            session.add(PostureScan(
                target=target, brand_slug=slug, category=category,
                grade=result.grade, score=result.score,
                headers_score=result.headers_score, tls_score=result.tls_score,
                email_score=result.email_score, findings=result.findings, reachable=True,
            ))
            created += 1
    await session.commit()
    print(f"[seed_mock] posture+{created}")


if __name__ == "__main__":
    asyncio.run(seed_mock())
