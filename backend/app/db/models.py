"""ORM models for the shared ingestion core.

Day 1 covers the entities every downstream product reads from:

    Brand        - a legitimate BD organisation we monitor (bKash, a bank, ...)
    Domain       - any domain name observed in the wild (from CT logs, DNS)
    Certificate  - a TLS certificate seen in Certificate Transparency logs

The phishing feed (Day 2) and the posture observatory (Day 4) add their own
tables that reference Domain, so this schema is deliberately product-neutral.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB

# JSONB on Postgres (indexable), plain JSON elsewhere (SQLite in tests/CI).
JSONType = JSON().with_variant(JSONB, "postgresql")
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class Brand(Base):
    """A legitimate organisation whose name attackers are likely to abuse."""

    __tablename__ = "brands"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    # mfs | bank | telco | gov | university | ecommerce | other
    category: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    # Tokens that, appearing in a domain, suggest impersonation ("bkash", "bkash-bd").
    keywords: Mapped[list[str]] = mapped_column(JSONType, default=list, nullable=False)
    # The brand's real, authoritative domains ("bkash.com"); used to exclude
    # legitimate certificates from the phishing feed.
    official_domains: Mapped[list[str]] = mapped_column(
        JSONType, default=list, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Brand {self.slug} ({self.category})>"


class Domain(Base):
    """Any domain name observed by a collector."""

    __tablename__ = "domains"
    __table_args__ = (
        Index("ix_domains_registrable", "registrable_domain"),
        Index("ix_domains_first_seen", "first_seen_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Full name as observed (may be a wildcard like *.example.com.bd).
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    # eTLD+1, e.g. "example.com.bd" - the unit we grade and score.
    registrable_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    tld: Mapped[str] = mapped_column(String(63), nullable=False, index=True)
    # ct | dns | seed
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    certificates: Mapped[list["Certificate"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Domain {self.name}>"


class Certificate(Base):
    """A TLS certificate observed in a Certificate Transparency log."""

    __tablename__ = "certificates"
    __table_args__ = (
        # crt.sh entry id uniquely identifies a logged certificate; the dedupe key.
        UniqueConstraint("crtsh_id", name="uq_certificates_crtsh_id"),
        Index("ix_certificates_not_after", "not_after"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # crt.sh min_cert_id / entry id.
    crtsh_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    common_name: Mapped[str | None] = mapped_column(String(255))
    issuer_name: Mapped[str | None] = mapped_column(String(500))
    serial_number: Mapped[str | None] = mapped_column(String(120))
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    domain: Mapped["Domain"] = relationship(back_populates="certificates")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Certificate crtsh_id={self.crtsh_id} cn={self.common_name}>"


class ThreatFinding(Base):
    """A domain flagged as likely impersonating a monitored brand.

    Produced by the phishing detector (Day 2). One row per (brand, domain):
    re-running detection updates the score in place rather than duplicating.
    """

    __tablename__ = "threat_findings"
    __table_args__ = (
        UniqueConstraint("brand_id", "domain_id", name="uq_finding_brand_domain"),
        Index("ix_findings_risk", "risk_score"),
        Index("ix_findings_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    brand_id: Mapped[int] = mapped_column(
        ForeignKey("brands.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # 0-100 heuristic risk score.
    risk_score: Mapped[int] = mapped_column(nullable=False, default=0)
    # low | medium | high | critical
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="low")
    # Human-readable signals that fired, e.g. ["brand keyword 'bkash'",
    # "suspicious TLD .xyz", "lure token 'reward'"].
    reasons: Mapped[list[str]] = mapped_column(JSONType, default=list, nullable=False)
    # new | reviewed | confirmed | dismissed  (workflow for later triage)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="new", index=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    brand: Mapped["Brand"] = relationship()
    domain: Mapped["Domain"] = relationship()

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ThreatFinding brand={self.brand_id} domain={self.domain_id} "
            f"risk={self.risk_score}>"
        )


class PostureScan(Base):
    """Latest passive security-posture assessment of a monitored org domain.

    Produced by the posture collector (Day 4). One row per target domain,
    updated in place on each scan (history can be added later).
    """

    __tablename__ = "posture_scans"
    __table_args__ = (
        UniqueConstraint("target", name="uq_posture_target"),
        Index("ix_posture_grade", "grade"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # The org's authoritative domain, e.g. "bkash.com".
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    brand_slug: Mapped[str | None] = mapped_column(String(120), index=True)
    category: Mapped[str] = mapped_column(String(40), nullable=False, default="other")

    grade: Mapped[str] = mapped_column(String(2), nullable=False, default="F")
    score: Mapped[int] = mapped_column(nullable=False, default=0)
    headers_score: Mapped[int] = mapped_column(nullable=False, default=0)
    tls_score: Mapped[int] = mapped_column(nullable=False, default=0)
    email_score: Mapped[int] = mapped_column(nullable=False, default=0)
    # List of {check, status: ok|warn|fail, detail}.
    findings: Mapped[list[dict]] = mapped_column(JSONType, default=list, nullable=False)
    # True when the target could not be reached (scored as unknown, not F).
    reachable: Mapped[bool] = mapped_column(default=True, nullable=False)

    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PostureScan {self.target} grade={self.grade}>"
