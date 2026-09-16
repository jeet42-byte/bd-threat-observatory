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
from sqlalchemy.dialects.postgresql import JSONB
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
    keywords: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    # The brand's real, authoritative domains ("bkash.com"); used to exclude
    # legitimate certificates from the phishing feed.
    official_domains: Mapped[list[str]] = mapped_column(
        JSONB, default=list, nullable=False
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
