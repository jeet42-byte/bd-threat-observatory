"""Pydantic response schemas for the public read-only API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class BrandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    slug: str
    name: str
    category: str


class ThreatOut(BaseModel):
    """A phishing finding, flattened with its brand and domain for the feed."""

    id: int
    domain: str
    registrable_domain: str
    tld: str
    brand_slug: str
    brand_name: str
    category: str
    risk_score: int
    confidence: str
    reasons: list[str]
    status: str
    report_count: int
    # Earliest TLS certificate issuance for this domain (Certificate
    # Transparency). A close proxy for when the domain went live - far more
    # meaningful than when our pipeline first ingested it. None if unknown.
    issued_at: datetime | None
    first_seen_at: datetime
    updated_at: datetime


class ThreatListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[ThreatOut]


class ReportOut(BaseModel):
    id: int
    domain: str
    report_count: int


class ConfidenceCount(BaseModel):
    confidence: str
    count: int


class BrandCount(BaseModel):
    brand_slug: str
    brand_name: str
    count: int


class StatsOut(BaseModel):
    total_findings: int
    total_domains: int
    total_certificates: int
    by_confidence: list[ConfidenceCount]
    top_brands: list[BrandCount]
    latest_finding_at: datetime | None


class PostureFinding(BaseModel):
    check: str
    status: str  # ok | warn | fail
    detail: str


class PostureOut(BaseModel):
    target: str
    brand_slug: str | None
    category: str
    grade: str
    score: int
    headers_score: int
    tls_score: int
    email_score: int
    reachable: bool
    findings: list[PostureFinding]
    checked_at: datetime


class PostureListOut(BaseModel):
    total: int
    items: list[PostureOut]
    grade_distribution: list[dict]
    average_score: float | None
