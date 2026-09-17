"""Integration tests for the public API, backed by an in-process SQLite DB.

Sets DATABASE_URL to a temp SQLite file *before* importing the app, so the same
engine serves both the seeding and the HTTP requests. Proves the endpoints,
filters, and joins end-to-end without Postgres or network.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

# Point the app at a throwaway SQLite file before app modules import.
_DB_FD, _DB_PATH = tempfile.mkstemp(suffix=".sqlite")
os.close(_DB_FD)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_DB_PATH}"

from fastapi.testclient import TestClient  # noqa: E402

from app.db.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.db import models  # noqa: E402
from app.main import app  # noqa: E402


async def _prepare() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        brand = models.Brand(
            name="bKash", slug="bkash", category="mfs",
            keywords=["bkash"], official_domains=["bkash.com"],
        )
        session.add(brand)
        await session.flush()

        phishing = models.Domain(
            name="secure-bkash-reward.xyz",
            registrable_domain="secure-bkash-reward.xyz",
            tld="xyz", source="seed",
        )
        legit = models.Domain(
            name="benign-example.com",
            registrable_domain="benign-example.com",
            tld="com", source="seed",
        )
        session.add_all([phishing, legit])
        await session.flush()

        session.add(
            models.ThreatFinding(
                brand_id=brand.id, domain_id=phishing.id,
                risk_score=91, confidence="critical",
                reasons=["contains brand keyword 'bkash'", "suspicious TLD '.xyz'"],
                status="new",
            )
        )
        await session.commit()


@pytest.fixture(scope="module", autouse=True)
def _seed():
    asyncio.run(_prepare())
    yield
    os.unlink(_DB_PATH)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_threats_returns_finding(client):
    body = client.get("/api/v1/threats").json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["domain"] == "secure-bkash-reward.xyz"
    assert item["brand_slug"] == "bkash"
    assert item["confidence"] == "critical"
    assert any("bkash" in r for r in item["reasons"])


def test_threats_min_score_filter(client):
    assert client.get("/api/v1/threats?min_score=95").json()["total"] == 0
    assert client.get("/api/v1/threats?min_score=90").json()["total"] == 1


def test_threats_brand_and_confidence_filters(client):
    assert client.get("/api/v1/threats?brand=bkash").json()["total"] == 1
    assert client.get("/api/v1/threats?brand=nagad").json()["total"] == 0
    assert client.get("/api/v1/threats?confidence=low").json()["total"] == 0


def test_brands_endpoint(client):
    brands = client.get("/api/v1/brands").json()
    assert any(b["slug"] == "bkash" for b in brands)


def test_stats_endpoint(client):
    s = client.get("/api/v1/stats").json()
    assert s["total_findings"] == 1
    assert s["total_domains"] == 2
    assert any(c["confidence"] == "critical" for c in s["by_confidence"])
    assert s["top_brands"][0]["brand_slug"] == "bkash"


def test_posture_endpoint_empty_ok(client):
    # No posture rows seeded in this module; endpoint should still respond.
    body = client.get("/api/v1/posture").json()
    assert body["total"] == 0
    assert body["average_score"] is None
