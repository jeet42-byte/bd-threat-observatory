"""Tests for DATABASE_URL normalisation (the deploy foot-gun guard)."""
from __future__ import annotations

from app.core.config import normalize_database_url


def test_plain_postgres_scheme_upgraded_to_asyncpg():
    assert normalize_database_url("postgresql://u:p@h/db") == (
        "postgresql+asyncpg://u:p@h/db"
    )
    assert normalize_database_url("postgres://u:p@h/db") == (
        "postgresql+asyncpg://u:p@h/db"
    )


def test_strips_libpq_only_query_params():
    got = normalize_database_url(
        "postgresql://u:p@h.neon.tech/db?sslmode=require&channel_binding=require"
    )
    assert got == "postgresql+asyncpg://u:p@h.neon.tech/db"


def test_already_asyncpg_is_unchanged():
    url = "postgresql+asyncpg://u:p@h/db"
    assert normalize_database_url(url) == url


def test_sqlite_passes_through():
    url = "sqlite+aiosqlite:///x.sqlite"
    assert normalize_database_url(url) == url
