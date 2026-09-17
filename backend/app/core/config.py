"""Application configuration, loaded from environment variables.

All secrets (DATABASE_URL, API keys) come from the environment so the same
code runs locally, in GitHub Actions, and on Render without changes.
"""
from __future__ import annotations

from functools import lru_cache

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Query params that are libpq-only and make the asyncpg driver error.
_ASYNCPG_INCOMPATIBLE_PARAMS = {"sslmode", "channel_binding"}


def normalize_database_url(url: str) -> str:
    """Make any Postgres URL safe for the async (asyncpg) driver.

    - upgrades ``postgres://`` / ``postgresql://`` to ``postgresql+asyncpg://``
      (a plain scheme would select the sync psycopg2 driver, which we don't ship)
    - drops libpq-only query params (``sslmode``, ``channel_binding``) that
      asyncpg rejects; asyncpg negotiates TLS on its own.

    SQLite URLs (used in tests) pass through unchanged.
    """
    if url.startswith("sqlite"):
        return url
    parts = urlsplit(url)
    scheme = parts.scheme
    if scheme in {"postgres", "postgresql"} or (
        scheme.startswith("postgresql+") and "asyncpg" not in scheme
    ):
        scheme = "postgresql+asyncpg"
    query = urlencode(
        [(k, v) for k, v in parse_qsl(parts.query) if k not in _ASYNCPG_INCOMPATIBLE_PARAMS]
    )
    return urlunsplit((scheme, parts.netloc, parts.path, query, parts.fragment))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Core ---
    app_name: str = "BD Threat Observatory"
    environment: str = Field(default="development")

    # --- Database ---
    # Async SQLAlchemy URL, e.g.
    #   postgresql+asyncpg://user:pass@host/dbname
    # Falls back to a local Postgres for development.
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/bd_threat_obs"
    )

    # --- Ingestion tuning ---
    # crt.sh can be slow; keep timeouts bounded so a slow keyword fails fast.
    ct_http_timeout: float = Field(default=20.0)
    ct_max_results_per_brand: int = Field(default=300)
    # Overall wall-clock budget for one crt.sh sweep. Past this, ingestion stops
    # starting new queries and persists what it has (keeps the job well under
    # its timeout and never commits nothing).
    ct_run_budget_seconds: int = Field(default=600)
    # Max findings to enrich (RDAP + reputation) per run; bounds runtime/rate.
    enrich_max_per_run: int = Field(default=80)
    # Re-enrich a finding only if older than this many days.
    enrich_ttl_days: int = Field(default=7)
    # Optional Google Safe Browsing API key (enables that intel source).
    gsb_api_key: str = Field(default="")
    # Only certificates first-seen within this many days are considered "new"
    # for the live feed. Backfill ignores this.
    ct_recent_days: int = Field(default=7)

    # --- API ---
    api_v1_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    @field_validator("database_url")
    @classmethod
    def _normalize_db_url(cls, v: str) -> str:
        return normalize_database_url(v)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
