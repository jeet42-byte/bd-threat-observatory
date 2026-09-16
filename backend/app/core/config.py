"""Application configuration, loaded from environment variables.

All secrets (DATABASE_URL, API keys) come from the environment so the same
code runs locally, in GitHub Actions, and on Render without changes.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    # crt.sh can be slow; keep timeouts generous but bounded.
    ct_http_timeout: float = Field(default=30.0)
    ct_max_results_per_brand: int = Field(default=1000)
    # Only certificates first-seen within this many days are considered "new"
    # for the live feed. Backfill ignores this.
    ct_recent_days: int = Field(default=7)

    # --- API ---
    api_v1_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
