"""Low-level client for crt.sh, a public Certificate Transparency search.

crt.sh exposes a JSON endpoint that returns logged certificates matching a
query. We use it in batch (from a scheduled job) rather than a streaming
websocket, which suits GitHub Actions cron and avoids a long-lived process.

Only public certificate metadata is read. Nothing is scanned or probed.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings

CRTSH_URL = "https://crt.sh/"

# crt.sh is community-run and rate-sensitive; be a polite client.
_REQUEST_GAP_SECONDS = 1.0


class CrtShError(RuntimeError):
    """Raised when crt.sh cannot be queried after retries."""


@retry(
    reraise=True,
    stop=stop_after_attempt(2),  # crt.sh wildcard scans are slow; fail fast
    wait=wait_exponential(multiplier=2, min=2, max=8),
    retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
)
async def _fetch(client: httpx.AsyncClient, query: str) -> list[dict]:
    """Fetch raw certificate rows for a single crt.sh query with backoff."""
    resp = await client.get(
        CRTSH_URL,
        params={"q": query, "output": "json"},
        headers={"User-Agent": "bd-threat-observatory/0.1 (+github.com/jeet42-byte)"},
    )
    resp.raise_for_status()
    if not resp.text.strip():
        return []
    try:
        data = resp.json()
    except ValueError as exc:  # crt.sh occasionally returns malformed JSON
        raise CrtShError(f"crt.sh returned non-JSON for query {query!r}") from exc
    return data if isinstance(data, list) else []


async def search_keyword(client: httpx.AsyncClient, keyword: str) -> list[dict]:
    """Return raw crt.sh rows whose identity contains ``keyword``.

    The ``%`` wildcards make crt.sh match the token anywhere in the certificate
    identity (common name or SAN), e.g. ``%bkash%``.
    """
    query = f"%{keyword}%"
    rows = await _fetch(client, query)
    if settings.ct_max_results_per_brand:
        rows = rows[: settings.ct_max_results_per_brand]
    return rows


async def search_keywords(keywords: Iterable[str]) -> list[dict]:
    """Query crt.sh for many keywords, spacing requests to stay polite.

    Returns the concatenated raw rows; de-duplication happens downstream by
    crt.sh entry id when the rows are persisted.

    crt.sh can be very slow or flaky, so the loop enforces an overall time
    budget (``ct_run_budget_seconds``): once exceeded it stops starting new
    queries and returns what it has, guaranteeing the run finishes and the
    collected rows get persisted rather than the job timing out with nothing.
    """
    results: list[dict] = []
    budget = settings.ct_run_budget_seconds
    started = time.monotonic()
    timeout = httpx.Timeout(settings.ct_http_timeout)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for i, keyword in enumerate(keywords):
            if budget and time.monotonic() - started > budget:
                print(f"[crtsh] time budget {budget}s reached; stopping early")
                break
            if i:
                await asyncio.sleep(_REQUEST_GAP_SECONDS)
            try:
                rows = await search_keyword(client, keyword)
            except (httpx.HTTPError, CrtShError) as exc:
                # One bad keyword should not abort the whole run.
                print(f"[crtsh] WARN keyword={keyword!r} failed: {exc}")
                continue
            print(f"[crtsh] keyword={keyword!r} -> {len(rows)} rows")
            results.extend(rows)
    return results
