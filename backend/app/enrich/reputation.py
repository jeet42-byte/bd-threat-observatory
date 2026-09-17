"""Open-source threat-intel reputation lookups.

Reports what public sources already know about a domain, rather than asserting
"the scam done" (which we cannot verify). Returns a list of intel items:

    {"source": str, "status": "malicious"|"listed"|"clean"|"unknown",
     "detail": str, "url": str}

Sources:
  - urlscan.io search  - free, no key: has the domain been scanned, and did any
    scan get a malicious verdict.
  - Google Safe Browsing - only if GSB_API_KEY is set (optional).

Best-effort: network failures yield no item for that source, never an error.
Parsing is separated from the network for offline tests.
"""
from __future__ import annotations

import httpx

from app.core.config import settings

_TIMEOUT = 15.0
_UA = "bd-threat-observatory/0.5 (+github.com/jeet42-byte)"

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def parse_urlscan(domain: str, data: dict) -> dict:
    """Summarise a urlscan.io search response into one intel item."""
    results = data.get("results", []) or []
    n = len(results)
    malicious = 0
    for r in results:
        verdict = (r.get("verdicts") or {}).get("overall") or {}
        if verdict.get("malicious"):
            malicious += 1
    search_url = f"https://urlscan.io/search/#domain%3A{domain}"
    if n == 0:
        return {
            "source": "urlscan.io",
            "status": "unknown",
            "detail": "no public scans found",
            "url": search_url,
        }
    if malicious:
        return {
            "source": "urlscan.io",
            "status": "malicious",
            "detail": f"{malicious} of {n} scans flagged malicious",
            "url": search_url,
        }
    return {
        "source": "urlscan.io",
        "status": "listed",
        "detail": f"{n} public scan(s), none flagged malicious",
        "url": search_url,
    }


def parse_gsb(domain: str, data: dict) -> dict | None:
    """Summarise a Google Safe Browsing response, or None if clean/no key."""
    matches = data.get("matches") or []
    if not matches:
        return None
    types = sorted({m.get("threatType", "THREAT") for m in matches})
    return {
        "source": "Google Safe Browsing",
        "status": "malicious",
        "detail": ", ".join(t.lower().replace("_", " ") for t in types),
        "url": f"https://transparencyreport.google.com/safe-browsing/search?url={domain}",
    }


async def _urlscan(client: httpx.AsyncClient, domain: str) -> dict | None:
    try:
        resp = await client.get(
            URLSCAN_SEARCH,
            params={"q": f"domain:{domain}", "size": 100},
            headers={"User-Agent": _UA},
        )
        if resp.status_code != 200:
            return None
        return parse_urlscan(domain, resp.json())
    except (httpx.HTTPError, ValueError):
        return None


async def _gsb(client: httpx.AsyncClient, domain: str) -> dict | None:
    key = getattr(settings, "gsb_api_key", "") or ""
    if not key:
        return None
    body = {
        "client": {"clientId": "bd-threat-observatory", "clientVersion": "0.5"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}"}, {"url": f"https://{domain}"}],
        },
    }
    try:
        resp = await client.post(GSB_URL, params={"key": key}, json=body)
        if resp.status_code != 200:
            return None
        return parse_gsb(domain, resp.json())
    except (httpx.HTTPError, ValueError):
        return None


async def lookup(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Return intel items from all configured sources (best-effort)."""
    items: list[dict] = []
    us = await _urlscan(client, domain)
    if us:
        items.append(us)
    gsb = await _gsb(client, domain)
    if gsb:
        items.append(gsb)
    return items
