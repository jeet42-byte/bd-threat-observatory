"""RDAP (modern WHOIS) lookup for domain registration data.

RDAP is public and key-free. We read only what registries publish: the
registrar, the registration date, and - when not redacted for privacy - the
registrant organisation and country. Registrant *names* are almost always
redacted (GDPR/ICANN privacy), so "owner" in practice means "registrar".

Parsing is separated from the network call so it can be unit-tested offline.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

# rdap.org bootstraps to the correct registry RDAP server for most TLDs.
RDAP_BASE = "https://rdap.org/domain/"
_TIMEOUT = 15.0
_UA = "bd-threat-observatory/0.5 (+github.com/jeet42-byte)"


@dataclass
class RdapResult:
    registrar: str | None = None
    registrant_org: str | None = None
    registrant_country: str | None = None
    created_at: datetime | None = None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value[:19], fmt)
            except ValueError:
                continue
    return None


def _vcard_field(entity: dict, key: str) -> str | None:
    """Pull a field (e.g. 'org') from an RDAP entity's jCard."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == key:
            val = item[-1]
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None


def parse_rdap(data: dict) -> RdapResult:
    """Extract registrar / registrant / creation date from an RDAP response."""
    result = RdapResult()

    for event in data.get("events", []) or []:
        if event.get("eventAction") == "registration":
            result.created_at = _parse_time(event.get("eventDate"))
            break

    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        if "registrar" in roles and not result.registrar:
            result.registrar = _vcard_field(entity, "fn") or entity.get("handle")
        if "registrant" in roles:
            result.registrant_org = _vcard_field(entity, "org") or _vcard_field(
                entity, "fn"
            )
            adr = None
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and item and item[0] == "adr":
                        parts = item[-1]
                        if isinstance(parts, list) and parts:
                            adr = parts[-1]  # country is the last ADR component
            if adr and isinstance(adr, str) and adr.strip():
                result.registrant_country = adr.strip()[:8]
    return result


@retry(
    reraise=True,
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    retry=retry_if_exception_type(httpx.TransportError),
)
async def _fetch(client: httpx.AsyncClient, domain: str) -> dict | None:
    resp = await client.get(f"{RDAP_BASE}{domain}", headers={"User-Agent": _UA})
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


async def lookup(client: httpx.AsyncClient, domain: str) -> RdapResult:
    """RDAP lookup for a registrable domain. Empty result on any failure."""
    try:
        data = await _fetch(client, domain)
    except (httpx.HTTPError, ValueError):
        return RdapResult()
    if not data:
        return RdapResult()
    return parse_rdap(data)
