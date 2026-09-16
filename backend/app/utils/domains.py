"""Domain-name normalisation helpers built on the Public Suffix List.

Certificate identities are messy: wildcards, mixed case, multiple SANs packed
into one field, trailing dots. These helpers turn them into clean, comparable
domain names plus their registrable domain (eTLD+1) and TLD.
"""
from __future__ import annotations

from datetime import datetime

import tldextract

# Offline extractor: use the bundled snapshot rather than fetching the PSL on
# every run (important inside CI where network egress should be minimal).
_extract = tldextract.TLDExtract(suffix_list_urls=())


def clean_name(raw: str) -> str | None:
    """Lowercase, strip wildcard prefixes and trailing dots. None if unusable."""
    if not raw:
        return None
    name = raw.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    # Ignore obvious non-hostnames (emails, empty labels).
    if not name or "@" in name or " " in name or ".." in name:
        return None
    return name


def split_names(name_value: str | None) -> set[str]:
    """crt.sh packs SANs into a newline-separated ``name_value`` field."""
    if not name_value:
        return set()
    out: set[str] = set()
    for part in name_value.replace("\r", "\n").split("\n"):
        cleaned = clean_name(part)
        if cleaned:
            out.add(cleaned)
    return out


def registrable_and_tld(name: str) -> tuple[str, str]:
    """Return (registrable_domain, tld) for a hostname.

    e.g. "login.bkash.example.com.bd" -> ("example.com.bd", "com.bd")
    Falls back to the full name if the suffix cannot be determined.
    """
    ext = _extract(name)
    if ext.suffix and ext.domain:
        registrable = f"{ext.domain}.{ext.suffix}"
        return registrable, ext.suffix
    return name, ext.suffix or ""


def parse_crtsh_timestamp(value: str | None) -> datetime | None:
    """crt.sh timestamps look like '2024-01-02T03:04:05' (naive UTC)."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None
