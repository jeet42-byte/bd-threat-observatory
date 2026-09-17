"""Passive probes for a domain's public security posture.

Each probe makes the kind of request a normal browser or mail system already
makes - an HTTPS GET, a TLS handshake, a public DNS TXT lookup - and reads what
comes back. No port scanning, no probing of non-public services.

Probes are best-effort: on any error they return an empty result and the
caller records the target as unreachable rather than failing the run. These
require outbound network, so they run in GitHub Actions, not the dev sandbox.
"""
from __future__ import annotations

import socket
import ssl

import httpx

_TIMEOUT = 12.0
_UA = "bd-threat-observatory/0.4 (+github.com/jeet42-byte)"


def probe_headers(host: str) -> dict[str, str] | None:
    """Return response headers from an HTTPS GET, or None if unreachable."""
    try:
        with httpx.Client(
            timeout=_TIMEOUT, follow_redirects=True, headers={"User-Agent": _UA}
        ) as client:
            resp = client.get(f"https://{host}")
        return dict(resp.headers)
    except httpx.HTTPError:
        return None


def probe_tls(host: str) -> dict | None:
    """Return {'version': 'TLSv1.3', ...} from a TLS handshake, or None."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {"version": ssock.version(), "cipher": ssock.cipher()[0]}
    except (OSError, ssl.SSLError):
        return None


def probe_dns(host: str) -> dict:
    """Return {'spf': str|None, 'dmarc': str|None} from public TXT records."""
    import dns.resolver  # imported lazily so the module loads without dnspython

    result: dict[str, str | None] = {"spf": None, "dmarc": None}

    def _txt(name: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=_TIMEOUT)
            return ["".join(s.decode() for s in r.strings) for r in answers]
        except Exception:  # noqa: BLE001 - any DNS failure -> no record
            return []

    for txt in _txt(host):
        if txt.lower().startswith("v=spf1"):
            result["spf"] = txt
            break
    for txt in _txt(f"_dmarc.{host}"):
        if txt.lower().startswith("v=dmarc1"):
            result["dmarc"] = txt
            break
    return result
