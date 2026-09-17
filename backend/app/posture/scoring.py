"""Passive security-posture scoring: headers + TLS + email auth -> grade.

Pure and explainable: each check yields a status (ok/warn/fail) and a detail
string, and contributes to a weighted 0-100 score mapped to an A-F grade. All
inputs are plain dicts, so the whole thing is unit-testable without network.

Everything scored here is observable from a normal HTTPS request and public
DNS TXT records - no scanning or probing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Category weights (must sum to 100).
WEIGHTS = {"headers": 45, "tls": 30, "email": 25}


@dataclass
class CategoryResult:
    score: int  # 0-100 within the category
    findings: list[dict] = field(default_factory=list)


@dataclass
class PostureResult:
    score: int
    grade: str
    headers_score: int
    tls_score: int
    email_score: int
    findings: list[dict]


def _finding(check: str, status: str, detail: str) -> dict:
    return {"check": check, "status": status, "detail": detail}


# --- HTTP security headers -------------------------------------------------

# header key (lowercase) -> (weight within headers category, human name)
_HEADER_CHECKS = {
    "strict-transport-security": (28, "HSTS"),
    "content-security-policy": (26, "Content-Security-Policy"),
    "x-frame-options": (16, "X-Frame-Options"),
    "x-content-type-options": (12, "X-Content-Type-Options"),
    "referrer-policy": (10, "Referrer-Policy"),
    "permissions-policy": (8, "Permissions-Policy"),
}


def score_headers(headers: dict[str, str]) -> CategoryResult:
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    earned = 0
    findings: list[dict] = []
    for key, (weight, name) in _HEADER_CHECKS.items():
        present = key in lower
        # CSP can also be satisfied for framing via frame-ancestors.
        if key == "x-frame-options" and not present:
            csp = lower.get("content-security-policy", "")
            if "frame-ancestors" in csp:
                present = True
        if present:
            earned += weight
            findings.append(_finding(name, "ok", "present"))
        else:
            status = "fail" if weight >= 20 else "warn"
            findings.append(_finding(name, status, "missing"))
    return CategoryResult(score=min(earned, 100), findings=findings)


# --- TLS -------------------------------------------------------------------

_TLS_RANK = {"TLSv1.3": 100, "TLSv1.2": 80, "TLSv1.1": 30, "TLSv1": 15, "SSLv3": 0}


def score_tls(tls: dict) -> CategoryResult:
    version = (tls or {}).get("version")
    if not version:
        return CategoryResult(
            score=0, findings=[_finding("TLS", "fail", "no TLS / not reachable")]
        )
    score = _TLS_RANK.get(version, 40)
    if score >= 80:
        status = "ok"
    elif score >= 40:
        status = "warn"
    else:
        status = "fail"
    return CategoryResult(
        score=score, findings=[_finding("TLS version", status, version)]
    )


# --- Email authentication (SPF / DMARC) ------------------------------------

def score_email(dns: dict) -> CategoryResult:
    dns = dns or {}
    spf = dns.get("spf")
    dmarc = dns.get("dmarc")
    earned = 0
    findings: list[dict] = []

    if spf:
        earned += 40
        findings.append(_finding("SPF", "ok", "present"))
    else:
        findings.append(_finding("SPF", "fail", "no SPF record"))

    if dmarc:
        policy = _dmarc_policy(dmarc)
        if policy in {"reject", "quarantine"}:
            earned += 60
            findings.append(_finding("DMARC", "ok", f"policy={policy}"))
        elif policy == "none":
            earned += 25
            findings.append(
                _finding("DMARC", "warn", "policy=none (monitoring only)")
            )
        else:
            earned += 20
            findings.append(_finding("DMARC", "warn", "present, policy unclear"))
    else:
        findings.append(_finding("DMARC", "fail", "no DMARC record"))

    return CategoryResult(score=min(earned, 100), findings=findings)


def _dmarc_policy(record: str) -> str:
    for part in record.split(";"):
        part = part.strip().lower()
        if part.startswith("p="):
            return part[2:].strip()
    return "unknown"


# --- Aggregate -------------------------------------------------------------

def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    if score >= 35:
        return "E"
    return "F"


def assess(headers: dict, tls: dict, dns: dict) -> PostureResult:
    h = score_headers(headers)
    t = score_tls(tls)
    e = score_email(dns)
    total = round(
        h.score * WEIGHTS["headers"] / 100
        + t.score * WEIGHTS["tls"] / 100
        + e.score * WEIGHTS["email"] / 100
    )
    return PostureResult(
        score=total,
        grade=grade_for(total),
        headers_score=h.score,
        tls_score=t.score,
        email_score=e.score,
        findings=h.findings + t.findings + e.findings,
    )
