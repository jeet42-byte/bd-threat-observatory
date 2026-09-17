"""Match an observed domain against monitored brands and score the risk.

Pure functions, no database or network: given a domain and the brand list, it
returns the best impersonation match (if any) with a score and reasons. This is
what the DB-facing detector calls per domain, and what the tests exercise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from functools import lru_cache

from app.phishing import scoring
from app.phishing.permute import generate_variants, skeleton

# Minimum score for a candidate to be recorded as a finding.
MIN_SCORE = 40
# Fuzzy similarity threshold for a label to count as a lookalike of a keyword.
FUZZY_THRESHOLD = 0.82

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


@dataclass
class MatchResult:
    brand_slug: str
    score: int
    confidence: str
    reasons: list[str] = field(default_factory=list)


@lru_cache(maxsize=2048)
def _variants(keyword: str) -> frozenset[str]:
    return frozenset(generate_variants(keyword))


def _labels(name: str) -> list[str]:
    """Alphanumeric-only labels of a domain (dots and hyphens split them)."""
    return [p for p in _NON_ALNUM.split(name.lower()) if p]


def _compact(name: str) -> str:
    """Domain with all separators removed: 'se-cure.bkash.xyz' -> 'securebkashxyz'."""
    return _NON_ALNUM.sub("", name.lower())


def _is_official(registrable: str, name: str, official_domains: list[str]) -> bool:
    for off in official_domains:
        off = off.lower()
        if registrable == off or name == off or name.endswith("." + off):
            return True
    return False


def _brand_identity(name: str, keyword: str) -> tuple[int, str] | None:
    """Strongest brand-identity signal for one keyword, or None.

    Returns (points, reason). Checks, in order of strength: verbatim keyword,
    typosquat variant, confusable skeleton, fuzzy label similarity.
    """
    compact = _compact(name)
    if keyword in compact:
        return scoring.POINTS["keyword_exact"], f"contains brand keyword '{keyword}'"

    hits = _variants(keyword) & set(_all_substrings_of_len(compact, keyword))
    if hits:
        variant = sorted(hits)[0]
        return scoring.POINTS["typosquat"], f"typosquat of '{keyword}' ('{variant}')"

    if skeleton(keyword) in skeleton(compact):
        return scoring.POINTS["lookalike"], f"homoglyph lookalike of '{keyword}'"

    for label in _labels(name):
        if abs(len(label) - len(keyword)) <= 2:
            ratio = SequenceMatcher(None, label, keyword).ratio()
            if ratio >= FUZZY_THRESHOLD:
                return (
                    scoring.POINTS["lookalike"],
                    f"lookalike of '{keyword}' ('{label}', {ratio:.0%})",
                )
    return None


def _all_substrings_of_len(text: str, keyword: str) -> set[str]:
    """Substrings of ``text`` with length within +/-1 of the keyword length.

    Typo variants differ from the keyword by one edit, so their length is
    len +/- 1; only those windows can match, which keeps this cheap.
    """
    out: set[str] = set()
    for target_len in {len(keyword) - 1, len(keyword), len(keyword) + 1}:
        if target_len <= 0:
            continue
        for i in range(0, len(text) - target_len + 1):
            out.add(text[i : i + target_len])
    return out


def match_brand(name: str, registrable: str, tld: str, brand: dict) -> MatchResult | None:
    """Return a MatchResult if ``name`` looks like it impersonates ``brand``."""
    if _is_official(registrable, name, brand.get("official_domains", [])):
        return None

    best: tuple[int, str] | None = None
    for keyword in brand["keywords"]:
        identity = _brand_identity(name, keyword)
        if identity and (best is None or identity[0] > best[0]):
            best = identity
    if best is None:
        return None  # no brand-identity signal -> not a finding

    score = best[0]
    reasons = [best[1]]

    tld_pts = scoring.tld_signal(tld)
    if tld_pts:
        score += tld_pts
        reasons.append(f"suspicious TLD '.{tld.rsplit('.', 1)[-1]}'")

    lure_pts, lure_reasons = scoring.lure_signals(_labels(name))
    score += lure_pts
    reasons.extend(lure_reasons)

    struct_pts, struct_reasons = scoring.structure_signals(registrable)
    score += struct_pts
    reasons.extend(struct_reasons)

    score = min(score, 100)
    if score < MIN_SCORE:
        return None
    return MatchResult(
        brand_slug=brand["slug"],
        score=score,
        confidence=scoring.confidence_tier(score),
        reasons=reasons,
    )


def best_match(name: str, registrable: str, tld: str, brands: list[dict]) -> MatchResult | None:
    """Highest-scoring brand match for a domain, or None."""
    best: MatchResult | None = None
    for brand in brands:
        result = match_brand(name, registrable, tld, brand)
        if result and (best is None or result.score > best.score):
            best = result
    return best
