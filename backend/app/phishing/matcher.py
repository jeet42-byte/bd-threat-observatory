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


def _is_official(registrable: str, name: str, official_domains: list[str]) -> bool:
    for off in official_domains:
        off = off.lower()
        if registrable == off or name == off or name.endswith("." + off):
            return True
    return False


# Remainders allowed when a brand keyword is glued to another token in a single
# domain label, e.g. "bkashreward" (lure) or "bkashbd" (BD nexus). A keyword
# merely embedded inside an unrelated word (rocket-in-rocketlawyer) is NOT a
# match - that was the main false-positive source.
_ALLOWED_GLUE = frozenset({"bd", "bangla", "bangladesh", "online", "app", "help"})


def _brand_identity(name: str, keyword: str) -> tuple[int, str] | None:
    """Strongest brand-identity signal for one keyword, matched at the level of
    whole domain labels (not embedded substrings), or None.

    A label is a hit when it (1) equals the keyword, (2) equals a typosquat
    variant, (3) is the keyword glued to a lure/BD token, (4) has the same
    confusable skeleton, or (5) is fuzzily similar. Substrings buried inside a
    longer unrelated word do not count.
    """
    labels = _labels(name)
    variants = _variants(keyword)
    glue = _ALLOWED_GLUE | scoring.LURE_TOKENS

    for label in labels:
        if label == keyword:
            return (
                scoring.POINTS["keyword_exact"],
                f"brand keyword '{keyword}' as a domain label",
            )
    for label in labels:
        if label in variants:
            return (
                scoring.POINTS["typosquat"],
                f"typosquat of '{keyword}' ('{label}')",
            )
    # keyword glued to a lure/BD token within one label
    for label in labels:
        if label == keyword or keyword not in label:
            continue
        if label.startswith(keyword) and label[len(keyword):] in glue:
            return (
                scoring.POINTS["keyword_exact"],
                f"brand keyword '{keyword}' + '{label[len(keyword):]}'",
            )
        if label.endswith(keyword) and label[: -len(keyword)] in glue:
            return (
                scoring.POINTS["keyword_exact"],
                f"'{label[: -len(keyword)]}' + brand keyword '{keyword}'",
            )
    ks = skeleton(keyword)
    for label in labels:
        if skeleton(label) == ks and label != keyword:
            return (
                scoring.POINTS["lookalike"],
                f"homoglyph lookalike of '{keyword}' ('{label}')",
            )
    for label in labels:
        if abs(len(label) - len(keyword)) <= 2:
            ratio = SequenceMatcher(None, label, keyword).ratio()
            if ratio >= FUZZY_THRESHOLD:
                return (
                    scoring.POINTS["lookalike"],
                    f"lookalike of '{keyword}' ('{label}', {ratio:.0%})",
                )
    return None


def match_brand(
    name: str,
    registrable: str,
    tld: str,
    brand: dict,
    legit_domains: frozenset[str] | None = None,
) -> MatchResult | None:
    """Return a MatchResult if ``name`` looks like it impersonates ``brand``.

    ``legit_domains`` is the set of every monitored brand's own official
    domains; a domain matching it is a legitimate brand property, never an
    impersonation, and is skipped.
    """
    if _is_official(registrable, name, brand.get("official_domains", [])):
        return None
    if legit_domains and _is_official(registrable, name, list(legit_domains)):
        return None

    best: tuple[int, str, str] | None = None
    for keyword in brand["keywords"]:
        identity = _brand_identity(name, keyword)
        if identity and (best is None or identity[0] > best[0]):
            best = (identity[0], identity[1], keyword)
    if best is None:
        return None  # no brand-identity signal -> not a finding

    score = best[0]
    reasons = [best[1]]
    matched_keyword = best[2]

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

    host_pts, host_reason = scoring.free_host_signal(registrable)
    if host_pts:
        score += host_pts
        reasons.append(host_reason)

    # A short brand keyword (<= 4 chars, e.g. "upay", "ibbl", "robi") matched on
    # its own, with no suspicious TLD / lure / structure signal, collides with
    # unrelated foreign companies. Require at least one corroborating signal.
    amplifier_fired = bool(tld_pts or lure_pts or struct_pts or host_pts)
    if len(matched_keyword) <= 4 and not amplifier_fired:
        return None

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
    legit = frozenset(
        d.lower()
        for brand in brands
        for d in brand.get("official_domains", [])
    )
    best: MatchResult | None = None
    for brand in brands:
        result = match_brand(name, registrable, tld, brand, legit_domains=legit)
        if result and (best is None or result.score > best.score):
            best = result
    return best
