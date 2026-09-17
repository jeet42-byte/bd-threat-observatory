"""Tests for brand matching and risk scoring (network-free, no DB)."""
from __future__ import annotations

from app.data.brands_seed import BRANDS
from app.phishing.matcher import best_match, match_brand
from app.utils.domains import registrable_and_tld

BKASH = next(b for b in BRANDS if b["slug"] == "bkash")


def _match(name: str):
    reg, tld = registrable_and_tld(name)
    return best_match(name, reg, tld, BRANDS)


def test_flags_obvious_phishing_as_critical():
    m = _match("secure-bkash-reward.xyz")
    assert m is not None
    assert m.brand_slug == "bkash"
    assert m.confidence in {"high", "critical"}
    assert any("bkash" in r for r in m.reasons)


def test_excludes_official_domains():
    assert _match("www.bkash.com") is None
    assert _match("bkash.com") is None
    assert _match("grameenphone.com") is None
    assert _match("bracbank.com") is None


def test_ignores_unrelated_domains():
    assert _match("randomunrelatedsite.com") is None
    assert _match("example.org") is None


def test_catches_vowel_swap_typosquat():
    m = _match("bkosh-helpline.info")
    assert m is not None and m.brand_slug == "bkash"
    assert any("typosquat" in r or "lookalike" in r for r in m.reasons)


def test_suspicious_tld_and_lures_raise_score():
    plain = match_brand("bkash-info.com", "bkash-info.com", "com", BKASH)
    loud = match_brand("bkash-reward.xyz", "bkash-reward.xyz", "xyz", BKASH)
    assert plain is not None and loud is not None
    assert loud.score > plain.score


def test_score_is_bounded():
    m = _match("secure-bkash-reward-bonus-verify-otp.xyz")
    assert m is not None
    assert 0 <= m.score <= 100
