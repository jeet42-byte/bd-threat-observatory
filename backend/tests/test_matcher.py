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


def test_no_substring_false_positives():
    # Legitimate global companies that merely contain a brand word as a
    # substring must NOT be flagged (whole-label matching).
    for d in [
        "rocketlawyer.com",
        "secure.rocketlawyer.com",
        "rocketsoftware.com",
        "lionrocket.com",
        "imupay.co.kr",
        "dgbupay.com",
        "muktopay.com",
    ]:
        assert _match(d) is None, d


def test_real_brand_domain_not_flagged_for_other_brand():
    # bKash's own domain must not be flagged as an Upay impersonation.
    assert _match("payment.bkash.com") is None
    assert _match("pay.bkash.com") is None


def test_short_keyword_needs_corroboration():
    # A bare 4-char keyword as the SLD with no suspicious TLD/lure is dropped...
    assert _match("upay.co.il") is None
    # ...but with amplifiers it is caught.
    m = _match("upay-reward.xyz")
    assert m is not None and m.brand_slug == "upay"


def test_brand_glued_to_lure_is_caught():
    m = _match("bkashreward.com")
    assert m is not None and m.brand_slug == "bkash"


def test_free_host_phishing_is_flagged():
    # SMS-phishing landing pages on shared platforms score high with a reason.
    for d in [
        "sso-robi-nhood--login.pages.dev",
        "bkash-verify.web.app",
        "nagad-reward.netlify.app",
    ]:
        m = _match(d)
        assert m is not None, d
        assert any("free-hosting platform" in r for r in m.reasons)
