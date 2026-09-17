"""Risk scoring signals for candidate phishing domains.

The score is deliberately rule-based and explainable: every point added comes
with a human-readable reason, so a finding can be justified to a victim
organisation or a takedown provider. (An LLM pass can refine this later, but the
rules stand on their own and are fully testable offline.)
"""
from __future__ import annotations

# TLDs disproportionately used for abuse / cheap throwaway registrations.
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "xyz", "top", "online", "club", "info", "live", "click", "buzz",
        "icu", "cyou", "shop", "store", "site", "website", "space", "fun",
        "monster", "quest", "rest", "bar", "cam", "sbs", "cfd", "work",
        "support", "help", "gift", "win", "vip", "link", "app",
    }
)

# Free hosting / shared-subdomain platforms attackers use to stand up phishing
# landing pages without registering a domain - the classic SMS-phishing (smishing)
# delivery. A brand keyword on one of these is a strong signal.
FREE_HOSTS: frozenset[str] = frozenset(
    {
        "pages.dev", "web.app", "firebaseapp.com", "workers.dev", "hosted.app",
        "run.app", "netlify.app", "vercel.app", "glitch.me", "repl.co",
        "replit.app", "replit.dev", "github.io", "gitlab.io", "surge.sh",
        "r2.dev", "blogspot.com", "wixsite.com", "weebly.com", "square.site",
        "000webhostapp.com", "herokuapp.com", "azurewebsites.net", "onrender.com",
        "myshopify.com", "godaddysites.com", "webflow.io", "framer.website",
    }
)

# Tokens typical of financial/credential lures, especially around BD MFS scams.
LURE_TOKENS: frozenset[str] = frozenset(
    {
        "reward", "rewards", "bonus", "offer", "offers", "gift", "gifts",
        "win", "winner", "lottery", "lucky", "prize", "cashback", "refund",
        "verify", "verification", "update", "secure", "security", "login",
        "signin", "account", "official", "helpline", "support", "care",
        "promo", "promotion", "otp", "kyc", "wallet", "payment", "pay",
        "recharge", "balance", "loan", "free", "claim", "gov",
    }
)

# Score contributions (tuned for precision; brand-identity match is required
# before any of these amplifiers count).
POINTS = {
    "keyword_exact": 45,     # brand token appears verbatim
    "typosquat": 38,         # a generated typo variant appears
    "lookalike": 32,         # homoglyph skeleton / fuzzy match
    "suspicious_tld": 16,
    "lure_token": 12,        # per token, capped below
    "lure_cap": 24,
    "many_hyphens": 6,       # 2+ hyphens
    "long_domain": 4,        # very long registrable domain
    "free_host": 20,         # brand keyword on a free-hosting platform
}


def tld_signal(tld: str) -> int:
    """Points for a suspicious TLD (uses the final label of a multi-part TLD)."""
    last = tld.rsplit(".", 1)[-1].lower()
    return POINTS["suspicious_tld"] if last in SUSPICIOUS_TLDS else 0


def free_host_signal(registrable: str) -> tuple[int, str | None]:
    """Points + reason if the domain sits on a free-hosting platform."""
    if registrable.lower() in FREE_HOSTS:
        return POINTS["free_host"], f"free-hosting platform '{registrable.lower()}'"
    return 0, None


def lure_signals(compact_labels: list[str]) -> tuple[int, list[str]]:
    """Points + reasons for lure tokens present in the domain labels."""
    # Match lure tokens as whole labels only, not as substrings - so "pay"
    # inside "upay" no longer counts as a lure and inflates false positives.
    found: list[str] = []
    label_set = set(compact_labels)
    for token in LURE_TOKENS:
        if token in label_set and token not in found:
            found.append(token)
    points = min(len(found) * POINTS["lure_token"], POINTS["lure_cap"])
    reasons = [f"lure token '{t}'" for t in found]
    return points, reasons


def structure_signals(registrable: str) -> tuple[int, list[str]]:
    points = 0
    reasons: list[str] = []
    if registrable.count("-") >= 2:
        points += POINTS["many_hyphens"]
        reasons.append("multiple hyphens")
    if len(registrable) >= 25:
        points += POINTS["long_domain"]
        reasons.append("unusually long domain")
    return points, reasons


def confidence_tier(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"
