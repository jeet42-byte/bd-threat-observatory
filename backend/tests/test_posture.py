"""Tests for passive posture scoring (network-free, pure functions)."""
from __future__ import annotations

from app.posture.scoring import (
    assess,
    grade_for,
    score_email,
    score_headers,
    score_tls,
)

STRONG_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def test_grade_boundaries():
    assert grade_for(90) == "A"
    assert grade_for(80) == "B"
    assert grade_for(65) == "C"
    assert grade_for(50) == "D"
    assert grade_for(35) == "E"
    assert grade_for(0) == "F"


def test_full_headers_score_max():
    assert score_headers(STRONG_HEADERS).score == 100


def test_missing_headers_score_zero():
    assert score_headers({}).score == 0


def test_csp_frame_ancestors_covers_x_frame_options():
    headers = {"Content-Security-Policy": "frame-ancestors 'none'"}
    findings = {f["check"]: f["status"] for f in score_headers(headers).findings}
    assert findings["X-Frame-Options"] == "ok"


def test_tls_ranking():
    assert score_tls({"version": "TLSv1.3"}).score == 100
    assert score_tls({"version": "TLSv1.2"}).score == 80
    assert score_tls({"version": "TLSv1"}).score == 15
    assert score_tls({}).score == 0


def test_email_rewards_strong_dmarc():
    strong = score_email({"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject"})
    weak = score_email({"spf": "v=spf1", "dmarc": "v=DMARC1; p=none"})
    none = score_email({})
    assert strong.score > weak.score > none.score
    assert none.score == 0


def test_assess_strong_org_is_A():
    r = assess(STRONG_HEADERS, {"version": "TLSv1.3"},
               {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject"})
    assert r.grade == "A" and r.score == 100


def test_assess_bare_org_is_F():
    r = assess({}, {}, {})
    assert r.grade == "F" and r.score == 0
