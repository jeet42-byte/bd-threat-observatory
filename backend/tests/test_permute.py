"""Tests for the typosquat/homoglyph generator."""
from __future__ import annotations

from app.phishing.permute import generate_variants, skeleton


def test_generates_common_typo_classes():
    v = generate_variants("bkash")
    assert "bksh" in v      # omission
    assert "bkkash" in v    # duplication
    assert "baksh" in v     # transposition
    assert "bkosh" in v     # vowel swap


def test_excludes_the_keyword_itself():
    assert "bkash" not in generate_variants("bkash")


def test_short_keywords_yield_nothing():
    assert generate_variants("gp") == set()


def test_skeleton_collapses_confusables():
    assert skeleton("bk0sh") == skeleton("bkosh")   # 0 -> o
    assert skeleton("nagad") != skeleton("bkash")
