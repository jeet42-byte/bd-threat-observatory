"""Typosquat and homoglyph generation for brand keywords.

An attacker registering a lookalike domain rarely types the brand exactly. They
drop a letter, double one, swap adjacent keys, or substitute a confusable
character (``0`` for ``o``, ``rn`` for ``m``). This module produces the set of
such variants for a keyword so the detector can spot them inside observed
domains, and provides a "skeleton" that collapses confusables to a canonical
form for lookalike comparison.

This is the same reasoning an attacker uses, applied defensively.
"""
from __future__ import annotations

# Confusable / homoglyph substitutions (ASCII-level; visually similar).
_HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "o": ("0",),
    "0": ("o",),
    "l": ("1", "i"),
    "i": ("1", "l", "j"),
    "1": ("l", "i"),
    "e": ("3",),
    "3": ("e",),
    "a": ("4", "@"),
    "4": ("a",),
    "s": ("5", "z", "$"),
    "5": ("s",),
    "b": ("6",),
    "g": ("9", "q"),
    "t": ("7",),
    "z": ("s",),
}

# For skeletonisation: map each confusable to one canonical character so that
# "bka5h", "bkosh" (o/0) etc. collapse toward the same skeleton as "bkash".
_SKELETON_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "l": "i",
        "3": "e",
        "4": "a",
        "@": "a",
        "5": "s",
        "$": "s",
        "z": "s",
        "7": "t",
        "6": "b",
        "9": "g",
    }
)

# QWERTY neighbours for realistic fat-finger replacements.
_QWERTY: dict[str, str] = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "serfcx",
    "e": "wsdr",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "i": "ujko",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "awedxz",
    "t": "rfgy",
    "u": "yhji",
    "v": "cfgb",
    "w": "qase",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
}


def skeleton(text: str) -> str:
    """Collapse confusable characters to a canonical skeleton for comparison."""
    return text.lower().translate(_SKELETON_MAP)


def _omissions(word: str) -> set[str]:
    return {word[:i] + word[i + 1:] for i in range(len(word))}


def _duplications(word: str) -> set[str]:
    return {word[:i] + word[i] + word[i:] for i in range(len(word))}


def _transpositions(word: str) -> set[str]:
    out = set()
    for i in range(len(word) - 1):
        out.add(word[:i] + word[i + 1] + word[i] + word[i + 2:])
    return out


def _replacements(word: str) -> set[str]:
    out = set()
    for i, ch in enumerate(word):
        for repl in _QWERTY.get(ch, ""):
            out.add(word[:i] + repl + word[i + 1:])
    return out


def _homoglyphs(word: str) -> set[str]:
    out = set()
    for i, ch in enumerate(word):
        for repl in _HOMOGLYPHS.get(ch, ()):  # type: ignore[arg-type]
            out.add(word[:i] + repl + word[i + 1:])
    return out


def _insertions(word: str) -> set[str]:
    out = set()
    for i in range(len(word) + 1):
        for ch in "abcdefghijklmnopqrstuvwxyz":
            out.add(word[:i] + ch + word[i:])
    return out


def _vowel_swaps(word: str) -> set[str]:
    vowels = "aeiou"
    out = set()
    for i, ch in enumerate(word):
        if ch in vowels:
            for v in vowels:
                if v != ch:
                    out.add(word[:i] + v + word[i + 1:])
    return out


def generate_variants(keyword: str, include_insertions: bool = False) -> set[str]:
    """Return typosquat variants of ``keyword`` (excluding the keyword itself).

    ``include_insertions`` adds every single-character insertion; it is large
    (26 * (len+1) variants) so it is off by default and used only where the
    extra recall is worth the size.
    """
    kw = keyword.lower().strip()
    if len(kw) < 3:
        return set()
    variants: set[str] = set()
    variants |= _omissions(kw)
    variants |= _duplications(kw)
    variants |= _transpositions(kw)
    variants |= _replacements(kw)
    variants |= _homoglyphs(kw)
    variants |= _vowel_swaps(kw)
    if include_insertions:
        variants |= _insertions(kw)
    variants.discard(kw)
    variants.discard("")
    # Drop very short variants (e.g. "pay" from "upay") - they are common
    # fragments that match unrelated domains and cause false positives.
    return {v for v in variants if len(v) >= 4}
