"""Network-free unit tests for domain normalisation.

These run in CI without a database or internet, guarding the parsing logic the
whole pipeline depends on.
"""
from __future__ import annotations

from datetime import datetime

from app.utils.domains import (
    clean_name,
    parse_crtsh_timestamp,
    registrable_and_tld,
    split_names,
)


def test_clean_name_strips_wildcard_and_lowercases():
    assert clean_name("*.Login.BKASH.COM.BD") == "login.bkash.com.bd"


def test_clean_name_rejects_non_hostnames():
    assert clean_name("") is None
    assert clean_name("admin@example.com") is None
    assert clean_name("has space.com") is None
    assert clean_name("double..dot.com") is None


def test_split_names_handles_multiple_sans():
    got = split_names("a.bkash-bd.com\n*.pay.bkash-bd.com\r\nA.BKASH-BD.COM")
    assert got == {"a.bkash-bd.com", "pay.bkash-bd.com"}


def test_split_names_empty():
    assert split_names(None) == set()
    assert split_names("") == set()


def test_registrable_handles_multi_level_bd_suffix():
    assert registrable_and_tld("login.bkash.example.com.bd") == (
        "example.com.bd",
        "com.bd",
    )


def test_registrable_handles_plain_com():
    assert registrable_and_tld("secure.bkash-rewards.com") == (
        "bkash-rewards.com",
        "com",
    )


def test_parse_crtsh_timestamp_variants():
    assert parse_crtsh_timestamp("2024-01-02T03:04:05") == datetime(2024, 1, 2, 3, 4, 5)
    assert parse_crtsh_timestamp("2024-01-02T03:04:05.123") == datetime(
        2024, 1, 2, 3, 4, 5, 123000
    )
    assert parse_crtsh_timestamp(None) is None
    assert parse_crtsh_timestamp("not-a-date") is None
