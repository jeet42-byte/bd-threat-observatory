"""Network-free test of the crt.sh row -> domain extraction logic.

Uses synthetic crt.sh rows (the exact shape crt.sh returns) to prove that a
certificate's common name and SANs are correctly turned into the set of
distinct domains the collector will persist - without hitting the network or a
database.
"""
from __future__ import annotations

from app.utils.domains import clean_name, split_names

# A realistic crt.sh row (subset of fields we use).
SAMPLE_ROWS = [
    {
        "id": 111,
        "common_name": "secure-bkash-reward.xyz",
        "name_value": "secure-bkash-reward.xyz\n*.secure-bkash-reward.xyz",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": "2024-05-01T00:00:00",
        "not_after": "2024-07-30T00:00:00",
    },
    {
        "id": 222,
        "common_name": "www.bkash.com",  # legitimate
        "name_value": "www.bkash.com\nbkash.com",
        "issuer_name": "C=US, O=DigiCert Inc",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2025-01-01T00:00:00",
    },
]


def _domains_for_row(row: dict) -> set[str]:
    names = split_names(row.get("name_value"))
    cn = clean_name(row.get("common_name", ""))
    if cn:
        names.add(cn)
    return names


def test_phishing_row_yields_expected_domains():
    assert _domains_for_row(SAMPLE_ROWS[0]) == {"secure-bkash-reward.xyz"}


def test_legitimate_row_yields_expected_domains():
    assert _domains_for_row(SAMPLE_ROWS[1]) == {"www.bkash.com", "bkash.com"}


def test_rows_have_dedupe_ids():
    ids = [r["id"] for r in SAMPLE_ROWS]
    assert len(ids) == len(set(ids))
