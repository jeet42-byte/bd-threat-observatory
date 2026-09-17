"""Offline tests for RDAP and reputation parsers (no network)."""
from __future__ import annotations

from app.enrich.rdap import parse_rdap
from app.enrich.reputation import parse_gsb, parse_urlscan

RDAP = {
    "events": [{"eventAction": "registration", "eventDate": "2026-08-15T10:00:00Z"}],
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap, Inc."]]]},
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["org", {}, "text", "Privacy service"], ["adr", {}, "text", ["", "", "", "", "", "", "BD"]]],
            ],
        },
    ],
}


def test_rdap_extracts_registrar_and_date():
    r = parse_rdap(RDAP)
    assert r.registrar == "NameCheap, Inc."
    assert r.registrant_org == "Privacy service"
    assert r.registrant_country == "BD"
    assert r.created_at is not None and r.created_at.year == 2026


def test_rdap_handles_empty():
    r = parse_rdap({})
    assert r.registrar is None and r.created_at is None


def test_urlscan_status_transitions():
    assert parse_urlscan("x.com", {"results": []})["status"] == "unknown"
    assert parse_urlscan(
        "x.com", {"results": [{"verdicts": {"overall": {"malicious": True}}}]}
    )["status"] == "malicious"
    assert parse_urlscan(
        "x.com", {"results": [{"verdicts": {"overall": {"malicious": False}}}]}
    )["status"] == "listed"


def test_gsb_parse():
    assert parse_gsb("x.com", {}) is None
    hit = parse_gsb("x.com", {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
    assert hit["status"] == "malicious" and "social engineering" in hit["detail"]
