"""Seed list of Bangladeshi organisations whose brands are commonly abused.

Kept as plain data so it is easy to review and extend. Each entry:

    name             human-readable brand name
    slug             stable identifier (lowercase, hyphenated)
    category         mfs | bank | telco | gov | university | ecommerce
    keywords         tokens that, in a domain, hint at impersonation
    official_domains authoritative domains, used to exclude legitimate certs

These are public brand facts (names and official websites), not private data.
"""
from __future__ import annotations

BRANDS: list[dict] = [
    # --- Mobile Financial Services (the #1 phishing target in BD) ---
    {
        "name": "bKash",
        "slug": "bkash",
        "category": "mfs",
        "keywords": ["bkash", "bkas", "bcash", "bkash-bd", "bkashapp"],
        "official_domains": ["bkash.com"],
    },
    {
        "name": "Nagad",
        "slug": "nagad",
        "category": "mfs",
        "keywords": ["nagad", "nagod", "nagad-bd", "mynagad"],
        "official_domains": ["nagad.com.bd", "mynagad.com.bd"],
    },
    {
        "name": "Rocket (DBBL)",
        "slug": "rocket-dbbl",
        "category": "mfs",
        "keywords": ["rocket", "dbblrocket", "dutchbanglarocket"],
        "official_domains": ["dutchbanglabank.com"],
    },
    {
        "name": "Upay",
        "slug": "upay",
        "category": "mfs",
        "keywords": ["upay", "upaybd"],
        "official_domains": ["upaybd.com"],
    },
    # --- Banks ---
    {
        "name": "Dutch-Bangla Bank",
        "slug": "dbbl",
        "category": "bank",
        "keywords": ["dbbl", "dutchbangla", "dutch-bangla"],
        "official_domains": ["dutchbanglabank.com"],
    },
    {
        "name": "BRAC Bank",
        "slug": "brac-bank",
        "category": "bank",
        "keywords": ["bracbank", "brac-bank"],
        "official_domains": ["bracbank.com"],
    },
    {
        "name": "Islami Bank Bangladesh",
        "slug": "ibbl",
        "category": "bank",
        "keywords": ["islamibank", "ibbl", "islami-bank"],
        "official_domains": ["islamibankbd.com"],
    },
    {
        "name": "City Bank",
        "slug": "city-bank",
        "category": "bank",
        "keywords": ["citybank", "citybankbd", "citytouch"],
        "official_domains": ["thecitybank.com"],
    },
    {
        "name": "Sonali Bank",
        "slug": "sonali-bank",
        "category": "bank",
        "keywords": ["sonalibank", "sonali-bank"],
        "official_domains": ["sonalibank.com.bd"],
    },
    # --- Telcos ---
    {
        "name": "Grameenphone",
        "slug": "grameenphone",
        "category": "telco",
        "keywords": ["grameenphone", "gpbd", "myjp", "grameen-phone"],
        "official_domains": ["grameenphone.com"],
    },
    {
        "name": "Robi",
        "slug": "robi",
        "category": "telco",
        "keywords": ["robi", "robibd", "robiaxiata"],
        "official_domains": ["robi.com.bd"],
    },
    {
        "name": "Banglalink",
        "slug": "banglalink",
        "category": "telco",
        "keywords": ["banglalink", "banglalinkbd"],
        "official_domains": ["banglalink.net"],
    },
    # --- Government / e-services ---
    {
        "name": "Bangladesh NID / Election Commission",
        "slug": "nid-ec",
        "category": "gov",
        "keywords": ["nidbd", "nid-bd", "banglandeshnid", "ecservices", "nidw"],
        "official_domains": ["services.nidw.gov.bd", "ec.gov.bd"],
    },
    {
        "name": "Bangladesh Government Portal",
        "slug": "gov-bd",
        "category": "gov",
        "keywords": ["govbd", "bangladesh-gov", "myoffice-bd"],
        "official_domains": ["bangladesh.gov.bd"],
    },
    # --- E-commerce / logistics (frequent parcel-scam lures) ---
    {
        "name": "Daraz Bangladesh",
        "slug": "daraz",
        "category": "ecommerce",
        "keywords": ["daraz", "darazbd", "daraz-bd"],
        "official_domains": ["daraz.com.bd"],
    },
    {
        "name": "Pathao",
        "slug": "pathao",
        "category": "ecommerce",
        "keywords": ["pathao", "pathaobd"],
        "official_domains": ["pathao.com"],
    },
]
