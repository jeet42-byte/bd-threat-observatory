# BD Threat Observatory

Passive security intelligence for Bangladesh's public web. One ingestion
pipeline feeds two products:

- **Phishing & Scam Feed** — detects fake bKash / Nagad / bank / gov domains
  as their TLS certificates appear in public Certificate Transparency logs.
- **Security Posture Observatory** — grades the public web security posture
  (headers, TLS, email auth) of Bangladeshi banks, telcos, and government
  services over time.

> **Ethics & legality.** This project is strictly **passive OSINT**. It reads
> only public data (Certificate Transparency logs, DNS, and information a normal
> browser receives). It performs **no scanning, probing, exploitation, or
> unauthorised access**, in line with Bangladesh's Cyber Security Act. Brand
> names are used only to detect impersonation of those brands.

## Architecture

| Layer | Technology | Host (free tier) |
|---|---|---|
| Database | PostgreSQL 16 (+ pg_trgm) | Neon |
| API | FastAPI + async SQLAlchemy | Render |
| Ingestion | Python collectors (crt.sh) | GitHub Actions cron |
| Frontend | Next.js + Tailwind + Recharts | Vercel |

The two products deliberately **share one ingestion core**: the Certificate
Transparency stream that discovers phishing domains is the same stream that
discovers the legitimate attack surface to grade.

```
bd-threat-observatory/
├── backend/
│   ├── app/
│   │   ├── core/config.py         env-driven settings
│   │   ├── db/                    database.py, models.py, init_db.py
│   │   ├── collectors/            crtsh.py, ct_collector.py, run_ingest.py
│   │   ├── data/brands_seed.py    BD brands monitored for impersonation
│   │   └── utils/domains.py       PSL-aware domain normalisation
│   ├── tests/                     network-free unit tests
│   └── requirements.txt
└── .github/workflows/
    ├── ingest_cron.yml            every 6 hours
    └── ci.yml                     tests on push / PR
```

## Data model (shared core)

- **Brand** — a legitimate BD organisation, its impersonation keywords, and its
  official domains.
- **Domain** — any domain observed in the wild (from CT logs), with its
  registrable domain (eTLD+1) and TLD.
- **Certificate** — a TLS certificate seen in Certificate Transparency,
  de-duplicated by crt.sh entry id.

The phishing feed and posture observatory add their own tables on top of these.

## Running locally

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Point DATABASE_URL at a Postgres instance (see .env.example)
export DATABASE_URL="postgresql+asyncpg://user:pass@host/db"

python -m app.collectors.run_ingest   # create schema, seed brands, ingest
python -m pytest -q                    # run the offline test suite
```

> The ingestion job needs outbound access to `crt.sh`. It runs on GitHub
> Actions (open internet) on a 6-hour schedule; some sandboxed dev
> environments block outbound egress, in which case run the collector from a
> machine that can reach crt.sh.

## Status

Under active development — built in daily increments (see `HANDOFF.md`).

- [x] **Day 1** — shared ingestion core: schema, brand seed, crt.sh collector, cron, CI
- [x] **Day 2** — phishing detection: typosquat/homoglyph engine, rule-based scoring, findings
- [ ] Day 3 — public API + `/threats` dashboard
- [ ] Day 4 — posture collector + A–F grading
- [ ] Day 5 — `/posture` dashboard + cross-linking
- [ ] Day 6 — polish, report, deploy
