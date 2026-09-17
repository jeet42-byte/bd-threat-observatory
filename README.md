# BD Threat Observatory

Passive security intelligence for Bangladesh's public web. One ingestion
pipeline feeds two products:

- **Phishing & Scam Feed** — detects fake bKash / Nagad / bank / gov domains
  as their TLS certificates appear in public Certificate Transparency logs.
- **Security Posture Observatory** — grades the public web security posture of
  Bangladeshi banks, telcos, and government services (HTTP security headers,
  TLS version, SPF/DMARC email auth) on an A-F scale, from passive checks only.

> **Ethics & legality.** This project is strictly **passive OSINT**. It reads
> only public data (Certificate Transparency logs, DNS, and information a normal
> browser receives). It performs **no scanning, probing, exploitation, or
> unauthorised access**, in line with Bangladesh's Cyber Security Act. Brand
> names are used only to detect impersonation of those brands.

## One-click deploy

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/jeet42-byte/bd-threat-observatory)

The button reads `render.yaml` and provisions the API; you supply the Neon
`DATABASE_URL` when prompted. Then deploy the dashboard on Vercel (root
directory `web/`, env `NEXT_PUBLIC_API_BASE` = the API URL). Full walkthrough in
[`DEPLOYMENT.md`](DEPLOYMENT.md).

## Screenshots

**Phishing & scam feed** — live impersonation findings with explainable signals
and a cross-link to each brand's real-domain email defense:

![Phishing feed](docs/screenshots/threats.png)

**Security posture observatory** — A–F grades for monitored BD organisations:

![Posture grades](docs/screenshots/posture.png)

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
│   │   ├── phishing/              permute.py, scoring.py, matcher.py, detector.py
│   │   ├── posture/               scoring.py, probes.py, collector.py
│   │   ├── api/                   schemas.py + v1/{threats,brands,stats}.py
│   │   ├── main.py                FastAPI app
│   │   ├── data/brands_seed.py    BD brands monitored for impersonation
│   │   └── utils/domains.py       PSL-aware domain normalisation
│   ├── tests/                     network-free unit tests
│   └── requirements.txt
├── web/                           Next.js dashboard (/threats)
│   └── src/{app,components,lib}
└── .github/workflows/
    ├── ingest_cron.yml            phishing ingest, every 6 hours
    ├── posture_cron.yml           posture scan, daily
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

## Public API

Read-only FastAPI service (all writes happen in the collectors, never over HTTP).

```bash
cd backend && source .venv/bin/activate
export DATABASE_URL="postgresql+asyncpg://user:pass@host/db"
python -m app.db.seed_mock             # optional: synthetic findings for a demo
uvicorn app.main:app --reload          # http://localhost:8000/docs
```

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness |
| GET | `/api/v1/threats` | phishing feed (filters: `brand`, `confidence`, `min_score`, pagination) |
| GET | `/api/v1/brands` | monitored brands |
| GET | `/api/v1/stats` | headline counts |
| GET | `/api/v1/posture` | security-posture grades (filters: `category`, `grade`, `brand`) |
| POST | `/api/v1/threats/{id}/report` | record a community scam report (increments counter) |

## Frontend (dashboard)

Next.js 14 + Tailwind. Renders the phishing feed; falls back to bundled sample
data when the API is unreachable, so a preview deploy works before the backend
is live.

```bash
cd web
npm install
cp .env.example .env.local   # set NEXT_PUBLIC_API_BASE to your API URL
npm run dev                  # http://localhost:3000/threats
```

## Report

Generate the "State of .bd Web Security" briefing (grade distribution, weakest
postures, most common gaps, phishing summary) from live data:

```bash
cd backend && python -m app.report.generate > REPORT.md
```

## Deployment

Free-tier stack: Neon (DB) + Render (API) + Vercel (dashboard) + GitHub Actions
(collectors). Step-by-step in [`DEPLOYMENT.md`](DEPLOYMENT.md).

## Status

Under active development — built in daily increments (see `HANDOFF.md`).

- [x] **Day 1** — shared ingestion core: schema, brand seed, crt.sh collector, cron, CI
- [x] **Day 2** — phishing detection: typosquat/homoglyph engine, rule-based scoring, findings
- [x] **Day 3** — public API (FastAPI) + `/threats` dashboard (Next.js) + mock seed
- [x] **Day 4** — posture observatory: passive header/TLS/email-auth checks + A–F grading + API
- [x] **Day 5** — `/posture` dashboard (grades, sub-score bars, distribution chart) + threat↔posture cross-link
- [x] **Day 6** — screenshots, deployment configs, `/about` page, "State of .bd" report generator
