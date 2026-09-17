# HANDOFF

Session-to-session state so any new session can resume without re-explaining.
Branch: `claude/nifty-ritchie-omdcrq`

## Where we are: end of Day 2

**Goal of the week:** build two portfolio projects (#1 Security Posture
Observatory, #2 Phishing/Scam Feed) as ONE repo sharing a Certificate
Transparency ingestion core. Stack mirrors the author's `bangladesh-crime-monitor`
(FastAPI + async SQLAlchemy + Postgres/Neon + Next.js + GitHub Actions cron).

### Done (Day 1) — shared ingestion core
- `backend/app/core/config.py` — env-driven settings (pydantic-settings).
- `backend/app/db/database.py` — async engine/session (asyncpg).
- `backend/app/db/models.py` — `Brand`, `Domain`, `Certificate` (product-neutral).
- `backend/app/db/init_db.py` — create tables + `pg_trgm` extension (idempotent).
- `backend/app/data/brands_seed.py` — 16 BD brands (mfs/bank/telco/gov/ecommerce).
- `backend/app/utils/domains.py` — PSL-aware normalisation (handles `.com.bd`).
- `backend/app/collectors/crtsh.py` — crt.sh JSON client, retry+backoff, polite.
- `backend/app/collectors/ct_collector.py` — rows → Domain+Certificate, idempotent.
- `backend/app/collectors/run_ingest.py` — entrypoint: init → seed → ingest.
- `backend/tests/` — 10 network-free unit tests (green).
- `.github/workflows/ingest_cron.yml` — every 6h + manual dispatch.
- `.github/workflows/ci.yml` — pytest on push/PR.

### Verified
- All modules import; domain helpers unit-tested; 10/10 pytest green.
- crt.sh client + parsing dry-run logic validated against synthetic rows.

### NOT yet verified (blocked in this dev sandbox)
- **Live crt.sh fetch**: this sandbox's egress proxy returns 403 for crt.sh.
  The code is correct; it will run on GitHub Actions (open internet). To prove
  it end-to-end, either run `run_ingest` from a machine that can reach crt.sh,
  or trigger the `ingest_cron` workflow once `DATABASE_URL` secret is set.
- **DB writes**: no Postgres in the sandbox. Needs a Neon DB + `DATABASE_URL`.


### Done (Day 2) — phishing detection engine
- `backend/app/db/models.py` — added `ThreatFinding` (brand_id, domain_id,
  risk_score, confidence, reasons JSONB, status; unique per brand+domain).
- `backend/app/phishing/permute.py` — typosquat/homoglyph generator
  (omission, duplication, transposition, QWERTY replacement, homoglyph,
  vowel-swap) + `skeleton()` confusable normaliser.
- `backend/app/phishing/scoring.py` — suspicious TLDs, lure tokens, point
  weights, confidence tiers. Explainable, rule-based (no LLM needed).
- `backend/app/phishing/matcher.py` — pure matcher: brand-identity signal
  required (keyword / typosquat / homoglyph / fuzzy), then TLD + lure +
  structure amplifiers; excludes each brand's official domains. MIN_SCORE=40.
- `backend/app/phishing/detector.py` — DB runner: scores every Domain, upserts
  ThreatFinding per (brand,domain), idempotent.
- Wired detection into `run_ingest` (collect -> detect each run).
- Tests: +10 (permute + matcher). Suite now 20/20 green.

### Verified (Day 2)
- Matcher precision spot-checked: legit domains (bkash.com, grameenphone.com,
  bracbank.com) -> no match; phishing (secure-bkash-reward.xyz,
  nagad-cashback.online, bkosh-helpline.info, islamibank-otp-verify.top) ->
  high/critical with explainable reasons. Scores bounded 0-100.

### NOT yet verified (same sandbox blocks as Day 1)
- Live crt.sh fetch + real DB writes still need GitHub Actions + Neon
  `DATABASE_URL`. Detector DB path is thin SQLAlchemy over the tested matcher.

## To deploy the pipeline (when ready)
1. Create a Neon Postgres DB; get the `postgresql+asyncpg://...` URL.
2. Add repo secret `DATABASE_URL` (Settings → Secrets → Actions).
3. Run the `ingest_cron` workflow via "Run workflow" (workflow_dispatch).
4. Confirm rows land in `brands`, `domains`, `certificates`.

## Next: Day 3 — public API + /threats dashboard
- FastAPI app (`app/main.py`) + read-only endpoints under `/api/v1`:
  `GET /threats` (filter by brand/confidence/min_score, paginated),
  `GET /brands`, `GET /stats` (counts by confidence/brand).
- Pydantic response schemas; CORS for the Vercel frontend.
- Next.js frontend `web/`: `/threats` page — table of findings (domain, brand,
  score, confidence, reasons, first_seen) + copy-able abuse-report text.
- Seed the DB with mock findings early so the UI renders before live ingest.
- Deploy: API on Render, DB on Neon, frontend on Vercel (all free tier).

## Conventions
- Every day ends at a committed, working checkpoint pushed to the branch.
- Offline-testable logic wherever possible (CI has no DB/network to crt.sh).
- Passive OSINT only — no scanning/probing. Keep the ethics note intact.
