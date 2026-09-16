# HANDOFF

Session-to-session state so any new session can resume without re-explaining.
Branch: `claude/nifty-ritchie-omdcrq`

## Where we are: end of Day 1

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

## To deploy the pipeline (when ready)
1. Create a Neon Postgres DB; get the `postgresql+asyncpg://...` URL.
2. Add repo secret `DATABASE_URL` (Settings → Secrets → Actions).
3. Run the `ingest_cron` workflow via "Run workflow" (workflow_dispatch).
4. Confirm rows land in `brands`, `domains`, `certificates`.

## Next: Day 2 — phishing detection engine
- `permute.py` — typosquat/homoglyph generator over brand keywords
  (character swaps, insertions, homoglyphs, TLD swaps, keyword+suffix combos).
- Matching: compare discovered `domains` against brand keywords using
  `pg_trgm` similarity + permutation hits; exclude each brand's
  `official_domains`.
- `classify.py` — score each candidate (rule-based first; LLM optional) into a
  `threat_findings` table: brand, domain, risk_score, reasons, first_seen.
- Add a `ThreatFinding` model referencing `Domain` + `Brand`.
- Keep it idempotent and covered by offline tests.

## Conventions
- Every day ends at a committed, working checkpoint pushed to the branch.
- Offline-testable logic wherever possible (CI has no DB/network to crt.sh).
- Passive OSINT only — no scanning/probing. Keep the ethics note intact.
