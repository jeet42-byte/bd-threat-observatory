# HANDOFF

Session-to-session state so any new session can resume without re-explaining.
Branch: `claude/nifty-ritchie-omdcrq`

## Where we are: end of Day 3

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


### Done (Day 3) — public API + dashboard
- `backend/app/api/schemas.py` — Pydantic response models.
- `backend/app/api/v1/{threats,brands,stats}.py` — routers.
  - `GET /api/v1/threats` filters: brand, confidence, min_score, status, paging.
  - `GET /api/v1/brands`, `GET /api/v1/stats` (counts by confidence/brand).
- `backend/app/main.py` — FastAPI app, CORS, `/health`.
- `backend/app/db/seed_mock.py` — synthetic domains+findings for demos.
- Made ORM JSON columns cross-dialect (JSONType = JSON + Postgres JSONB variant)
  and engine pool args conditional, so tests run on SQLite.
- `backend/tests/test_api.py` — 6 integration tests over in-process SQLite
  (endpoints, filters, joins). Suite now 26/26 green.
- `web/` — Next.js 14 + Tailwind dashboard:
  - `/` landing, `/threats` feed (stat cards, brand/confidence/min-score
    filters, risk badges, signal chips, abuse-report modal with copy).
  - `src/lib/{api,types,sample,abuse}.ts` — API client with bundled sample
    fallback so it renders before the backend is live.
- `.github/workflows/ci.yml` now installs requirements-dev.txt (aiosqlite).

### Verified (Day 3)
- `npm run build` clean (compile + strict typecheck + lint). `/threats`
  prerenders; server smoke test served `/` and `/threats` with sample fallback.
- API import + OpenAPI + 6 SQLite integration tests green.

### NOT yet verified (same sandbox blocks)
- Live crt.sh fetch + real Postgres still need GitHub Actions + Neon
  `DATABASE_URL`. API/detector logic proven on SQLite; only live ingest pending.

## To deploy the pipeline (when ready)
1. Create a Neon Postgres DB; get the `postgresql+asyncpg://...` URL.
2. Add repo secret `DATABASE_URL` (Settings → Secrets → Actions).
3. Run the `ingest_cron` workflow via "Run workflow" (workflow_dispatch).
4. Confirm rows land in `brands`, `domains`, `certificates`.

## Next: Day 4 — posture observatory collector
- Reuse discovered registrable domains (from `domains`) for BD orgs; add
  `PostureScan` model (org, grade A-F, sub-scores, checked_at).
- Passive checks only: HTTP security headers (HSTS, CSP, X-Frame-Options),
  TLS version/cipher, and email auth (SPF/DKIM/DMARC via public DNS TXT).
  All from a normal request / public DNS — no scanning.
- Grading logic + `/api/v1/posture` endpoints; keep offline-testable
  (feed synthetic header/DNS dicts into pure scoring functions).
- Note: these checks also need outbound egress -> run on GitHub Actions.

## Conventions
- Every day ends at a committed, working checkpoint pushed to the branch.
- Offline-testable logic wherever possible (CI has no DB/network to crt.sh).
- Passive OSINT only — no scanning/probing. Keep the ethics note intact.
