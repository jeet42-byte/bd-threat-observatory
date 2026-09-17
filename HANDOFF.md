# HANDOFF

Session-to-session state so any new session can resume without re-explaining.
Branch: `claude/nifty-ritchie-omdcrq`

## Where we are: end of Day 6

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


### Done (Day 4) — posture observatory
- `backend/app/db/models.py` — `PostureScan` (target, brand, grade A-F,
  sub-scores headers/tls/email, findings JSONB, reachable, checked_at).
- `backend/app/posture/scoring.py` — pure, weighted scoring:
  headers (HSTS/CSP/XFO/XCTO/Referrer/Permissions, 45%), TLS version (30%),
  email SPF+DMARC (25%) -> 0-100 -> A-F. Explainable findings.
- `backend/app/posture/probes.py` — passive probes: HTTPS GET headers, TLS
  handshake version, public DNS TXT (SPF/_dmarc). Best-effort, run on Actions.
- `backend/app/posture/collector.py` + `run_posture.py` — targets = brand
  official domains; idempotent upsert of PostureScan.
- `backend/app/api/v1/posture.py` + schemas — `GET /api/v1/posture`
  (filters category/grade/brand; grade_distribution + average_score).
- `.github/workflows/posture_cron.yml` — daily posture scan.
- `seed_mock.py` now also seeds 6 posture scans (A->F spread).
- Portability fixes: init_db skips pg_trgm off-Postgres so demo/tests run on
  SQLite. +9 tests (posture scoring + posture API). Suite 35/35 green.

### Verified (Day 4)
- End-to-end on SQLite: seed_mock -> 15 findings + 6 posture scans; both
  `/api/v1/threats` and `/api/v1/posture` return correct data. Grade spread
  A(bkash) B(gp) D(brac) E(nagad) F(sonali/ec.gov). OpenAPI lists /posture.

### NOT yet verified (same sandbox blocks)
- Live probes (headers/TLS/DNS) + real Postgres need GitHub Actions + Neon.
  Scoring/collector/API logic proven on SQLite; only live scan pending.


### Done (Day 5) — posture dashboard + cross-link
- `web/src/lib/types.ts` — posture types (Grade, PostureFinding, Posture,
  PostureList). `web/src/lib/postureSample.ts` — bundled fallback (6 orgs).
- `web/src/lib/api.ts` — `fetchPosture()` with sample fallback + `hasDmarc()`.
- Components: `GradeBadge`, `ScoreBar`, shared `Nav` (tabs: feed / posture).
- `web/src/app/posture/page.tsx` — org table (grade badge, headers/TLS/email
  sub-score bars, DMARC indicator), category filter, Recharts grade-distribution
  chart, findings drill-down modal, stat cards.
- `/threats` page: now uses shared Nav + new "Brand defense" column — for each
  phishing finding it shows whether the impersonated brand's real domain
  enforces DMARC (cross-links posture into the feed: is spoofing blunted?).
- `npm run build` clean (6 routes, compile + strict typecheck + lint); server
  smoke test served /posture and /threats.

### Deploy note
- Both dashboards read `NEXT_PUBLIC_API_BASE`; without it they render bundled
  sample data (so Vercel preview works before the API/DB is live).


### Done (Day 6) — polish, report, deploy prep
- `backend/app/report/generate.py` — "State of .bd Web Security" markdown
  report (grade distribution, weakest postures, common gaps, phishing summary).
  +1 test. Suite 36/36 green.
- Deploy configs: `render.yaml` (API), `web/vercel.json`, `backend/Procfile`,
  and `DEPLOYMENT.md` (Neon + Render + Vercel + Actions, step by step).
- Frontend `/about` page (methodology, ethics/legality, data sources,
  disclaimer); About added to nav.
- Replaced the posture Recharts chart with a robust CSS bar viz (renders
  identically headless; dropped recharts dep, /posture bundle 102kB -> 6.5kB).
- Real screenshots captured via Playwright/Chromium into `docs/screenshots/`
  (threats.png, posture.png, about.png, landing.png); embedded in README.

### Remaining (needs the user's dashboards)
- Live deploy: create Neon DB, set GitHub `DATABASE_URL` secret, run both
  workflows once, deploy Render (render.yaml) + Vercel (root web/, set
  NEXT_PUBLIC_API_BASE). All documented in DEPLOYMENT.md.
- Day 7 buffer: optional extra brands, more posture targets, README tweaks.

## To deploy the pipeline (when ready)
1. Create a Neon Postgres DB; get the `postgresql+asyncpg://...` URL.
2. Add repo secret `DATABASE_URL` (Settings → Secrets → Actions).
3. Run the `ingest_cron` workflow via "Run workflow" (workflow_dispatch).
4. Confirm rows land in `brands`, `domains`, `certificates`.

## Next: Day 7 (buffer) / deploy
- The whole product is built, tested (36 backend tests, clean frontend build),
  and documented. What's left is the live deploy (user's dashboards) per
  DEPLOYMENT.md, and any optional polish (more brands/targets, a hosted demo
  link in the README once Vercel is up).

## Conventions
- Every day ends at a committed, working checkpoint pushed to the branch.
- Offline-testable logic wherever possible (CI has no DB/network to crt.sh).
- Passive OSINT only — no scanning/probing. Keep the ethics note intact.
