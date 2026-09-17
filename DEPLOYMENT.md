# Deployment

The stack runs entirely on free tiers: **Neon** (Postgres), **Render** (API),
**Vercel** (dashboard), **GitHub Actions** (scheduled collectors).

Everything below is one-time setup. Once done, the pipeline runs itself.

## 1. Database — Neon

1. Create a project at <https://neon.tech> → a Postgres 16 database.
2. Copy the connection string and convert it to the async driver form:
   ```
   postgresql+asyncpg://USER:PASSWORD@HOST/DBNAME
   ```
   (Change the scheme from `postgresql://` to `postgresql+asyncpg://`; drop any
   `?sslmode=require` — asyncpg negotiates TLS automatically.)

## 2. Secrets — GitHub

Repo → Settings → Secrets and variables → Actions → **New repository secret**:

| Name | Value |
|---|---|
| `DATABASE_URL` | the `postgresql+asyncpg://…` URL from step 1 |
| `GSB_API_KEY` | _(optional)_ Google Safe Browsing API key to enable that intel source |

The two workflows read this secret:
- **Ingest (Certificate Transparency)** — `.github/workflows/ingest_cron.yml`, every 6h
- **Posture scan** — `.github/workflows/posture_cron.yml`, daily

Trigger each once now via **Actions → (workflow) → Run workflow** to populate
the database. (Or run `python -m app.db.seed_mock` against the DB for a demo.)

## 3. API — Render

1. New → **Blueprint**, point it at this repo. Render reads `render.yaml`.
2. Set the `DATABASE_URL` environment variable (same value as step 2) — it is
   marked `sync: false`, so it must be entered in the dashboard.
3. Deploy. The service exposes `/health` and `/api/v1/*`.
   Note the URL, e.g. `https://bd-threat-observatory-api.onrender.com`.

> Free Render services sleep after ~15 min idle; the first request wakes them.

## 4. Dashboard — Vercel

1. New Project → import this repo → set **Root Directory** to `web`.
2. Environment variable:
   | Name | Value |
   |---|---|
   | `NEXT_PUBLIC_API_BASE` | the Render API URL from step 3 (no trailing slash) |
3. Deploy. Without this variable the dashboard still renders bundled sample
   data, so a preview works even before the API is connected.

## 5. Report (optional)

Generate the "State of .bd Web Security" briefing from live data:

```bash
cd backend
DATABASE_URL="postgresql+asyncpg://…" python -m app.report.generate > REPORT.md
```

## Local development

```bash
# API
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
export DATABASE_URL="postgresql+asyncpg://…"   # or a local Postgres
python -m app.db.seed_mock                      # demo data
uvicorn app.main:app --reload

# Dashboard
cd web && npm install
echo "NEXT_PUBLIC_API_BASE=http://localhost:8000" > .env.local
npm run dev
```
