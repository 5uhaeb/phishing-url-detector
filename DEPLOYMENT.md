# Deploying a tested model release

Phase 1 is prepared for the existing production hosts: the [Vercel frontend](https://phishing-url-detector-xi.vercel.app) and [Render API](https://linkguard-api-5m93.onrender.com).

Training and serving are separate. A backend build installs the versioned, checksum-pinned bundle in the private repository, or downloads an explicitly configured release. It never trains a new model. Retain each release and its code revision for rollback.

## Train and validate

From the project root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r dependencies.lock.txt
.\.venv\Scripts\python.exe train.py --download --jobs 4
.\.venv\Scripts\python.exe -m unittest -v
cd frontend
npm ci
npm run check
npm run build
npm test
cd ..
```

The backend suite requires the full trained model. `ci/quality-checks.workflow.yml` is an Actions template for training, release, bundled-model API and frontend checks. It is stored as a template because the current GitHub token lacks workflow-write scope. Browser tests use installed Google Chrome and the real local API. They cover four viewport widths, WCAG A/AA checks, prediction, downloads, error handling and safe URL rendering. Set `LINKGUARD_PYTHON` if the interpreter lives elsewhere.

The winner is chosen on validation domains before testing. Keep the report, split indices, dataset checksums and models together. Historical test improvements do not establish future production accuracy. Supply an independently labeled mixed-class CSV to `evaluate.py --csv <path>` for external validation; labels are 1=phishing, 0=legitimate.

## Create the release

```powershell
.\.venv\Scripts\python.exe release.py build
.\.venv\Scripts\python.exe release.py verify
```

This creates `release/current/` and `release/current.zip`, prints the archive SHA256, and includes the serving model, matching evaluation, pinned dependency lock and a per-file manifest. Existing release destinations are immutable; use `--directory release/<new-version>` for another release. The full research model and domain hashes remain outside the serving bundle.

Random Forest exports to compact arrays with score parity checks. XGBoost and LightGBM retain their calibrated estimators and require their pinned libraries at runtime. The exporter never treats a boosted model as a forest.

Install only trusted artifacts. A checksum pins bytes; joblib still uses pickle serialization. Obtain the expected hash through a trusted channel alongside the selected code revision.

## Run the release locally

```powershell
$env:MODEL_PATH = 'release/current/runtime-model.joblib'
$env:EVALUATION_PATH = 'release/current/evaluation.json'
$env:MODEL_MMAP = '1'
$env:PUBLIC_FEED_KEYS = 'phishing_database'
.\.venv\Scripts\python.exe app.py
```

`/health` returns 503 for a missing model and reports its name/version, feed freshness and rate-limit storage. `/api/models` returns comparisons only when the report matches the active model. `/evaluation` excludes stale external scores. Optional `MODEL_SHA256` verifies the individual model before loading. Invalid class order, thresholds, weights or feature schema fail startup.

## Render

The tested release is committed as `deployment/model-release.zip`, with its SHA256 pinned in `deployment/release.json`. The default `release.py fetch` installs it offline from the authenticated private checkout. Keep the source repository private. For a later release, replace the bundle and checksum together after validation.

Alternatively, set both `RELEASE_URL` (HTTPS) and `RELEASE_SHA256` to download a trusted external archive. Signed URLs belong in environment secrets. Configuring only one value fails the build.

The Blueprint installs locked dependencies, verifies the archive and each member, and sets both `MODEL_PATH` and `EVALUATION_PATH`. Missing or altered releases fail the build. Waitress listens on `0.0.0.0:$PORT`. Public feeds refresh at runtime; failed downloads remain visible without blocking the build.

Set `FRONTEND_ORIGINS` to exact trusted origins, comma-separated without wildcards. Render's hostname is trusted automatically. Configure `RATELIMIT_STORAGE_URI` with Redis before scaling beyond one process/instance. Optional `WEB_RISK_API_KEY` belongs only on the backend; each lookup still needs consent.

Production configuration enables only `phishing_database`. OpenPhish Community is personal/academic noncommercial as documented in README; enable it for client operations only with an appropriate licensed arrangement. Preserve the Phishing.Database license with downloaded snapshots.

The free plan remains configured. Memory, cold starts, throughput, shared rate limits and feed persistence still need verification on the actual host. Local tests do not establish Linux capacity.

## Docker

After building `release/current`:

```powershell
docker build -t linkguard:phase1 .
docker run --rm -p 5000:5000 --env-file .env linkguard:phase1
```

The image verifies the release, includes OpenMP for boosted models, runs as a non-root user and has an HTTP health check. Use a real `.env` with `HOST=0.0.0.0`, trusted hosts and deployment settings; it is excluded from the image. Docker validation requires a running Docker engine.

## Vercel frontend

Use project root `frontend`, output directory `dist`, and configure routing before deploying:

```powershell
cd frontend
$env:BACKEND_URL = 'https://your-service.onrender.com'
node configure-vercel.mjs
npm ci
npm run check
npm run build
```

Commit generated `vercel.json` when changing hosts. It proxies `/api/*` and sets security headers. Update Render's exact frontend-origin allowlist.

Set `LINKGUARD_BASE_URL` to the deployed frontend before `npm test` for live browser checks. Verify health, prediction through the real proxy, mobile layout, JSON download and rejection of unrelated origins. Keep URL request bodies out of infrastructure access logs.

## Rollback and release status

Redeploy the previous code revision and its bundled release, or its retained external release URL and checksum. Update model and evaluation paths together and restart workers. Local backups are in `artifacts/<run-id>/previous-release/`. Health keeps `production_validated=false` until independent future-time mixed-class validation exists.

Phase 2 redesign is deferred until the client supplies the reference and preferred resource.
