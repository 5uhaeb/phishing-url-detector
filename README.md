# LinkGuard

A phishing-link checker with a plain HTML/CSS/JavaScript frontend and a Flask backend.
The backend examines URL text, security rules and public phishing reports without visiting submitted websites.

```text
frontend/
  index.html        Page
  style.css         Styles
  app.js            API calls and results
  dev_server.py     Local frontend server and API proxy
  tests/            Browser tests
backend/
  main.py           Flask API and server entry point
  detector.py       URL validation, features, rules and model prediction
  feeds.py          Local public-feed matching
  reputation.py     Optional consent-based Google Web Risk lookup
  train.py          Train and compare all three models
  dataset.py        Download and clean training data
  metrics.py        Evaluation and validation threshold selection
  models/           Random Forest, XGBoost, LightGBM and their evaluation
  tests/            API, model, provider and training tests
  requirements.txt  Pinned Python dependencies
render.yaml         Backend hosting configuration
```

## Run locally

Use Python 3.13. From the project folder in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe backend\main.py
```

Open a second terminal in the same folder:

```powershell
.\.venv\Scripts\python.exe frontend\dev_server.py
```

Open http://127.0.0.1:5187. The frontend forwards API requests to the backend on port 5000.
The backend starts with XGBoost. To use another preserved model, set `$env:MODEL_NAME = 'random_forest'`
or `$env:MODEL_NAME = 'lightgbm'` before starting the backend. Only one model loads at a time.

## API

- `POST /api/predict`: JSON `{"url":"https://example.com","consent":false}`.
- `GET /api/status`: model, public-feed and optional external-service availability.
- `GET /api/models`: the recorded comparison of all three models.
- `GET /health`: readiness and the active model version.
- `GET /evaluation`: the matching model evaluation report.

Reports download in the frontend. Low predicted risk does not establish safety.
Submitted URLs are not stored. Google lookups require a configured key and explicit per-request consent.

## Test

```powershell
cd backend
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
cd ..\frontend
npm ci
npm run check
npm run build
npm test
```

Browser tests start both local servers and use installed Google Chrome.
The static frontend builds independently of backend files.

## Training

```powershell
.\.venv\Scripts\python.exe backend\train.py --download --output backend\training_output
```

Training uses raw UCI PhiUSIIL URLs plus the supplementary ealvaradob URL dataset.
It removes duplicate/conflicting records and separates domains between training, calibration,
validation and testing. Model weights and thresholds are selected on validation, before test scoring.
The simplified trainer uses fixed model configurations; the original parameter-search experiment is archived.
It saves all three models, checksums, split indices, evaluation JSON and comparison CSV in a new output folder.
To use a new training run, replace the model files, manifest and evaluation in `backend/models` together and restart.
Existing trained models are preserved; reorganizing the code does not retrain them.

## Research audit

The supplied development corpora can be audited without changing the frozen model or
threshold:

```powershell
.\.venv\Scripts\python.exe backend\research_audit.py `
  --combined C:\Users\shaik\Downloads\LinkGuard-Combined-Dataset\combined_phishing_dataset.csv `
  --external C:\Users\shaik\Downloads\phishing-url-detector\data\kaggle-real-world-phishing\phishing_url_dataset_unique.csv `
  --combined-split C:\Users\shaik\Downloads\Codex\phishing-url-detector-archive-2026-10-29\artifacts\20261029T154217299203Z\split-indices.npz `
  --combined-fingerprint b41677b5073aa2f2125130a6c31ebd4d3250285ce76a84e3c7468a036423e856 `
  --model backend\models\xgboost.joblib `
  --output backend\audit_output_corrected
```

The audit verifies the combined corpus fingerprint before evaluating only its held-out
test indices, and removes Kaggle records whose registrable domains occur anywhere in
the combined corpus. It writes hashes, invalid/duplicate/conflict counts, URL-style
profiles, source/type slices, domain-cluster bootstrap 95% intervals, and frozen-model
feature-ablation sensitivity. Raw-model and final-system-score AUCs are reported
separately.
Kaggle `urlhaus` positives are reported as malware and must not be called phishing
recall. These files are not an untouched final test: timestamps and independent
provenance collection are still required before a production claim.

Today's capstone work and limitations are summarized in
[the 1 November 2026 note](docs/capstone/2026-11-01.md), with
[one consolidated results CSV](docs/capstone/linkguard_final_results_2026-11-01.csv).
Reusable research scripts are in `backend/research_*.py`; generated datasets,
model candidates and intermediate reports are excluded from Git.

## Phishing-specific research (1 November 2026)

The latest experiment improves **actual phishing detection**, keeping malware
labels separate and retaining Random Forest as the capstone baseline. On the
same 48,406 unseen-domain URLs, the frozen XGBoost/character candidate improved
phishing recall from **55.80% to 76.34%**, F1 from **68.91% to 85.08%**, and FPR
from **3.07% to 1.55%**. It did **not** meet the predeclared 1% FPR release gate;
the existing production model files are unchanged. These scores use a new
cohort and must not be compared directly with the historical Kaggle aggregate.

- [Repository audit](docs/REPOSITORY_AUDIT.md): concrete issues and code corrections.
- [Dataset audit](docs/DATASET_AUDIT.md): typed labels, provenance and leakage checks.
- [Model comparison](docs/MODEL_COMPARISON.md): RF, XGBoost, LightGBM, character models and ensembles.
- [Evaluation report](docs/EVALUATION_REPORT.md): fresh phishing, malware, uncertainty, runtime and rejection decision.
- [Capstone alignment](docs/CAPSTONE_ALIGNMENT.md): requirements in the supplied abstract.
- [Consolidated results](docs/capstone/linkguard_final_results_2026-11-01.csv): historical and current cohorts explicitly identified; values are fractions.

The API now uses its full-precision classification decision; rounded display
scores cannot promote a URL across the threshold. `rule_evidence` adds stable
rule identifiers, severity, observed features and bounded index contributions.
Existing response fields, consent behavior, risk states and deployment layout
are preserved. The combined index remains a warning score, not a calibrated
phishing probability.

### Reproduce the research

Use a fresh checkout/cache for a new independent experiment. Install optional
local research dependencies (they are not added to Render's serving install):

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-research.txt
.\.venv\Scripts\python.exe backend\research_sources.py --directory backend\data\capstone_run
.\.venv\Scripts\python.exe backend\research_data.py --split train --revision eca603e0ecd4f698f8d4d226c088659e72681239
```

Use the publisher raw `additional-urls.json`, and place the Kaggle export at
`backend/data/kaggle-real-world-phishing/phishing_url_dataset_unique.csv`. The
original combined CSV is needed only to exclude domains seen by the legacy
model. It is not added to the new training mixture. Adjust these local paths:

```powershell
.\.venv\Scripts\python.exe backend\phishing_benchmark.py --stage baseline --source-directory backend\data --combined C:\datasets\combined_phishing_dataset.csv
.\.venv\Scripts\python.exe backend\phishing_benchmark.py --stage prepare --source-directory backend\data
.\.venv\Scripts\python.exe backend\phishing_benchmark.py --stage train --output backend\training_output\new_phishing_run
.\.venv\Scripts\python.exe backend\phishing_benchmark.py --stage final --output backend\training_output\new_phishing_run --combined C:\datasets\combined_phishing_dataset.csv
.\.venv\Scripts\python.exe backend\phishing_benchmark.py --stage runtime --output backend\training_output\new_phishing_run
.\.venv\Scripts\python.exe backend\research_runtime.py --output backend\training_output\new_phishing_run
```

The source acquisition script refuses to overwrite a reserved snapshot. Training
freezes all candidates, thresholds and source/model/data hashes before final
scoring; the final stage refuses reuse. Fitting uses a source/type-stratified
sample of at most 180,000 rows; character vocabulary uses at most 120,000.
No HTML or suspicious destinations are fetched. Threat-feed snapshots, trained
candidates and per-URL predictions remain ignored local artifacts; publisher
terms still apply. `research_documentation.py` regenerates this capstone run's
tables from saved results without tuning; it expects its matching baseline,
timing and protocol artifacts. Historical final cohorts cannot be reused to
tune a new candidate while retaining an independent-test claim.

## Deployment

Vercel project root: `frontend`; build: `node build.mjs`; output: `dist`.
Render service root: `backend`; build: `pip install -r requirements.txt`; start: `python main.py`.
The checked-in `render.yaml` describes this layout. For an existing Render service, update its root,
build and start settings before deploying this refactor. Set `FRONTEND_ORIGINS` to exact allowed frontend origins.
Old `MODEL_PATH` and `EVALUATION_PATH` settings are no longer used; select a model with `MODEL_NAME`.
Use shared `RATELIMIT_STORAGE_URI` storage before running multiple instances.
`backend/.env.example` lists optional environment settings; it is not loaded automatically.

## Previous research and backups

The full pre-cleanup project, original model artifacts, datasets, CSV reports and research scripts are preserved at:

`C:\Users\shaik\Downloads\Codex\phishing-url-detector-archive-2026-10-29`

The client CSV package is inside that archive at `reports/research/2026-10-29.zip`.
Dataset provenance and licenses remain in `backend/models/evaluation.json`; the public-feed license is in `backend/licenses`.
