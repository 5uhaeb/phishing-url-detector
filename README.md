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
