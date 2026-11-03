# LinkGuard — client delivery

A lightweight URL checker with a browser interface, Flask API, machine learning,
security rules and optional exact-URL threat-feed matching. Submitted websites
are never opened. Low detected risk is not a safety guarantee.

**Live product:** https://phishing-url-detector-xi.vercel.app

**Backend health:** https://linkguard-api-5m93.onrender.com/health

## Start the exported product

1. Extract the ZIP completely and install **Python 3.13**.
2. On Windows, double-click **`START_LINKGUARD.cmd`**.
3. The launcher prepares `.venv`, installs the pinned dependencies on first run,
   starts the local application and opens your browser. Keep its console open;
   close it or press Ctrl+C when finished.

First setup needs internet. Later, run `START_LINKGUARD.cmd --offline` for
model/rule analysis without feed downloads or external reputation. Cached feed
matches, if present, still retain their freshness checks. Ordinary online mode
refreshes public feeds in the background; URL analysis works while they load.

On any supported platform, `python launcher.py` does the same setup. An available
loopback port is selected automatically. The local app is not exposed to the LAN.
API hosting still uses `python backend/main.py`; `render.yaml` preserves the
existing Render layout. Vercel serves the unchanged frontend.

## Client reports

- [Graphical report — two-page PDF](reports/model_improvements.pdf)
- [Presentation image](reports/model_improvements.png)
- [Measured scores — CSV](reports/model_scores.csv)

The main comparison uses **the same 48,406 test URLs from 33,285 domains absent
from both training corpora**: 16,117 phishing and 32,289 legitimate URLs. Original
models were re-scored with their frozen policies; improved configurations and
thresholds were chosen on validation before final evaluation.
Benchmark decisions use the frozen model/rule policy; review outcomes count as
non-positive. Threat-feed/reputation overrides are excluded to avoid circular
evaluation against feed-derived phishing labels.

| Model | Original phishing recall | Improved research recall | Original FPR | Improved FPR |
|---|---:|---:|---:|---:|
| Random Forest | 54.20% | 57.06% | 2.82% | 1.58% |
| XGBoost | 55.80% | 64.27% | 3.07% | 1.67% |
| LightGBM | 55.01% | 64.06% | 2.97% | 1.62% |

The complementary XGBoost/character ensemble reached **76.34% phishing recall,
85.08% F1 and 1.55% FPR**. It is a **research candidate**, not the shipped model:
it missed the predeclared 1% false-positive release gate. The existing XGBoost
artifact remains active. Random Forest is retained as the approved capstone
baseline; all three preserved models and their provenance are bundled.

The second report page uses **ealvaradob alone**, excluding UCI: 811,472 cleaned
URLs, with 178,918 test URLs from 71,527 held-out domains. Balanced accuracy is
88–89%, with 13–15% false positives. Conservative thresholds lower FPR below 1%
but reduce positive-class recall to 45–49%. Publisher malicious labels are not
represented as independently verified phishing-only ground truth.

No UCI-only 99% shortcut result is used in this client report. The production
32-feature extractor ignores the conventional `www` prefix. The shipped model
does retain legacy mixed-source training, including UCI; its independent scores
above expose its generalization limits rather than hiding them. Improved research
models used typed PhreshPhish data, additional legitimate URLs, richer features,
separate calibration and character patterns. Changes were assessed together;
the report does not claim a causal gain from a single parameter.

No dataset is proven bias-free, domain separation does not prove campaign
separation, and the legitimate comparison data are historical. The reports do
not establish 95% across all metrics. `backend/models/evaluation.json` is the
preserved training-era regression report; it is a different cohort from the client
CSV. The CSV includes thresholds, exact confusion counts, cohort fingerprint,
positive-class meaning and deployment status. Percent columns use 0–100 units.
The independent cohort is 33.3% phishing; observed precision cannot be assumed
at ordinary browsing prevalence. Research models were frozen and evaluated on
1 November; the original baselines were re-scored for this delivery on 3 November.

Sources: [PhreshPhish](https://huggingface.co/datasets/phreshphish/phreshphish),
[ealvaradob](https://huggingface.co/datasets/ealvaradob/phishing-dataset),
[OpenPhish](https://github.com/openphish/public_feed), and
[PhishTank](https://phishtank.net/developer_info.php). Publisher terms apply;
raw feed URLs are not redistributed in this delivery.

## Minimal repository

```text
START_LINKGUARD.cmd   Windows entry point
launcher.py          Local product: frontend and API on one port
backend/             API, URL features, rules, providers, training and tests
backend/models/      Three preserved models, checksums and provenance
frontend/            HTML/CSS/JS, hosting configuration and browser tests
reports/             One CSV, one graphical PDF and its presentation image
tools/               Rebuild the report and export the source package
render.yaml          Render hosting configuration
```

Full historical research, experiment scripts, old reports and documentation are
preserved on [research-archive-2026-11-03](https://github.com/5uhaeb/phishing-url-detector/tree/research-archive-2026-11-03).
Raw datasets, feed snapshots, credentials, virtual environments and experiment
artifacts are excluded from this delivery. Dataset attribution/provenance remains
in the model evaluation metadata; the Phishing.Database license is retained.

## Train on an explicitly chosen dataset

Training is optional and never runs when starting the product. Supply a CSV or
JSON with `url`, `URL` or `text`, plus binary `label`. Declare which label is the
positive class. Nothing automatically downloads or mixes UCI into training.

```powershell
.\.venv\Scripts\python.exe backend\train.py --dataset C:\datasets\urls.json --positive-label 1 --dataset-name ealvaradob --target-name malicious --infer-https --output backend\training_output\my_run
```

`--infer-https` applies the same scheme convention to bare URLs in either class.
Cleaning reports invalid, duplicate and contradictory labels. Domains are
separated across fitting/calibration/validation/test, and both balanced-F1 and
conservative operating points are reported. Source metadata is not a feature.
Use confirmed phishing labels if you intend to evaluate phishing detection.
Training writes a new directory and does not replace production artifacts.

## Tests and maintenance

```powershell
cd backend
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
cd ..\frontend
npm ci
npm run check
npm test
```

Browser tests require installed Google Chrome. Core URL analysis requires no
external reputation key. Google Web Risk is optional, consent-gated and configured
only through backend environment variables. Exact feed matches are never whole
domain blocks. Feed refresh is streamed to disk with bounded SQLite batches;
source failure retains previous indicators. URLs submitted through the UI are
not stored by the application. HTTPS, length and keywords alone do not prove safety.

To redraw the report from its CSV, install `tools/requirements.txt` and run
`python tools/client_report.py`. Recreating the underlying research measurements
requires the archived code and private/licensed snapshots; drawing charts does
not retrain models. Do not retune using the already examined final cohorts.

Export a fresh source delivery with `python tools/export_product.py --output
C:\deliveries\LinkGuard`. The ZIP includes a per-file SHA-256 manifest and excludes
private data and generated environments. Keep the original model artifacts for
rollback. Publish no research candidate without independent release validation.
