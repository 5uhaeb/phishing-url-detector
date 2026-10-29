# Lightweight Hybrid Phishing URL Detection

A responsive LinkGuard interface, public phishing-feed matching, cybersecurity rules, and a calibrated model selected from Random Forest, XGBoost and LightGBM. The default setup requires no API key. Submitted URLs are never visited, logged, or saved by the application. A local SQLite index stores downloaded public threat indicators, not user submissions. There is no frontend framework or user account system.

The Flask interface works without JavaScript. A separate static frontend in `frontend/` supports Vercel hosting with the Python API on Render. Both interfaces share the responsive stylesheet, including mobile layouts, visible keyboard focus and readable risk states. See [DEPLOYMENT.md](DEPLOYMENT.md) for deployment configuration and browser tests.

## Run on Windows

Open PowerShell in this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r dependencies.lock.txt
.\.venv\Scripts\python.exe train.py --download
.\.venv\Scripts\python.exe feeds.py
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000. Stop with Ctrl+C. Restart after retraining. The server uses Waitress with four threads and binds only to loopback. It refreshes feed snapshots when needed, checks every 12 hours, and expires snapshots after 24 hours. Internet hosting still needs HTTPS, trusted host/proxy configuration, shared rate-limit storage, monitoring, and independent future-time validation. A production WSGI server does not establish production detection accuracy.

Training downloads the public UCI archive (~15 MB compressed) and the supplementary raw URL JSON (~73 MB). It does not visit any dataset URLs or execute remote dataset-loader code. The default uses the full UCI dataset plus a stratified 200,000-row sample of the supplementary corpus with seed 42; `--max-rows 40000` limits the combined dataset for quick experiments. Reproduce the evaluation:

```powershell
.\.venv\Scripts\python.exe train.py --max-rows 0
.\.venv\Scripts\python.exe -m unittest -v
.\.venv\Scripts\python.exe evaluate.py --limit 500
.\.venv\Scripts\python.exe benchmark.py
```

Run tests after training. The committed `dependencies.lock.txt` pins the verified environment. Update it deliberately when changing dependencies.

## Files

- `app.py`: Flask page, JSON prediction endpoint, and health endpoint.
- `detector.py`: URL validation, normalization, 32 lexical features, rules, and combined local decisions.
- `train.py`: download, cleaning, training, validation threshold selection, and test evaluation.
- `feeds.py`: download fixed public sources, build the local exact-URL index, and track expiry/provenance.
- `reputation.py`: optional consent-gated Google Web Risk adapter and evidence precedence.
- `evaluate.py`: evaluate unchanged model thresholds on unseen-domain feed samples or a labeled external CSV.
- `benchmark.py`: separate offline paper-context experiment using UCI's 30 precomputed website features.
- `templates/index.html`: basic HTML form and result table.
- `test_detector.py`: validation, offline behavior, and application checks.
- `requirements.txt`: Python dependencies.

The pinned dependency lock is committed. Generated files include `data/` (datasets, feed snapshots, feed index, source license, prior model backup), `model.joblib`, `evaluation.json`, `external-evaluation.json`, `benchmark-results.json`, and immutable experiment/release artifacts. Data, model artifacts, and the environment are ignored by Git. Do not load model files from untrusted sources: joblib uses pickle serialization.

## Phase 1: three-model training

The project is now developed in `C:/Users/shaik/Downloads/Codex/phishing-url-detector`, on branch `phase-1-model-comparison`. The original Downloads project remains intact.

```powershell
# Full comparison; promote the validation-selected champion locally.
.\.venv\Scripts\python.exe train.py --jobs 4
# Experiment without changing local serving files.
.\.venv\Scripts\python.exe train.py --max-rows 40000 --no-promote
```

1. Read raw URLs and labels from both sources. Invert UCI labels explicitly: internal 1=phishing. Remove contradictory labels, exact duplicates, invalid URLs and normalized duplicates. Never visit dataset URLs or use precomputed webpage features.
2. Measure 32 lexical features using the same extractor at training and inference. Ignore the conventional leading www prefix in measurements to reduce collection bias. UCI-only legitimate URLs are all homepages; the supplementary source supplies ordinary paths and queries.
3. Use the same deterministic, registered-domain-disjoint training/calibration/validation/test partitions for all three families, approximately 60/10/10/20. Private hosted domains use the bundled suffix list. Save exact split indices, dataset checksums and split fingerprints.
4. Train two predeclared parameter settings per family. Fit sigmoid calibration only on calibration domains. Search exact validation score cutoffs to maximize phishing recall subject to validation false-positive rate <=1% (configurable with `--max-fpr`). Tied scores stay together; predicting no positives is a valid fallback.
5. Compare model shares of 100%, 90% and 80% in the local risk index. Freeze the parameter setting, model share and threshold using validation recall, then precision and average precision. Select the champion before computing test predictions. Rules remain visible even when their index share is zero.
6. Report every family on the same frozen test partition: accuracy, precision, recall, F1, FPR, confusion matrix, ROC AUC, average precision, Brier score and inference latency. Also report the standalone calibrated model at its selected cutoff and at 0.5. Feed matches are excluded.
7. Preserve all family artifacts in `artifacts/<run-id>/`, with the previous local release in `previous-release/`. Export a serving copy and update the local champion unless `--no-promote` is set. Restart the app after promotion. For deployment, package a verified immutable release; see [DEPLOYMENT.md](DEPLOYMENT.md).

Read [reports/comparison.md](reports/comparison.md) for measured results and [reports/comparison.json](reports/comparison.json) for the full audit. `/api/models` returns current model comparisons. Prediction responses include `model_name` and `model_weight`; both interfaces display the active model accurately. Old external evaluations are excluded from the export when their model version differs.

The historical test split has been used during previous development. These are controlled regression comparisons, not a new prospective benchmark. Validation FPR is a selection target; future and test FPR can exceed it. Historical calibration can fail on new campaigns. A risk index is not a probability or proof of safety. URL-only inference does not inspect webpage content, redirects, DNS, certificates or domain age.

Fresh exact public-feed matches take precedence. Otherwise, local warnings and an explicit verification field remain separate. Optional Google Web Risk requires a configured key and explicit per-request consent. Missing evidence is never treated as proof of safety. Rule indicators describe triggered checks, not individual explanations of the learned model.

Phase 2 redesign is deferred until the client supplies the preferred reference/resource.

## Free public threat intelligence

- OpenPhish official community feed: https://github.com/openphish/public_feed . Updated by the source every 12 hours; personal/non-commercial academic research only. Terms: https://openphish.com/terms.html . Do not use this feed for commercial operations or redistribute its contents without permission.
- Phishing.Database: https://github.com/Phishing-Database/Phishing.Database . MIT-licensed public URL reports; downloads use its active URL file. License: https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE . The downloaded original license is retained in `data/feeds/Phishing.Database-LICENSE.txt`; retain it when copying the snapshots/index. Preserve all upstream attribution.

Matching is conservative: URL path, query case, and fragment distinctions are retained. We do not block an entire shared hostname because one page was reported. Missing, stale, malformed, or failed downloads are visible; an invalid response never replaces a good indexed snapshot. Absence from these limited lists does not establish safety. The SQLite index is queried locally and no submitted URL is sent to feed sources. Download times are recorded; they do not prove the source recently visited a URL or that it remains online.

Google Web Risk remains optional and disabled without `WEB_RISK_API_KEY`. If you supply your own legitimate key in the server environment, each request still requires explicit consent; API JSON uses `"consent": true`. Never use keys discovered in other people's repositories. This adapter can require billing, so it is not needed for the free default. URLs with embedded credentials/private numeric addresses/reserved destinations are not sent. Failures are reported as unavailable, never as clean; matches expire according to provider timestamps. The official endpoint is fixed, redirects disabled, and connect/read timeouts bounded.

## Historical baseline (16 October 2026, India time)

Before phase 1, `evaluation.json` recorded the multi-source baseline, including source checksums, source/class path distributions, disjoint-domain split sizes, and current metrics. Feed results are excluded. The previous UCI-only experiment reported 97.46% accuracy but failed ordinary repository/video/documentation links because all legitimate training records were homepages. Its model and report are retained under `data/before-path-bias-*` for the audit; those scores must not be advertised as current real-world performance. The supplementary dataset corrects the missing legitimate-path coverage; no GitHub/YouTube whitelist is used.

`external-evaluation.json` filters out every registered domain used anywhere in the current development experiment and uses one URL per remaining domain. Always compare its `model_version` with the current model; rerun it after training. These positive-only samples measure recall, not precision, F1, false-positive rate, or accuracy. Feed matching against the same snapshots is only an integration check. Feed labels can be wrong, and the snapshots do not provide independent manual verification or a future-time test.

The regression suite also evaluates ordinary real-world URL structures, including repository paths, YouTube video queries, documentation, and sign-in pages. These are manually selected diagnostic examples, not an independent accuracy dataset or a live verification of those pages. The scanner does not fetch their contents.

The preserved pre-phase-1 baseline, after the path-bias correction, measured 84.47% accuracy, 65.47% phishing recall, and 0.90% false-positive rate at the conservative validation-selected threshold. On new-domain positive-only feed samples, model-only recall was 210/244 (86.07%) for OpenPhish and 245/500 (49.00%) for Phishing.Database; all 744 exact feed matches were separately recognized. This generalization gap remains material: the standalone model is not production-ready. Ordinary GitHub repository URLs and youtube.com now score Low in the curated regression checks, while some video/sign-in/documentation URLs and the user-reported phishing example remain Medium. Full live API regression output is saved in `data/real-url-checks.json`; these cases must not be counted as an independent performance benchmark.

For independent mixed-class evaluation, provide `--csv path.csv` to `evaluate.py`, using columns `URL,label` with 1=phishing and 0=legitimate. This differs from the original UCI label convention. Input source provenance and label quality remain the researcher's responsibility. No model or threshold is refitted by evaluation.

## Paper comparison and benchmark limits

There is no universal IEEE accuracy benchmark. The supplied base paper is published by EURASIP/Springer, not IEEE. EnLeM reports 97.21% accuracy and 97.51% F1 on UCI Phishing Websites 327 (11,055 rows / 30 precomputed website features), using 10-fold validation. Its feature inputs differ from our deployed raw-URL model. Source: https://link.springer.com/article/10.1186/s13635-025-00219-1 .

`benchmark.py` evaluates a fixed Random Forest on that dataset under two explicit protocols: stratified 10-fold validation and validation grouping identical feature vectors. It does not tune against test folds and never deploys that model as a raw-URL checker. The measured accuracy was 97.24% with stratified folds and 95.43% with identical-vector grouping. Phishing F1 was 96.87% and 94.87%, respectively; averaging conventions can differ from the paper. Only 5,785 distinct feature vectors exist among the 11,055 records. The small accuracy difference from the paper is not evidence of superiority, and its reported F1 target has not been reached. Exact fold indices and a comparable controlled protocol are needed before claiming to match or exceed the paper.

The offline benchmark dataset is from Mohammad and McCluskey, UCI, CC BY 4.0: https://archive.ics.uci.edu/dataset/327/phishing+websites ; DOI https://doi.org/10.24432/C51W2X . Its precomputed features include website information not available from URL text; therefore this benchmark model is not used by `app.py`.

## Deployment controls

The application limits POST analysis across the form/API/export to 30 requests/minute and 300/hour per remote IP, caps body/form size, blocks cross-site browser POSTs, and sets no-store/referrer/frame/content security headers. `/health` reports model/feed readiness and explicitly reports `production_validated: false`. Submitted suspicious URLs are rendered as escaped text rather than clickable links. Downloaded reports are generated on request and not stored.

Rate limiting defaults to per-process memory for this local setup. A multi-instance deployment needs shared storage, for example `RATELIMIT_STORAGE_URI=redis://127.0.0.1:6379/0`, with a Redis service you operate. Host headers default to localhost/loopback only; set `ALLOWED_HOSTS` to your allowed comma-separated hosts for deployment. No forwarded IP headers are trusted by default; configure only a known trusted reverse proxy before using them for per-client limits. Configure TLS at the proxy and keep Waitress inaccessible except through that proxy. No cloud services, billing, accounts, or paid keys were enabled by this project.

Form privacy uses `Referrer-Policy: same-origin`, which withholds referrers from other origins while allowing normal browser form submissions. An opaque `Origin: null` is accepted only when browser-controlled `Sec-Fetch-Site: same-origin` confirms the request context. Cross-site metadata, mismatched origins, and opaque origins without that confirmation are rejected. Rejected HTML forms show a reload message; the JSON API retains structured errors. This also handles old tabs loaded before the referrer-policy correction.

## API

`POST /api/predict` accepts JSON `{"url":"https://example.com"}`. Returns final evidence-based prediction, risk, local model output, rule indicators, features, public-feed evidence, optional external reputation state, and latency. `POST /report` downloads a newly calculated JSON analysis; optional external consent must be given again for that export. `GET /evaluation` downloads the model, independent-domain, and paper-context evaluation reports. `GET /health` returns 200 when the model is loaded or 503 when missing, with separate feed/reputation statuses. Invalid/oversized/rate-limited inputs return 400/413/429. No history is retained; do not configure proxy/body logging to collect submitted URLs.

## Attribution and academic use

Dataset: Arvind Prasad and Shalini Chandra (2024), *PhiUSIIL Phishing URL (Website)*, UCI Machine Learning Repository, CC BY 4.0. https://archive.ics.uci.edu/dataset/967/phiusil-phishing-url-dataset . Dataset DOI listed by UCI: https://doi.org/10.1016/j.cose.2023.103545 . Derived features are computed locally; source labels are inverted internally.

Supplementary raw URL dataset: ealvaradob, *Phishing Dataset*, URL-only `urls.json` configuration, declared Apache-2.0 by its publisher: https://huggingface.co/datasets/ealvaradob/phishing-dataset . Its card documents the original Kaggle/JPCERT/GitHub/open-database compilation. Only JSON text/labels are loaded; no remote Python loader is executed. Original 1=phishing / 0=benign labels are explicitly converted to the training convention. Bare URLs receive an inferred https:// scheme consistently across both classes; this assumption and counts are recorded in the report. This historical compiled dataset can have labeling/source bias and does not establish current website safety. `--no-additional-data` is available only to reproduce the known-biased UCI-only baseline.

Base paper: Yeasmin et al. (2026), *EnLeM: ensemble learning-based model to detect phishing websites*, EURASIP Journal on Information Security, article 1. https://doi.org/10.1186/s13635-025-00219-1 . EnLeM uses Decision Tree/Random Forest/k-NN voting; this project combines lexical rules with a calibrated model selected from Random Forest, XGBoost and LightGBM. It is not a reproduction of EnLeM or its reported results.

This implementation was prepared with AI assistance. Review the code, reproduce the experiments, explain the choices in your own words, and follow your university's disclosure policy. Original implementation does not replace citation of the dataset and research sources.

Remaining future work: batch input, monitored periodic retraining, a browser extension and email URL extraction. Phase 1 adds the model comparison and optimization workflow described above.
