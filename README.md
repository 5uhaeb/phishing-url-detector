# Lightweight Hybrid Phishing URL Detection

A responsive LinkGuard interface, public phishing-feed matching, cybersecurity rules, and a calibrated Random Forest. The default setup requires no API key. Submitted URLs are never visited, logged, or saved by the application. A local SQLite index stores downloaded public threat indicators, not user submissions. There is no frontend framework or user account system.

The Flask interface works without JavaScript. A separate static frontend in `frontend/` supports Vercel hosting with the Python API on Render. Both interfaces share the responsive stylesheet, including mobile layouts, visible keyboard focus and readable risk states. See [DEPLOYMENT.md](DEPLOYMENT.md) for deployment configuration and browser tests.

## Run on Windows

Open PowerShell in this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
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

Run tests after training. Capture exact installed versions with `python -m pip freeze > dependencies.lock.txt` using the virtual environment's Python.

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

Generated files include `data/` (datasets, feed snapshots, feed index, source license, prior model backup), `model.joblib`, `evaluation.json`, `external-evaluation.json`, `benchmark-results.json`, and `dependencies.lock.txt`. Data, model artifacts, and the environment are ignored by Git. Do not load model files from untrusted sources: joblib uses pickle serialization.

## Method

1. Read only raw URLs and labels, ignoring UCI's precomputed webpage features. Add the documented ealvaradob raw-URL corpus so legitimate training URLs include paths and queries. UCI PhiUSIIL contains no legitimate non-root paths; using it alone taught an invalid path=phishing shortcut. The original UCI-only metrics are retained only as a biased development baseline, not evidence of general-purpose link detection.
2. Remove duplicate and conflicting labels, sample reproducibly, validate/normalize URLs, then remove normalized duplicates/conflicts.
3. Ignore a conventional leading `www.` in lexical feature measurements to reduce a collection-style shortcut noticed during smoke testing. The original URL stays visible and is never redirected or rewritten. Feature lengths/subdomain counts refer to this measurement form. Split approximately 60% training, 20% validation, 20% test by registered domain. Private suffixes such as hosted blog domains are included using tldextract's bundled suffix list; submitted URLs never trigger suffix-list downloads.
4. Train 240 trees, maximum depth 24, minimum leaf size 2, balanced class weights, seed 42. No scaling is needed for tree splits. Fit sigmoid score calibration using a separately held-out set of domains.
5. Compute a fixed combined index: `0.8 * model score + 0.2 * rule score`. The weights and rules are design choices, not results from the base paper.
6. Use approximately 60/10/10/20 train/calibrate/threshold-selection/test splits, disjoint by registered domain. Select thresholds to maximize validation recall subject to validation false-positive rate <=1%. This is a validation target, not a guaranteed production bound. Never select thresholds on test results. The standalone label uses its own validation-selected threshold.
7. Exact URL matches in fresh public feeds take priority and show Known phishing threat with source and download time. This means a source reported that URL, not that this application visited or independently verified it. Otherwise local high scores show Suspicious URL and ambiguous/medium signals show Needs review. Low local scores show Low predicted risk. A separate Verification field describes what independent evidence was checked; missing external verification does not turn a low predicted risk into Unknown. Low risk still does not establish safety. An optional negative Google lookup never overrides a local warning. Expired feed matches can trigger review but cannot be presented as current threat evidence.

Internal label 1 means phishing. UCI's label 1 means legitimate, so training explicitly inverts the original labels. `evaluation.json` records split class counts, thresholds, confusion matrices (rows=true, columns=predicted; legitimate then phishing), accuracy/precision/recall/F1, training time, batch inference, median/p95 single-URL analysis time, data checksum, and environment details. Report actual results, even if the hybrid performs worse than Random Forest alone.

Rules inspect IP hosts, @, subdomains, lengths, hyphens, digit ratio, keywords, HTTP, punycode, percent encoding, opaque path tokens, brands in subdomains, and nested destination URLs. These are warning signals, not proof of phishing or local explanations of the model. Model scores are sigmoid-calibrated on historical data; calibration can fail under distribution shift. The combined index is not a probability. HTTPS, familiar names, and low model scores do not guarantee safety. URL-only inference does not inspect site content, redirects, DNS, certificates, or domain age. The product adds public-feed evidence but still cannot guarantee detection of new attacks.

## Free public threat intelligence

- OpenPhish official community feed: https://github.com/openphish/public_feed . Updated by the source every 12 hours; personal/non-commercial academic research only. Terms: https://openphish.com/terms.html . Do not use this feed for commercial operations or redistribute its contents without permission.
- Phishing.Database: https://github.com/Phishing-Database/Phishing.Database . MIT-licensed public URL reports; downloads use its active URL file. License: https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE . The downloaded original license is retained in `data/feeds/Phishing.Database-LICENSE.txt`; retain it when copying the snapshots/index. Preserve all upstream attribution.

Matching is conservative: URL path, query case, and fragment distinctions are retained. We do not block an entire shared hostname because one page was reported. Missing, stale, malformed, or failed downloads are visible; an invalid response never replaces a good indexed snapshot. Absence from these limited lists does not establish safety. The SQLite index is queried locally and no submitted URL is sent to feed sources. Download times are recorded; they do not prove the source recently visited a URL or that it remains online.

Google Web Risk remains optional and disabled without `WEB_RISK_API_KEY`. If you supply your own legitimate key in the server environment, each request still requires explicit consent; API JSON uses `"consent": true`. Never use keys discovered in other people's repositories. This adapter can require billing, so it is not needed for the free default. URLs with embedded credentials/private numeric addresses/reserved destinations are not sent. Failures are reported as unavailable, never as clean; matches expire according to provider timestamps. The official endpoint is fixed, redirects disabled, and connect/read timeouts bounded.

## Measured results (16 October 2026, India time)

`evaluation.json` records the currently deployed multi-source experiment, including source checksums, source/class path distributions, disjoint-domain split sizes, and current metrics. Feed results are excluded. The previous UCI-only experiment reported 97.46% accuracy but failed ordinary repository/video/documentation links because all legitimate training records were homepages. Its model and report are retained under `data/before-path-bias-*` for the audit; those scores must not be advertised as current real-world performance. The supplementary dataset corrects the missing legitimate-path coverage; no GitHub/YouTube whitelist is used.

`external-evaluation.json` filters out every registered domain used anywhere in the current development experiment and uses one URL per remaining domain. Always compare its `model_version` with the current model; rerun it after training. These positive-only samples measure recall, not precision, F1, false-positive rate, or accuracy. Feed matching against the same snapshots is only an integration check. Feed labels can be wrong, and the snapshots do not provide independent manual verification or a future-time test.

The regression suite also evaluates ordinary real-world URL structures, including repository paths, YouTube video queries, documentation, and sign-in pages. These are manually selected diagnostic examples, not an independent accuracy dataset or a live verification of those pages. The scanner does not fetch their contents.

After the path-bias correction, the mixed-source held-out hybrid measured 84.47% accuracy, 65.47% phishing recall, and 0.90% false-positive rate at the conservative validation-selected threshold. On new-domain positive-only feed samples, model-only recall was 210/244 (86.07%) for OpenPhish and 245/500 (49.00%) for Phishing.Database; all 744 exact feed matches were separately recognized. This generalization gap remains material: the standalone model is not production-ready. Ordinary GitHub repository URLs and youtube.com now score Low in the curated regression checks, while some video/sign-in/documentation URLs and the user-reported phishing example remain Medium. Full live API regression output is saved in `data/real-url-checks.json`; these cases must not be counted as an independent performance benchmark.

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

Base paper: Yeasmin et al. (2026), *EnLeM: ensemble learning-based model to detect phishing websites*, EURASIP Journal on Information Security, article 1. https://doi.org/10.1186/s13635-025-00219-1 . EnLeM uses Decision Tree/Random Forest/k-NN voting; this project instead combines lexical cybersecurity rules with Random Forest. It is not a reproduction of EnLeM or its reported results.

This implementation was prepared with AI assistance. Review the code, reproduce the experiments, explain the choices in your own words, and follow your university's disclosure policy. Original implementation does not replace citation of the dataset and research sources.

Future work from the abstract: batch input, periodic retraining, model optimization, browser extension, and email URL extraction. These are outside this first version.
