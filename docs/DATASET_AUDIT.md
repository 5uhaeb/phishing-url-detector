# Dataset audit

This experiment uses three semantic labels: legitimate (0), phishing (1), and
malware (2). Neither provenance, dates, source names nor target brands are model
inputs. A URLhaus report is not converted into phishing ground truth.

## Development inputs

- [PhreshPhish](https://huggingface.co/datasets/phreshphish/phreshphish), **TRAIN
  metadata only**, revision `eca603e0ecd4f698f8d4d226c088659e72681239`, 498,255
  raw rows. Publisher labels are `phish`/`benign`; the corpus has actual collection
  dates. License: CC BY 4.0, with publisher research-use guidance. The previously
  examined upstream TEST partition is not reused for candidate selection or a
  new untouched-test claim. HTML is never downloaded.
- [ealvaradob](https://huggingface.co/datasets/ealvaradob/phishing-dataset): a
  seed-20261101 sample of 100,000 publisher-labelled legitimate URLs from the
  existing local corpus. Only label 0 is used: its generic malicious class is
  not assumed to consist entirely of phishing. Missing schemes receive `https://`
  consistently. Collection timestamps are unavailable. Publisher declares
  Apache 2.0; underlying-source provenance still limits interpretation.
- [Historical Kaggle real-world URLs](https://www.kaggle.com/datasets/dhrubangtalukdar/real-world-phishing-url-classification-data):
  24,106 raw URLhaus rows are typed as malware development examples. Kaggle's
  OpenPhish and Tranco records are excluded from this training corpus. Once
  URLhaus is used for development, the original Kaggle aggregate is historical
  evidence, not a fresh test for the new model.

Cleaning 622,361 input rows removed 4,586 invalid and 683 duplicate rows, leaving
**617,092** records; no contradictory normalized type labels were found in this
development mixture. Counts are measured, not publisher totals substituted for
cleaned data. Full input SHA-256s and source counts per partition are recorded
locally in `backend/data/capstone_run/dataset_audit.json`.

| Domain partition | Legitimate | Phishing | Malware | Total | Domains |
|---|---:|---:|---:|---:|---:|
| Fitting | 217,638 | 115,492 | 14,386 | 347,516 | 140,515 |
| Calibration | 47,464 | 18,083 | 2,683 | 68,230 | 23,453 |
| Validation | 33,612 | 24,043 | 2,681 | 60,336 | 23,418 |
| Reserved within-source test | 73,041 | 63,617 | 4,352 | 141,010 | 47,032 |

SHA-256 of seed plus registrable domain assigns about 60/10/10/20 percent of
domains. Row/class ratios differ because domains have different numbers of URLs;
they are not silently rebalanced after seeing results. Fitting is capped at
180,000 rows, stratified jointly by source/type. Character vocabulary fitting
is capped at 120,000 phishing/legitimate fitting rows. Calibration, validation
and test never contribute vocabulary or model fitting records. Early stopping
uses validation, never test. Every domain receives exactly one partition.

## Canonicalization and leakage

The shared parser requires explicit HTTP(S), validates host/port/IDNA/percent
encoding, lowercases scheme and host and supplies an empty root path. Research
identity removes default ports but preserves userinfo, path/query spelling,
query order, `www` and fragments. Production's older 32 measurements continue
to ignore conventional `www` and fragments; the research 64-feature view
explicitly includes fragment information. No percent-decoding, path sorting or
global lowercasing changes URL identity. Conflicting exact normalized types are
removed before exact deduplication; related campaigns/templates may still cross
domain boundaries. The bundled PSL includes private suffixes.

## Reserved independent phishing inputs

[OpenPhish Community](https://github.com/openphish/public_feed) and
[PhishTank's verified-online export](https://phishtank.net/developer_info.php)
were downloaded on 1 November 2026, before new candidate selection. The initial
PhishTank URL redirects to its publisher CDN; only that HTTPS host/path is
allowed by `research_sources.py`. 51,813 PhishTank entries are marked verified
and online. Verification dates span 2011–2026: retrieval time is not first-seen
time. A separate recent slice uses verification dates on/after 2 October 2026.
Follow publisher terms; raw snapshots and URLs remain excluded from Git.

Feed holdouts are cleaned/deduplicated and exclude **all development-corpus
domains**, including reserved within-source domains. A paired comparison also
excludes every domain in the original combined training corpus, so the old and
new models are compared fairly. The denominator after these exclusions is in
the evaluation report. No final-feed URL is used to fit or calibrate models,
choose thresholds, or select a candidate. These feed-derived labels are never
looked up in the same feeds when measuring detection.

The negative side of the fresh-phishing comparison consists of reserved
historical legitimate domains, not newly adjudicated contemporary browsing.
There is no claim of independent recent benign ground truth, independent
campaigns, or complete temporal separation for sources without timestamps.
