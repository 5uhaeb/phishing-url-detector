# Verified deployment — 1 November 2026

- Render service: `linkguard-api` (`srv-dbcgqd0m7kps739opq2g`). This is the only
  Render service connected to the LinkGuard repository; unrelated services were untouched.
- Deployment: `dep-dbjkle0u01pc73foor0g`, status **live**.
- Application commit: `092ad79bd6e42a1cc2141c4e366af6b64254a6a9`.
- Completed at **19:52 IST** (14:22 UTC).
- Root: `backend`; build: `pip install -r requirements.txt`; start: `python main.py`.
- Active model: **XGBoost**, version `2026-10-29T15:42:17.299185+00:00`.
- Model SHA-256: `08316e688c66e99e2a458802030487a26803f784ba5635b3f05872ed3177c2b9`.

The latest decision-consistency fix and structured rule evidence are now visible
in live responses. Health and prediction returned HTTP 200; direct Render and
Vercel-proxied predictions matched the local artifact. Ten Kaggle samples,
including an old rounding-boundary case, matched live features, scores, flags
and evidence. The live evaluation report equals the checked-in report.
All **7 browser tests passed against production**, including 320/375/768/1440 px,
accessibility, result download, error recovery and untrusted text rendering.

## Final deployed-model scores

These are full-dataset local batch scores using the verified matching artifact
and deployed full-precision ML/rules decision. They are not 48,803 HTTP calls.
Review outcomes count as non-positive. Feed/reputation lookups are excluded from
benchmarking; the live service currently reports missing public-feed snapshots
and no configured external reputation. No threat-intelligence accuracy is claimed.

| Kaggle cohort | URLs | Accuracy | Precision | Malicious recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|
| All cleaned URLs | 48,803 | 94.18% | 99.52% | 88.79% | 93.85% | 0.43% |
| Domains absent from original training corpus | 42,781 | 93.82% | 99.52% | 89.47% | 94.23% | 0.56% |

OpenPhish-only recall remains **43.24% (128/296)** overall and **38.87%
(103/265)** on unseen domains. URLhaus malware supplies most Kaggle positives;
the aggregate recall must not be described as phishing recall. The small change
from previous 94.21%/93.86% accuracy comes from eliminating 15 rounded-threshold
malware decisions; it is not a retraining result.

The independent paired phishing comparison remains: existing XGBoost 55.80%
recall / 3.07% FPR; research ensemble 76.34% / 1.55%. Those are different cohorts
from Kaggle. The ensemble was **not deployed**, because its FPR confidence bound
exceeds the predeclared 1% gate. No claim of 95% across all target metrics is made.

See [EVALUATION_REPORT.md](EVALUATION_REPORT.md) for dataset limitations,
uncertainty, source-specific results and the acceptance decision. Automatic
deployment remains disabled; future application releases require a manual deploy.
