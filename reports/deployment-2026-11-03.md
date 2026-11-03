# XGBoost deployment ? 3 November 2026

- Model: `xgboost_domain`, trained `2026-11-03T13:53:09.472325+00:00`.
- Fitted URL transformer bundled with the model; 2,692 inputs; leading www ignored.
- Frozen balanced threshold: `0.5800396476112477`; model weight 1.0. Rules remain explanatory and feed/reputation overrides remain available.
- Artifact SHA-256: `402e57e96f90fe2a769d15dcee283e8b90fb02e151c06d941997f847b1dfe06a`.
- Benchmark: 84,212 PhreshPhish later-period URLs from 60,767 development-unseen domains.
- Accuracy 92.46%, precision 95.91%, phishing recall 92.49%, F1 94.17%, FPR 7.60%.
- FPR <1% release target remains unmet. Deployment was explicitly requested; `/health` retains `production_validated: false`.
- 42 backend tests and 7 actual local browser tests passed. Bundled inference exactly matches all 84,212 frozen test scores (maximum difference 0.0).
- Local Windows smoke-test server: 218.88 MiB working set; 235.39 MiB peak. This is not a Render memory measurement.
- The GitHub profile `https://github.com/5uhaeb` still scores 63.4/100 and exceeds the frozen 58.0/100 threshold. It remains a known false positive; no domain allowlist or post-test threshold adjustment was added.
- Preserved RF/LightGBM binaries and evaluation entries are legacy artifacts on a different cohort. Improved comparisons remain on the research branch.
- Previous live code for rollback: `911e4140ce8b07e7bc1123fd591298576212ab57`; previous model version `2026-10-29T15:42:17.299185+00:00`.

Deployment status and live verification will be recorded after rollout.
