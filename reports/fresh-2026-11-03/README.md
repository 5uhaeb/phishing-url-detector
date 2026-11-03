# Fresh LinkGuard experiment — 3 November 2026

**Research results; the deployed application and client ZIP are unchanged.**

**Final verdict: 3/3 retrained families meet all four 90% targets at their balanced policies; 0/3 meet all four plus FPR <1% at their conservative policies.**

These are measured point estimates. Random Forest is borderline: its accuracy and recall 95% confidence intervals extend below 90%. The false-positive release target is unmet; these results do not justify automatic production promotion.

Data: [official PhreshPhish](https://huggingface.co/datasets/phreshphish/phreshphish), revision `eca603e0ecd4f698f8d4d226c088659e72681239`.
Final test: **84,212 URLs**, **60,767 domains**, 55,442 phishing / 28,770 benign. Collection dates 2025-09-08 through 2025-12-16.

Training, calibration, validation and test registrable domains are disjoint. Publisher test rows on training-corpus domains were excluded before any fitting. No UCI data, historical scores, pretrained research models, live feeds or reputation labels were used. All three 32-feature baselines were freshly trained from current GitHub code. Text vocabularies/selection were learned on fit rows only; thresholds and models were frozen on validation.

Scores apply to URLs accepted by the current product parser (HTTP(S), at most 4,096 characters, valid host/encoding). Parser rejections are counted in `evaluation.json`, not counted as correct classifications. Duplicates and label conflicts are removed before fitting. Feature candidates include train-only character/word counts and train-only TF-IDF/SVD factors; no other classifier supplies predictions as features.

The source contains a www imbalance; every input feature ignores conventional leading www. Numeric and text invariance was checked on 499 corpus pairs plus unit fixtures. This neutralizes that explicit shortcut, without claiming absence of all source bias.

| Model | Version | Policy | Accuracy | Precision | Recall | F1 | FPR | All four ≥90% |
|---|---|---|---:|---:|---:|---:|---:|---|
| Random Forest | Fresh baseline | balanced | 79.68% | 90.48% | 77.26% | 83.35% | 15.66% | FAIL |
| Random Forest | Fresh baseline | conservative | 63.30% | 98.21% | 45.07% | 61.79% | 1.58% | FAIL |
| Random Forest | Retrained | balanced | 90.37% | 94.86% | 90.27% | 92.51% | 9.43% | PASS |
| Random Forest | Retrained | conservative | 80.07% | 98.51% | 70.80% | 82.39% | 2.06% | FAIL |
| XGBoost | Fresh baseline | balanced | 79.32% | 91.42% | 75.70% | 82.82% | 13.69% | FAIL |
| XGBoost | Fresh baseline | conservative | 65.83% | 98.99% | 48.59% | 65.18% | 0.96% | FAIL |
| XGBoost | Retrained | balanced | 92.46% | 95.91% | 92.49% | 94.17% | 7.60% | PASS |
| XGBoost | Retrained | conservative | 89.08% | 98.77% | 84.46% | 91.06% | 2.03% | FAIL |
| LightGBM | Fresh baseline | balanced | 80.47% | 91.55% | 77.48% | 83.93% | 13.78% | FAIL |
| LightGBM | Fresh baseline | conservative | 67.98% | 98.75% | 52.02% | 68.14% | 1.27% | FAIL |
| LightGBM | Retrained | balanced | 92.28% | 95.88% | 92.24% | 94.03% | 7.64% | PASS |
| LightGBM | Retrained | conservative | 89.84% | 98.77% | 85.63% | 91.73% | 2.05% | FAIL |

The balanced policy maximizes the weakest of the four requested validation metrics for both baselines and retrained candidates. The conservative policy targets at most 0.8% validation FPR, with margin for the desired <1% test rate. A test target miss is a failed gate, not a reason to retune on the final test.

| Retrained model / policy | Recall 95% CI | FPR 95% CI | Projected precision at 1% phishing |
|---|---:|---:|---:|
| Random Forest / balanced | 89.54%–90.95% | 9.09%–9.77% | 8.81% |
| Random Forest / conservative | 69.38%–72.14% | 1.90%–2.24% | 25.73% |
| XGBoost / balanced | 91.84%–93.10% | 7.28%–7.93% | 10.95% |
| XGBoost / conservative | 83.54%–85.31% | 1.85%–2.22% | 29.56% |
| LightGBM / balanced | 91.60%–92.85% | 7.31%–7.94% | 10.87% |
| LightGBM / conservative | 84.70%–86.47% | 1.88%–2.23% | 29.67% |

Confidence intervals use 1,000 registrable-domain bootstrap resamples. The 1% precision is a mathematical projection from measured recall/FPR, not an observed result. The filtered test has an elevated phishing prevalence, so observed precision must not be presented as general internet precision. This evaluates URL-only phishing classification; it cannot establish performance on future campaigns or arbitrary sources.

Every attempted development candidate is listed in `validation_candidates.csv`. Exact confusion counts, frozen thresholds, model SHA-256 hashes, and provenance appear in `evaluation.json` and `scores.csv`. Selected fitted research artifacts and raw metadata remain outside the minimized production repository.

Reproduce using `tools/fresh_data.py`, `tools/fresh_benchmark.py` and `tools/fresh_protocol.md`. Install `backend/requirements.txt`, `tools/requirements-fresh.txt`; install `tools/requirements.txt` only for charts. Source data attribution: Dalton et al., [PhreshPhish](https://arxiv.org/abs/2507.10854), CC BY 4.0.
