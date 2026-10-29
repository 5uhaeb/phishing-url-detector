# Phase 1 model comparison

Selected on validation: **XGBoost**. Test results never select the winner.

| Model | Accuracy | Precision | Recall | F1 | FPR | ROC AUC |
|---|---:|---:|---:|---:|---:|---:|
| Previous hybrid | 84.47% | 98.26% | 65.47% | 78.58% | 0.90% | — |
| Random Forest | 84.66% | 98.17% | 65.98% | 78.92% | 0.95% | 0.9275 |
| XGBoost | 84.98% | 98.20% | 66.72% | 79.45% | 0.94% | 0.9317 |
| LightGBM | 84.78% | 98.18% | 66.26% | 79.12% | 0.94% | 0.9313 |

Previous hybrid: accuracy 84.47%, recall 65.47%, FPR 0.90%.
Historical baseline figures are directly comparable only when dataset and split fingerprints match.

Baseline audit: the unchanged previous model reproduces its original confusion matrix on this exact test partition.

Champion changes: accuracy +0.51, recall +1.24, F1 +0.87, FPR +0.05 percentage points.

| Model | Median analysis (ms) | p95 analysis (ms) |
|---|---:|---:|
| Random Forest | 16.36 | 18.91 |
| XGBoost | 1.53 | 1.93 |
| LightGBM | 1.33 | 1.54 |

All models use the same raw URL features, data, disjoint domain partitions, calibration method and validation FPR target.
Two fixed parameter settings per family; no test-driven parameter or threshold changes.
The historical split was used in earlier development. This is a regression comparison, not a new independent prospective benchmark.
Validation targets do not guarantee test or future false-positive rates. Production requires a future-time mixed-class audit.
