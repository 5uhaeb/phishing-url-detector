# Model comparison

The current XGBoost artifact is the fixed production baseline. The Random
Forest required by the abstract is preserved and also retrained in the new
phishing-specific comparison. No model is selected by inspecting final scores.

The controlled search uses two Random Forest configurations, two XGBoost
configurations, two LightGBM configurations, a retrained 50-feature XGBoost
ablation and two character TF-IDF/SGD configurations. XGBoost/LightGBM use
validation early stopping. Sigmoid calibration uses separate domains. Character
vocabulary and IDF are fitted on fitting records only. Fixed 25/50/75% character
mixtures are compared with the validation-best member of each tree family.
No stacking model is fitted on in-sample or test predictions.

Additional formulations are (1) legitimate versus combined malicious XGBoost,
(2) legitimate/phishing/malware three-class XGBoost, and (3) separate phishing
and malware classifiers. The latter uses a phishing threshold for phishing
decisions and a separately validation-tuned malicious threshold for the combined
specialist alarm. Each formulation is evaluated on exactly the same final
cohorts; malware scores are not substituted for phishing scores.

Validation considers maximum F1, recall at 1% and 0.5% FPR, and recall at 95%
precision, with raw ML and 90% ML / 10% existing-rule indices. The frozen primary
candidate maximizes validation phishing recall at 1% FPR, then F1, preferring
fewer components and higher model share on ties. Model and hybrid scores are
reported separately; a mixture or hybrid risk index is not claimed calibrated.

## Acceptance gate, declared before final results

There is one preselected candidate, not a search for the best final-test row.
Replacement requires all of:

1. Paired unseen-domain phishing recall improves by at least five percentage
   points, with candidate recall's 95% domain-bootstrap lower bound exceeding
   the baseline upper bound.
2. Paired phishing F1 improves, and the candidate's 95% bootstrap upper bound on
   FPR is at most 1% on reserved legitimate domains.
3. Fresh OpenPhish recall does not regress by over two percentage points.
4. Candidate single-URL p95 latency is at most 50 ms and measured process RSS is
   at most 400 MiB on the recorded local environment.

These are release gates for this experiment, not proof of production safety or
95% metrics. If any fails, keep the current artifact; do not choose another model
or retune thresholds after seeing the final cohort. Dataset limitations remain
even if all gates pass. No live release is claimed without a successful release
and explicit verification.

Measured final tables, uncertainty, timing and the acceptance decision are
generated in [EVALUATION_REPORT.md](EVALUATION_REPORT.md) after the frozen run.
Exact parameters are in the experiment source and serialized frozen estimators;
model/source/data hashes and any pre-test mechanical correction are recorded.


## Measured paired final results

| Model | Accuracy | Precision | Phishing recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| existing_deployed | 83.24% | 90.08% | 55.80% | 68.91% | 3.07% |
| rf_200 | 84.65% | 94.76% | 57.06% | 71.23% | 1.58% |
| xgb_650 | 86.99% | 95.05% | 64.27% | 76.69% | 1.67% |
| lgb_400 | 86.95% | 95.17% | 64.06% | 76.57% | 1.62% |
| char_1e-05 | 89.31% | 96.00% | 70.86% | 81.53% | 1.47% |
| binary_malicious | 87.14% | 95.15% | 64.68% | 77.01% | 1.64% |
| three_class | 87.28% | 94.93% | 65.28% | 77.36% | 1.74% |
| separate_specialists | 86.99% | 95.05% | 64.27% | 76.69% | 1.67% |
| xgb_character_0.75 | 91.09% | 96.08% | 76.34% | 85.08% | 1.55% |

All rows use the same 48,406 URLs: 16,117 fresh-feed phishing and 32,289 reserved legitimate URLs. Family configurations and weights were chosen on validation. The last ensemble is the single preselected primary candidate; other final rows are comparisons, not alternative release selections.

**Acceptance: failed.** Candidate FPR is 1.55%; its 95% upper bound is 1.74%. The current XGBoost artifact is retained. No threshold is retuned after this result.

`rf_200` is Random Forest; `xgb_650` is XGBoost; `lgb_400` is LightGBM; `char_1e-05` is character TF-IDF/SGD. Numeric suffixes are configured maximum tree counts, not scores. Early stopping can use fewer boosting iterations. `xgb_character_0.75` mixes 75% character and 25% XGBoost scores.

## Retrained feature ablation

| Model | Accuracy | Precision | Phishing recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| xgb_450 | 78.60% | 97.29% | 50.08% | 66.12% | 1.00% |
| xgb_original50 | 76.89% | 97.05% | 45.98% | 62.40% | 1.00% |

The original 50-feature and enhanced 64-feature XGBoost variants share the same configured hyperparameters and seed. Extra features improve validation recall at the fixed FPR policy; they were not chosen using final-test scores. This does not establish the causal importance of individual correlated features.
