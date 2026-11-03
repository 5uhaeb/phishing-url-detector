# Fresh three-family experiment — 3 November 2026

The starting point is GitHub main commit 56c2703. Earlier evaluations, tuning
choices, and fitted research models are not inputs. Production models and the
client export remain unchanged. Results here are experiments, not deployment.

1. Download URL/label/date metadata from a pinned revision of the official
   PhreshPhish dataset (CC BY 4.0). Never fetch the listed sites or HTML bodies.
2. Validate binary phish/benign labels and URLs with the current parser. Remove
   normalized duplicates and contradictory URLs, treating conventional `www.`
   spellings as identical. Audit class-specific collection patterns.
3. Keep the publisher's test split sealed. Exclude all test registrable domains
   present in the publisher's training split. This is a stricter filtered test,
   not a claim to reproduce the publisher's complete official benchmark.
4. Split only the publisher's training data into 70% fit, 15% calibration, 15%
   validation by registrable domain (fixed seeds 20261103 and 20261104). No URL
   random splitting, majority-class downsampling, or filtering hard test rows.
5. Freshly fit all three current `train.make_models` configurations using the
   shared 32 features. Calibrate on calibration only, freeze validation-only
   weakest-of-four and low-FPR operating points. These are fresh code baselines,
   not predictions recycled from an older artifact.
6. Train all three families with expanded lexical URL statistics and train-only
   character/word features, including train-only TF-IDF/SVD text factors as a
   second feature representation (not a stacked classifier). Tune depth/regularization/number of trees on validation
   only. Every feature must be invariant to adding/removing leading `www.`.
   No external blacklist, source/date/label/HTML/brand annotation features.
7. Select the best candidate per family by the minimum of accuracy, precision,
   recall and F1; break ties by lower FPR then average precision. Also select a
   separate conservative operating point maximizing validation recall subject
   to <=0.8% validation FPR, providing margin for the desired <1% test FPR.
8. If early validation misses the target, improve features/models on the same
   development splits. Keep the final test sealed until all selections freeze.
   Record every tested configuration and outcome; do not hide failed candidates.
9. Evaluate frozen baselines and winners exactly once on the same sealed test.
   Report accuracy, precision, recall, F1, FPR, ROC/PR AUC, confusion matrices,
   group-bootstrap confidence intervals, and the four-metric >=90% / FPR<1%
   target verdict. Publish failures honestly. No guarantee of a particular score.
10. Keep CSV/report, hashes, partitions, code and selected research artifacts.
    Never replace the live model without a separately reviewed release decision.

This controls the explicit www shortcut and domain leakage; it cannot prove the
absence of every source bias or guarantee future performance. Benchmark precision
depends on phishing prevalence; report a projected 1% prevalence precision too.

Pre-test protocol clarification: the first baseline fits recorded maximum-F1
thresholds. Before any final-test access, rescore their saved validation predictions
with the same weakest-of-four threshold objective as the improved models. Preserve
the initial threshold as a diagnostic. This avoids confusing threshold selection
with gains from retraining; fitted baseline models themselves do not change.

## Reproduction

Use a new private output folder for each complete experiment. Install the backend
dependencies and `tools/requirements-fresh.txt`. Set `OMP_NUM_THREADS` and
`OPENBLAS_NUM_THREADS` to fit available CPU capacity when running stages together.

```text
python tools/fresh_data.py --output PRIVATE/metadata
python tools/fresh_benchmark.py prepare --metadata PRIVATE/metadata --output PRIVATE/run
python tools/fresh_benchmark.py baseline --output PRIVATE/run --jobs 8
python tools/fresh_benchmark.py lexical --output PRIVATE/run --jobs 8
python tools/fresh_benchmark.py latent --output PRIVATE/run --jobs 4
python tools/fresh_benchmark.py freeze --output PRIVATE/run
python tools/fresh_benchmark.py final --output PRIVATE/run
python tools/fresh_report.py --experiment PRIVATE/run --output reports/fresh-2026-11-03
```

The `features` and `latent-features` stages optionally precompute development
matrices. `deep` is an optional additional tuning round; its candidates are included
only when actually fitted and logged before freeze. Never run tuning after freeze.
Charts require the separate optional `tools/requirements.txt` dependencies.

Development-only follow-up: the first lexical RF reached 89.06% validation recall
at the 0.8% FPR policy. Before freezing/opening test predictions, add a `domain`
round for all three families: inverse-square-root training-domain frequency,
normalized to equal total class weight. This reduces domination by prolific
domains; calibration and validation distributions remain unweighted. Its command
is `python tools/fresh_benchmark.py domain --output PRIVATE/run --jobs 8`, before
the freeze stage. The attempted candidates are retained regardless of outcome.
