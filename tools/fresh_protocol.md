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
