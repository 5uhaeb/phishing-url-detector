# Repository audit

Inspected the backend, preserved model manifests, research scripts, frontend,
browser/API/provider/training tests, dependencies, deployment settings and the
supplied capstone abstract on 1 November 2026. No destinations in the datasets
are fetched. Production artifacts are preserved for rollback.

| Finding | Evidence and correction |
|---|---|
| Malware recall was easy to mistake for phishing recall | `research_audit.load_records` records Kaggle `source`; URLhaus positives are malware. Historical external scores mostly measure these 24,102 URLs, compared with just 296 valid OpenPhish URLs. New experiments keep benign/phishing/malware types and never use source as a feature. |
| Dataset collection style is predictive | UCI benign URLs disproportionately use `www` and root paths. `detector.extract_features` already ignores conventional `www` for measurements; this removes one shortcut but cannot repair missing benign paths or phishing campaigns. Historical ealvaradob-only testing still has 13–15% FPR at balanced thresholds. |
| Conservative threshold suppresses phishing recall | The frozen XGBoost hybrid threshold is 0.8407650642509457 with 90% model weight. Historical OpenPhish-only unseen-domain recall is 38.87%. Thresholds must be compared on validation at 0.5%/1% FPR, maximum F1 and constrained precision; lowering one on a test set would be leakage. |
| Display rounding changed final decisions | `detector.analyze` rounded scores before `reputation.combine_evidence` compared them again. Live-equivalent Kaggle scoring changed 15 decisions. Fixed by carrying the full-precision boolean decision and review flag; display fields remain compatible. Regression test: `tests/test_decision_policy.py`. |
| Fragments and userinfo are underrepresented in research text | Production 32-feature extraction strips fragments; the older character view also omitted userinfo. `research_features.py` adds a versioned research-only text view and structural measurements that preserve them. Existing models retain their original schema. Value must be demonstrated on validation. |
| Rules had no structured evidence | `evaluate_rules` returned prose and a summed score. Added `rule_evidence`: stable identifiers, severity, observed feature, configured weight, capped contribution and contribution to final index. Existing weights and model parameters are unchanged; correlated URL warnings remain weak evidence rather than independent probabilities. |
| Earlier final tests are now historical | Kaggle and the prior PhreshPhish final test have informed discussion. They cannot be advertised as untouched tests for a new model. Fresh OpenPhish/PhishTank snapshots are reserved before new candidate selection; date/domain exclusions are reported. |
| Runtime threat intelligence is unavailable | Live `/api/status` reported missing feed snapshots and no Web Risk key. Neither a missing feed nor an absent match establishes safety. Existing exact-match/TTL/consent/timeout behavior is preserved. Feed-derived labels are excluded from feed lookup when measuring independent detection. |
| Deployment layout differs from the live historical service | Local `main.py` uses `backend/` and an evaluation report; the live service returns a historical nested report. Compare model run ID, feature values, thresholds and sampled predictions rather than assuming identical endpoint JSON. No unverified deployment is claimed. |

The Random Forest baseline, XGBoost and LightGBM remain selectable through
`MODEL_NAME`. The API validates model checksums and schemas. Existing URL parsing
uses IDNA, bundled PSL including private suffixes, IP/port validation and no
network resolution. CORS, request limits, consent gating, safe fixed-destination
Web Risk calls and DOM `textContent` rendering already address their intended
boundaries; the framework and frontend do not need replacing.

Remaining research limits include source/label confounding, no guarantee of
campaign-disjoint data, no broad recent independent benign ground truth, and
feed reports that may contain errors. Fitting on current feed labels and then
reporting exact matches from that same feed is circular, not model improvement.
