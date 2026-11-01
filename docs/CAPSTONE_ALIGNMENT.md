# Capstone alignment

The supplied abstract is **A Lightweight Hybrid Phishing URL Detection System
Using Cybersecurity Rules and Random Forest with Web-Based Deployment**.
The implementation retains its architecture and educational scope.

| Abstract requirement | Implementation and evidence |
|---|---|
| Submit a URL through a web interface | Existing mobile-accessible HTML/CSS/JS frontend, `/api/predict` Flask route. Browser tests cover 320, 375, 768 and 1440 pixels, accessibility, errors, downloads and untrusted text. |
| URL/domain/subdomain/special-character/hyphen/digit/keyword/HTTPS features | `detector.extract_features`, existing 32-feature production schema; experimental additions are isolated in `research_features.py`. No website is visited. |
| Cybersecurity rule module | `detector.evaluate_rules` and `rule_evidence`; warning identifiers, observed evidence and bounded contributions accompany the existing indicators. Rules are warning signals, not proof of phishing. |
| Random Forest classifier | Preserved `backend/models/random_forest.joblib`, reproducible `train.py` baseline and two tuned phishing-specific research configurations. Run `MODEL_NAME=random_forest` to use the baseline locally. It is not falsely described as the active XGBoost model. |
| Hybrid prediction, risk and explanations | ML/rule risk index, full-precision local decision, review state and optional fresh exact feed evidence. The hybrid index is not a calibrated probability. |
| Accuracy, precision, recall, F1 and confusion matrix | Frozen validation/test protocol with typed labels, separate phishing/malware/source cohorts, domain bootstrap intervals and explicit test limitations. |
| Training time and prediction latency | Per-model timing, compact-candidate memory/load/latency measurement and local full-API timing. Historical scores are distinguished from new measurements. |
| Web deployment | Existing Vercel frontend and Render backend configuration retained. A locally tested patch is not described as deployed unless a release actually succeeds and is verified. |

XGBoost is the existing production classifier; Random Forest remains the
abstract-required baseline. LightGBM, character models and ensembles are
documented extensions motivated by weak unseen-domain phishing recall. They
do not replace the required baseline or turn the capstone into a browser crawler,
microservice platform or screenshot detector. Any future page-content method
would require a separately evaluated, safely isolated extension.

95% metrics are research aspirations. A high aggregate malware accuracy does
not establish phishing detection, and a threshold that flags many legitimate
URLs is not an accepted solution. Production model replacement depends on the
frozen candidate's independent phishing results and false-positive behavior,
not the headline accuracy. Previous model artifacts remain available for rollback.
