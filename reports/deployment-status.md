# Phase 1 deployment

Deployment requested on 29 October 2026 (India time).

- GitHub: private repository `5uhaeb/phishing-url-detector`, production branch `main`.
- Vercel: existing `phishing-url-detector` project; https://phishing-url-detector-xi.vercel.app.
- Render: existing `linkguard-api` service; https://linkguard-api-5m93.onrender.com.
- Bundled model: XGBoost, run `20261029T154217299203Z`.
- Model release SHA256: `2fcdcca7a890efb46c1ecf0e947b11f04c3c4e19689ad015415a7ceb71ed9ced`.
- Local verification before deployment: 54 backend tests passed; 7 browser tests passed.

The build installs the checksum-verified model from the private repository. Training is excluded from deployment. Deployment progress and live validation follow the production push.

The Actions workflow is retained as `ci/quality-checks.workflow.yml`; activating it requires GitHub workflow-write permission. Local release checks have passed.
