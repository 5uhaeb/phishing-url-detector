# Phase 1 verification

Verified locally on 29 October 2026 (India time), using the pinned Python environment.

- Full mixed-source experiment: 431,701 usable URLs; 86,976 test URLs across 60,410 domains.
- All three families use identical domain-disjoint partitions. Exact indices are retained with the run artifacts.
- XGBoost selected on validation before test scoring. The unchanged previous model reproduces its original test confusion matrix on the same partition.
- Backend: `python -m unittest -v` — 54 passed.
- Browser: `npm test` — 7 passed, including four viewport widths and WCAG A/AA checks.
- Frontend syntax and build: passed. Python dependency consistency: passed.
- All three model families: calibration, export and prediction parity tests passed.
- Release manifest and file checksums: verified. Offline release prediction, health, comparison API and strict JSON report checks passed.
- Docker image and live deployment: unverified; local Docker engine was unavailable. Live push and redeployment status is recorded in `deployment-status.md`.
- Independent future-time mixed-class validation: not supplied. The historical benchmark does not establish production accuracy.

Run: `20261029T154217299203Z`.

Release ZIP: `release/current.zip` (2,101,676 bytes).

Archive SHA256: `2fcdcca7a890efb46c1ecf0e947b11f04c3c4e19689ad015415a7ceb71ed9ced`.

See [comparison.md](comparison.md) for measured results and [DEPLOYMENT.md](../DEPLOYMENT.md) for installation and rollback.

Phase 2 redesign is deferred at the user's request.
