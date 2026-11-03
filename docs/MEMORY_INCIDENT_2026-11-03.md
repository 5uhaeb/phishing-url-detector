# Render memory incident — 3 November 2026

Render reported an OOM restart for `linkguard-api`. Metrics recorded roughly
510 MiB before restart; logs show repeated `python main.py` startup events.
The configured large Phishing.Database refresh was the leading allocation path:
the old importer retained download chunks, joined bytes, decoded text, a line
list, and a Python dictionary of every URL digest at once.

## Correction

`backend/feeds.py` now streams at most 64 KiB per download chunk to a temporary
file and hashes bytes incrementally. Parsing reads bounded lines, stores distinct
digests in a disk-backed SQLite TEMP table and uses 512-row insertion batches.
SQLite main/temp caches are set to 1 MiB and mapping is disabled for this import.
Only a fully validated replacement updates the source's indicator rows and
metadata in one transaction. Failed downloads, invalid content and SQL failures
retain previous evidence. Temporary files are cleaned up automatically.

The existing 100 MiB download bound is retained; a new 32 KiB line bound prevents
an oversized single line from becoming another large allocation. Duplicate-heavy
valid feeds are accepted using the valid-line ratio, while SQL deduplicates them.
Model artifacts, thresholds, URL matching semantics and the service plan are
unchanged. `main.py` now logs refresh start, progress, completion and failures
without logging user-submitted URLs.

## Measured local reproduction

Each fresh process loaded the same serving XGBoost artifact. These are sampled
Windows RSS measurements, not measurements of Render's Linux container.

| Import | Input size | Distinct URLs | Additional peak RSS |
|---|---:|---:|---:|
| Previous implementation, capped sample | 8 MiB | 78,941 | 39.72 MiB |
| Streamed implementation, same sample | 8 MiB | 78,941 | 3.25 MiB |
| Streamed implementation, complete snapshot | 62.77 MiB | 788,119 | 3.36 MiB |

The complete new import's total process peak was **190.08 MiB**, including the
loaded model. This demonstrates bounded import allocations as input size grows;
it does not guarantee a universal production memory maximum.

Reproduce with `backend/benchmark_feed_memory.py --snapshot <local-feed.txt>`;
optional `psutil` comes from `requirements-research.txt`. Legacy comparison is
restricted to at most 8 MiB rather than deliberately exhausting memory.

All **50 backend tests passed**, including a large-feed allocation regression,
duplicate/chunk/BOM handling, oversized lines/bodies, invalid UTF-8, interrupted
downloads, and rollback after a database replacement failure. ML score changes
are not claimed: this is an ingestion/resource fix, not retraining.

Automatic refresh was temporarily paused and the existing build redeployed to
stabilize service while preparing this fix. The final release must restore
`REFRESH_FEEDS=1` and verify one complete production refresh and memory metrics;
the verification outcome is recorded below after deployment.
