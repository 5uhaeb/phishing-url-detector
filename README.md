# LinkGuard — Phishing URL Detection

## Concept

LinkGuard detects suspicious phishing URLs: deceptive links that impersonate trusted services to steal passwords, payment details or other sensitive information. It helps users inspect links before opening them, using machine learning, URL rules and optional threat-feed matches. Submitted websites are never opened; low detected risk does not guarantee safety.

## Previous and new scores

Both tables use the **same 84,212 reserved URLs from 60,767 unseen domains**, using [PhreshPhish](https://huggingface.co/datasets/phreshphish/phreshphish). No UCI data or leading `www` signal was used; tuning used validation data only.

### Before development — fresh baselines

| Model | Accuracy | Precision | Phishing recall | F1 | False-positive rate |
|---|---:|---:|---:|---:|---:|
| Random Forest | 79.68% | 90.48% | 77.26% | 83.35% | 15.66% |
| XGBoost | 79.32% | 91.42% | 75.70% | 82.82% | 13.69% |
| LightGBM | 80.47% | 91.55% | 77.48% | 83.93% | 13.78% |

### After development — retrained models

| Model | Accuracy | Precision | Phishing recall | F1 | False-positive rate |
|---|---:|---:|---:|---:|---:|
| Random Forest | **90.37%** | **94.86%** | **90.27%** | **92.51%** | **9.43%** |
| XGBoost | **92.46%** | **95.91%** | **92.49%** | **94.17%** | **7.60%** |
| LightGBM | **92.28%** | **95.88%** | **92.24%** | **94.03%** | **7.64%** |

All four measured metrics exceed 90%; **false positives remain above the 1% target**. Random Forest's confidence intervals cross 90%. These benchmark scores use 65.8% phishing prevalence, not ordinary browsing prevalence.

[Full report](reports/fresh-2026-11-03/README.md) · [CSV](reports/fresh-2026-11-03/scores.csv) · [Graph](reports/fresh-2026-11-03/comparison.png) · [PDF](reports/fresh-2026-11-03/comparison.pdf)

## Models

- **Random Forest:** averages independent decision trees. It is a useful baseline but had lower recall and more false positives here.
- **XGBoost:** builds trees sequentially to correct errors, with regularization to control complexity. It narrowly led test accuracy, precision, recall and F1.
- **LightGBM:** uses histogram-based, leaf-wise tree growth for efficient training. Its scores were close to XGBoost.

**Why XGBoost led:** its error correction and regularization suit these URL features. The result reflects features, training and threshold choices together; it does not prove universal superiority.

**Further work:** reduce false alarms, add newer and more diverse data, and validate on independent campaigns and realistic phishing prevalence.

**Research ensemble:** an earlier experiment combined XGBoost with a character-pattern classifier. It used a different test cohort and missed its false-positive release target. It is not deployed.

## Project and launch

**Live app:** https://phishing-url-detector-xi.vercel.app

The app and launcher use the existing shipped model. **The new scores above describe research models saved locally; their binaries are not uploaded or deployed.** This branch contains the experiment code and reports.

### Quick start

Install **Python 3.13**, extract the source ZIP or download this branch, then double-click **`START_LINKGUARD.cmd`** on Windows. First setup needs internet. The launcher opens the browser; close its console to stop.

### Manual commands — PowerShell, from the project root

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe launcher.py --use-current-env
```

Add `--offline` to skip feed refresh and external reputation checks. Cached feed matches can still apply until expiry.

For separate development servers, run these in **two terminals** after setup:

```powershell
# Terminal 1: backend
.\.venv\Scripts\python.exe backend\main.py
# Terminal 2: frontend; open http://127.0.0.1:5187
.\.venv\Scripts\python.exe frontend\dev_server.py
```

### Files to run

| File | Purpose |
|---|---|
| `START_LINKGUARD.cmd` / `launcher.py` | Complete local app |
| `backend/main.py` | Backend API |
| `frontend/dev_server.py` | Separate frontend server |
| `backend/train.py` | Train all three model families |
| `tools/fresh_benchmark.py` | Fresh research experiment |
| `tools/fresh_report.py` | Generate research reports |

Run backend tests:

```powershell
cd backend
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

**46 tests passed.** Dataset preparation, training commands and dependencies are in the [experiment protocol](tools/fresh_protocol.md). Training saves separate artifacts and does not replace the deployed model.
