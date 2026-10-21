"""Train from UCI raw URLs; evaluate on domains unseen during training."""

import argparse
import hashlib
import io
import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from urllib.request import urlopen
from zipfile import ZipFile

import joblib
import numpy as np
import pandas as pd
import sklearn
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import (accuracy_score, confusion_matrix, precision_recall_fscore_support,
                             brier_score_loss, roc_auc_score, average_precision_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from detector import FEATURE_NAMES, analyze, evaluate_rules, extract_features, hybrid_score

ROOT = Path(__file__).resolve().parent
DATA_URL = 'https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip'
DATA_FILE = ROOT / 'data' / 'PhiUSIIL_Phishing_URL_Dataset.csv'
SEED = 42
ADDITIONAL_FILE = ROOT / 'data' / 'additional-urls.json'
ADDITIONAL_URL = 'https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/urls.json'


def download_additional():
    ADDITIONAL_FILE.parent.mkdir(exist_ok=True)
    temporary = ADDITIONAL_FILE.with_suffix('.tmp')
    print('Downloading supplementary raw URL dataset (~73 MB)...', flush=True)
    with requests.get(ADDITIONAL_URL, timeout=(5, 60), stream=True) as response:
        response.raise_for_status()
        total = 0
        with temporary.open('wb') as output:
            for chunk in response.iter_content(1024 * 1024):
                total += len(chunk)
                if total > 100_000_000:
                    raise ValueError('Supplementary dataset exceeds size limit.')
                output.write(chunk)
    temporary.replace(ADDITIONAL_FILE)


def download():
    DATA_FILE.parent.mkdir(exist_ok=True)
    print('Downloading UCI PhiUSIIL dataset (about 15 MB)...', flush=True)
    with urlopen(DATA_URL, timeout=120) as response:
        archive = response.read(50 * 1024 * 1024)
    with ZipFile(io.BytesIO(archive)) as zipped:
        names = [name for name in zipped.namelist() if name.endswith(DATA_FILE.name)]
        if len(names) != 1:
            raise ValueError('Dataset archive did not contain the expected CSV.')
        DATA_FILE.write_bytes(zipped.read(names[0]))


def metrics(labels, predictions):
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average='binary', zero_division=0)
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return dict(accuracy=float(accuracy_score(labels, predictions)), precision=float(precision),
                recall=float(recall), f1=float(f1),
                false_positive_rate=float(fp / max(1, tn + fp)),
                missed_phishing_rate=float(fn / max(1, tp + fn)),
                confusion_matrix=matrix.tolist())


def tune_threshold(labels, scores, max_fpr=.01):
    candidates = np.append(np.linspace(.01, 1, 100), 1.001)
    measured = [(float(t), metrics(labels, scores >= t)) for t in candidates]
    feasible = [(t, m) for t, m in measured if m['false_positive_rate'] <= max_fpr]
    return max(feasible, key=lambda pair: (pair[1]['recall'], pair[1]['precision'], -abs(pair[0] - .5)))[0]


def train(args):
    started = perf_counter()
    if args.download and not DATA_FILE.exists():
        download()
    path = args.csv or DATA_FILE
    if not path.exists():
        raise ValueError('Dataset missing. Run python train.py --download first.')
    frame = pd.read_csv(path, usecols=['URL', 'label'])[['URL', 'label']].dropna()
    frame['source'] = 'UCI PhiUSIIL'
    raw_count = len(frame)
    provenance = [dict(name='UCI PhiUSIIL', rows=len(frame), source=DATA_URL, license='CC BY 4.0',
                       sha256=hashlib.sha256(path.read_bytes()).hexdigest())]
    if not set(frame.label.unique()).issubset({0, 1}) or frame.label.nunique() != 2:
        raise ValueError('Expected UCI labels: 0=phishing and 1=legitimate, with both classes.')
    if not args.no_additional_data:
        extra_path = args.additional_data
        if not extra_path.exists() and args.download and extra_path == ADDITIONAL_FILE:
            download_additional()
        if not extra_path.exists():
            raise ValueError('Supplementary dataset missing. Use --download, or explicitly --no-additional-data for the biased UCI-only baseline.')
        extra = pd.read_json(extra_path)[['text', 'label']].dropna()
        if not set(extra.label.unique()).issubset({0, 1}) or extra.label.nunique() != 2:
            raise ValueError('Supplementary labels must be 1=phishing, 0=legitimate.')
        extra_raw_count = len(extra)
        if args.additional_limit and len(extra) > args.additional_limit:
            extra, _ = train_test_split(extra, train_size=args.additional_limit,
                                        stratify=extra.label, random_state=SEED)
        # Original corpus includes bare URLs. Apply the same documented scheme
        # convention to both classes, never only to benign samples.
        missing_scheme = ~extra.text.str.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
        extra.loc[missing_scheme, 'text'] = 'https://' + extra.loc[missing_scheme, 'text']
        extra = extra.rename(columns={'text': 'URL'})
        extra['label'] = 1 - extra['label'].astype(int)  # Match UCI convention until extraction.
        extra['source'] = 'ealvaradob raw URLs'
        provenance.append(dict(name='ealvaradob raw URLs', source=ADDITIONAL_URL,
            card='https://huggingface.co/datasets/ealvaradob/phishing-dataset',
            license='Apache-2.0 as declared by dataset publisher; underlying sources listed on dataset card',
            raw_rows=extra_raw_count, sampled_rows=len(extra), inferred_https_schemes=int(missing_scheme.sum()),
            sha256=hashlib.sha256(extra_path.read_bytes()).hexdigest()))
        frame = pd.concat([frame, extra], ignore_index=True)
        raw_count = len(frame)
    # Remove contradictory exact labels, then sample without using test labels to tune anything.
    conflicts = frame.groupby('URL').label.nunique()
    frame = frame[~frame.URL.isin(conflicts[conflicts > 1].index)].drop_duplicates('URL')
    if args.max_rows and len(frame) > args.max_rows:
        frame, _ = train_test_split(frame, train_size=args.max_rows,
                                    stratify=frame.label, random_state=SEED)
    print(f'Extracting text features from {len(frame):,} URLs...', flush=True)
    records = []
    invalid = 0
    for url, label, source in frame[['URL', 'label', 'source']].itertuples(index=False, name=None):
        try:
            normalized, features, group = extract_features(url)
        except ValueError:
            invalid += 1
            continue
        records.append(dict(url=normalized, group=group, target=1 - int(label), source=source, **features))
    clean = pd.DataFrame(records)
    if clean.empty:
        raise ValueError('No valid URLs found.')
    normalized_conflicts = clean.groupby('url').target.nunique()
    clean = clean[~clean.url.isin(normalized_conflicts[normalized_conflicts > 1].index)]
    clean = clean.drop_duplicates('url').reset_index(drop=True)
    x = clean[list(FEATURE_NAMES)].to_numpy(dtype=float)
    y = clean.target.to_numpy()
    groups = clean.group.to_numpy()
    trainval, test = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED)
                          .split(x, y, groups))
    inner_train, inner_validation = next(GroupShuffleSplit(n_splits=1, test_size=.25,
                                          random_state=SEED + 1).split(
                                              x[trainval], y[trainval], groups[trainval]))
    training, development = trainval[inner_train], trainval[inner_validation]
    cal, policy = next(GroupShuffleSplit(n_splits=1, test_size=.5, random_state=SEED + 2)
                       .split(x[development], y[development], groups[development]))
    calibration, validation = development[cal], development[policy]
    partitions = {'training': training, 'calibration': calibration, 'validation': validation, 'test': test}
    for name, indices in partitions.items():
        if len(np.unique(y[indices])) != 2:
            raise ValueError(f'{name} partition needs both classes. Use a larger dataset.')
    from itertools import combinations
    assert all(not set(groups[a]) & set(groups[b]) for a, b in combinations(partitions.values(), 2))
    model = RandomForestClassifier(n_estimators=240, max_depth=24, min_samples_leaf=2,
                                   class_weight='balanced', n_jobs=-1, random_state=SEED)
    print('Training Random Forest...', flush=True)
    fitting = perf_counter()
    model.fit(x[training], y[training])
    training_seconds = perf_counter() - fitting
    # Single-row inference uses one worker: avoid thread startup dominating latency.
    model.n_jobs = 1
    calibrating = perf_counter()
    model = CalibratedClassifierCV(FrozenEstimator(model), method='sigmoid')
    model.fit(x[calibration], y[calibration])
    calibration_seconds = perf_counter() - calibrating
    rule_scores = np.array([evaluate_rules(dict(zip(FEATURE_NAMES, row)))[0] for row in x])
    phishing_column = list(model.classes_).index(1)
    validation_probability = model.predict_proba(x[validation])[:, phishing_column]
    rule_threshold = tune_threshold(y[validation], rule_scores[validation], args.max_fpr)
    rf_threshold = tune_threshold(y[validation], validation_probability, args.max_fpr)
    threshold = tune_threshold(y[validation], hybrid_score(validation_probability, rule_scores[validation]), args.max_fpr)
    inference_start = perf_counter()
    test_probability = model.predict_proba(x[test])[:, phishing_column]
    batch_ms_per_url = (perf_counter() - inference_start) * 1000 / len(test)
    artifact = dict(model=model, features=list(FEATURE_NAMES), threshold=threshold,
                    rf_threshold=rf_threshold, calibrated=True,
                    development_group_hashes={hashlib.sha256(g.encode()).hexdigest() for g in groups},
                    trained_at=datetime.now(timezone.utc).isoformat(), sklearn_version=sklearn.__version__)
    # Warm up, then measure complete single-URL analysis separately from batch inference.
    analyze(clean.url.iloc[test[0]], artifact)
    timings = []
    for url in clean.url.iloc[test[:100]]:
        tick = perf_counter()
        analyze(url, artifact)
        timings.append((perf_counter() - tick) * 1000)
    report = dict(
        dataset=dict(name='Multi-source raw URLs' if len(provenance) > 1 else 'UCI PhiUSIIL',
                     sources=provenance, source=DATA_URL, license='See individual dataset sources',
                     authors='Arvind Prasad and Shalini Chandra (2024)',
                     sha256=hashlib.sha256(path.read_bytes()).hexdigest(), raw_rows=raw_count,
                     sample_limit=args.max_rows, invalid_sampled_urls=invalid, usable_rows=len(clean)),
        methodology=dict(seed=SEED, positive_class='phishing (1)',
                         source_labels='UCI 0=phishing, 1=legitimate; inverted internally',
                         split='60/10/10/20 approximately: train/calibrate/threshold/test; disjoint domain groups',
                         thresholds_selected_on='Maximize validation recall subject to validation false-positive-rate target',
                         validation_fpr_target=args.max_fpr, calibration='sigmoid on disjoint calibration domains',
                         hybrid_formula='0.8 * Random Forest score + 0.2 * rule score',
                         feature_normalization='Ignore conventional leading www in lexical feature measurements',
                         features=list(FEATURE_NAMES), confusion_matrix_order=['legitimate', 'phishing']),
        splits={name: dict(rows=len(indices), phishing=int(y[indices].sum()),
                           legitimate=int(len(indices) - y[indices].sum()),
                           domains=len(set(groups[indices]))) for name, indices in partitions.items()},
        thresholds=dict(rules=rule_threshold, random_forest=rf_threshold, hybrid=threshold),
        test_results=dict(
            rules=metrics(y[test], rule_scores[test] >= rule_threshold),
            random_forest=metrics(y[test], test_probability >= rf_threshold),
            hybrid=metrics(y[test], hybrid_score(test_probability, rule_scores[test]) >= threshold)),
        timing=dict(training_seconds=training_seconds, batch_model_ms_per_url=batch_ms_per_url,
                    calibration_seconds=calibration_seconds,
                    single_url_analysis_median_ms=float(np.median(timings)),
                    single_url_analysis_p95_ms=float(np.percentile(timings, 95))),
        environment=dict(python=platform.python_version(), sklearn=sklearn.__version__,
                         platform=platform.platform(), processor=platform.processor()),
        limitations=['Historical benchmark; no guarantee for new phishing campaigns.',
                     'URL text only: no webpage content, redirects, DNS, certificates, or reputation.',
                     'Dataset artifacts and collection bias may inflate benchmark performance.',
                     'Feature normalization was revised during development; an independent external test is still needed.',
                     'Calibration is fitted on historical data; it can fail under distribution shift.',
                     'Hybrid index is not a calibrated probability; no claim of exceeding a paper benchmark.'],
        trained_at=artifact['trained_at'],
    )
    report['probabilistic_metrics'] = dict(
        brier_score=float(brier_score_loss(y[test], test_probability)),
        roc_auc=float(roc_auc_score(y[test], test_probability)),
        average_precision=float(average_precision_score(y[test], test_probability)))
    report['source_audit'] = [dict(source=source, label='phishing' if label else 'legitimate',
                                  rows=len(part), non_root_path_fraction=float((part.path_length > 1).mean()))
                              for (source, label), part in clean.groupby(['source', 'target'])]
    report['validation_results'] = dict(
        rules=metrics(y[validation], rule_scores[validation] >= rule_threshold),
        random_forest=metrics(y[validation], validation_probability >= rf_threshold),
        hybrid=metrics(y[validation], hybrid_score(validation_probability, rule_scores[validation]) >= threshold))
    report['timing']['total_training_pipeline_seconds'] = perf_counter() - started
    joblib.dump(artifact, ROOT / 'model.joblib', compress=3)
    (ROOT / 'evaluation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report['test_results'], indent=2), flush=True)
    print('Saved model.joblib and evaluation.json.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--csv', type=Path, help='CSV with URL,label columns using UCI label meanings')
    parser.add_argument('--max-rows', type=int, default=0, help='Default 0: all rows; set a limit for quick experiments')
    parser.add_argument('--max-fpr', type=float, default=.01, help='Validation false-positive-rate target, default 0.01')
    parser.add_argument('--additional-data', type=Path, default=ADDITIONAL_FILE)
    parser.add_argument('--additional-limit', type=int, default=200000, help='Stratified supplementary sample; 0=all')
    parser.add_argument('--no-additional-data', action='store_true', help='Reproduce the UCI-only baseline (known homepage bias)')
    arguments = parser.parse_args()
    if arguments.max_rows < 0 or 0 < arguments.max_rows < 100:
        parser.error('--max-rows must be 0 or at least 100')
    if not 0 < arguments.max_fpr < 1:
        parser.error('--max-fpr must be between 0 and 1')
    if arguments.additional_limit < 0 or 0 < arguments.additional_limit < 100:
        parser.error('--additional-limit must be 0 or at least 100')
    try:
        train(arguments)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Training failed: {exc}\n')
