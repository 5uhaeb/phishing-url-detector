"""Independent-domain evaluation. No threat-list lookup contributes to model scores."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from detector import FEATURE_NAMES, evaluate_rules, extract_features, hybrid_score
from feeds import FeedStore
from train import ROOT, metrics


def evaluate(csv=None, limit=500):
    artifact = joblib.load(ROOT / 'model.joblib')
    if artifact.get('features') != list(FEATURE_NAMES):
        raise ValueError('Train the current feature schema first.')
    seen = artifact.get('development_group_hashes')
    if seen is None:
        raise ValueError('Retrain first: model lacks domain provenance for overlap filtering.')
    store = FeedStore()
    sources = []
    if csv:
        frame = pd.read_csv(csv)[['URL', 'label']].dropna()
        if not set(frame.label.unique()).issubset({0, 1}):
            raise ValueError('External CSV labels must be 1=phishing and 0=legitimate.')
        sources = [(csv.name, list(frame.itertuples(index=False, name=None)),
                    dict(sha256=hashlib.sha256(csv.read_bytes()).hexdigest()))]
    else:
        for source in store.status()['sources']:
            if not source['fresh']:
                continue
            path = store.directory / f"{source['key']}.txt"
            if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != source['sha256']:
                continue
            sources.append((source['name'], [(url, 1) for url in path.read_text(encoding='utf-8-sig').splitlines()
                                            if url.strip() and not url.startswith('#')], source))
    report = dict(created_at=datetime.now(timezone.utc).isoformat(), model_version=artifact['trained_at'],
                  methodology='Frozen model, unchanged thresholds; filter domains from every training/calibration/development/test partition.',
                  label_convention='1=phishing, 0=legitimate', sources=[],
                  limitations=['Feed labels are provider reports, not independent manual site verification.',
                               'Positive-only feeds estimate recall, not precision, F1, false positives, or accuracy.',
                               'Feed lookup matches are a functional integration check, not model performance.',
                               'A separate future-time mixed-class dataset is still required for production validation.'])
    used_groups = set()
    for name, records, provenance in sources:
        vectors, targets, urls = [], [], []
        skipped = 0
        # Stable sampling independent of predictions and labels; one URL per new domain.
        rng = np.random.default_rng(42)
        for position in rng.permutation(len(records)):
            value, label = records[position]
            try:
                normalized, features, group = extract_features(value)
            except ValueError:
                skipped += 1
                continue
            if hashlib.sha256(group.encode()).hexdigest() in seen or group in used_groups:
                skipped += 1
                continue
            used_groups.add(group)
            vectors.append([features[f] for f in FEATURE_NAMES])
            targets.append(int(label))
            urls.append(value)
            if len(vectors) >= limit:
                break
        if not vectors:
            report['sources'].append(dict(source=name, evaluated=0, skipped=skipped))
            continue
        matrix, y = np.array(vectors, dtype=float), np.array(targets)
        probability = artifact['model'].predict_proba(matrix)[:, list(artifact['model'].classes_).index(1)]
        rules = np.array([evaluate_rules(dict(zip(FEATURE_NAMES, row)))[0] for row in matrix])
        predictions = hybrid_score(probability, rules, artifact.get('model_weight', .8)) >= artifact['threshold']
        results = metrics(y, predictions)
        if len(set(y)) == 1:
            # Do not emit misleading perfect precision/F1/accuracy from phishing-only rows.
            results = dict(phishing_recall=float(predictions.mean()),
                           detected=int(predictions.sum()), missed=int((~predictions).sum())) if y[0] == 1 else dict(
                               false_positive_rate=float(predictions.mean()), false_positives=int(predictions.sum()))
        # Local URL matching only; no external service and no submitted target is visited.
        exact_matches = sum(store.lookup(url)['status'] == 'match' for url in urls) if not csv else None
        report['sources'].append(dict(source=name, evaluated=len(y), skipped=skipped,
            phishing=int(y.sum()), legitimate=int(len(y) - y.sum()), local_model_only=results,
            functional_feed_matches=exact_matches,
            provenance={k: provenance[k] for k in ('sha256', 'fetched_at', 'license') if k in provenance}))
    if not report['sources']:
        raise ValueError('No fresh feed snapshots or external CSV available.')
    (ROOT / 'external-evaluation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', type=Path, help='Independent URL,label CSV, 1=phishing, 0=legitimate')
    parser.add_argument('--limit', type=int, default=500, help='New domains per source')
    args = parser.parse_args()
    if args.limit < 1:
        parser.error('--limit must be positive')
    try:
        evaluate(args.csv, args.limit)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Evaluation failed: {exc}\n')
