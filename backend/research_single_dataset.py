"""Reproducible ealvaradob-only comparison; production artifacts are untouched."""
import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from detector import FEATURE_NAMES, extract_features
from metrics import metrics
from research_v3 import f1_threshold
from train import NAMES, split_data, train_models


def main(source, output):
    if output.exists():
        raise ValueError('Use a new output directory.')
    raw = pd.read_json(source)[['text', 'label']]
    if raw.label.isna().any() or not set(raw.label.unique()).issubset({0, 1}):
        raise ValueError('Expected binary labels, 1=phishing.')
    records, invalid = [], 0
    for i, (url, label) in enumerate(raw.itertuples(index=False, name=None)):
        try:
            if not isinstance(url, str):
                raise ValueError('Missing URL')
            if '://' not in url:
                url = 'https://' + url
            normalized, features, group = extract_features(url)
        except (ValueError, TypeError):
            invalid += 1
            continue
        records.append(dict(url=normalized, group=group, target=int(label), **features))
        if i and i % 100000 == 0:
            print(f'Extracted {i:,}/{len(raw):,}', flush=True)
    clean = pd.DataFrame(records)
    conflicts = clean.groupby('url').target.nunique()
    bad = conflicts[conflicts > 1].index
    conflicting_rows = int(clean.url.isin(bad).sum())
    clean = clean[~clean.url.isin(bad)]
    before = len(clean)
    clean = clean.drop_duplicates('url').reset_index(drop=True)
    profile = dict(raw_rows=len(raw), invalid_rows=invalid, conflicting_urls=len(bad),
                   conflicting_rows=conflicting_rows, duplicate_rows=before-len(clean),
                   cleaned_rows=len(clean), phishing=int(clean.target.sum()),
                   legitimate=int((clean.target == 0).sum()),
                   source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                   label_convention='1=phishing, 0=legitimate',
                   bare_url_policy='Apply https:// equally to either class when scheme absent',
                   features='Existing 32 URL features; leading www ignored in measurements, URLs preserved')
    print(json.dumps(profile, indent=2), flush=True)
    provenance = [dict(name='ealvaradob only', path=str(source), **profile)]
    train_models(clean, provenance, output, max_fpr=.01, jobs=4)
    x = clean[list(FEATURE_NAMES)].to_numpy(dtype=float)
    y = clean.target.to_numpy()
    splits = split_data(x, y, clean.group.to_numpy())
    val, test = splits['validation'], splits['test']
    rows, predictions = [], clean.loc[test, ['url', 'group', 'target']].copy()
    frozen = {}
    # Freeze all raw-model balanced thresholds using validation before test scoring.
    for name in NAMES:
        artifact = joblib.load(output/f'{name}.joblib')
        threshold = f1_threshold(y[val], artifact['model'].predict_proba(x[val])[:, 1])
        frozen[name] = threshold
    (output/'balanced_validation_thresholds.json').write_text(json.dumps(frozen, indent=2))
    for name in NAMES:
        artifact = joblib.load(output/f'{name}.joblib')
        p = artifact['model'].predict_proba(x[test])[:, 1]
        for policy, threshold in [('balanced_validation_f1', frozen[name]),
                                  ('raw_validation_fpr_1pct', artifact['model_threshold'])]:
            rows.append(dict(model=NAMES[name], policy=policy, threshold=threshold,
                             rows=len(test), **metrics(y[test], p >= threshold)))
        predictions[name+'_probability'] = p
    evaluation = json.loads((output/'evaluation.json').read_text())
    for name, result in evaluation['models'].items():
        rows.append(dict(model=NAMES[name], policy='hybrid_validation_fpr_1pct',
                         threshold=result['threshold'], rows=len(test), **result['test_results']))
    pd.DataFrame(rows).to_csv(output/'all_scores.csv', index=False)
    predictions.to_csv(output/'test_predictions.csv', index=False)
    (output/'dataset_profile.json').write_text(json.dumps(profile, indent=2))
    joblib.dump(clean, output/'cleaned_features.joblib', compress=3)
    print(pd.DataFrame(rows).drop(columns=['confusion_matrix']).round(5).to_string(index=False), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    main(args.source, args.output)
