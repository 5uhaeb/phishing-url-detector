"""Train and compare the three models; save results to a separate output folder."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

from dataset import ROOT, load_dataset
from detector import FEATURE_NAMES, evaluate_rules, hybrid_score
from metrics import metrics, tune_threshold, f1_threshold

NAMES = {'random_forest': 'Random Forest', 'xgboost': 'XGBoost', 'lightgbm': 'LightGBM'}


def make_models(jobs):
    return {
        'random_forest': RandomForestClassifier(n_estimators=240, max_depth=24, min_samples_leaf=2,
                            class_weight='balanced', n_jobs=jobs, random_state=42),
        'xgboost': XGBClassifier(n_estimators=900, max_depth=8, learning_rate=.05, min_child_weight=3,
                            subsample=.9, colsample_bytree=.9, reg_lambda=5, tree_method='hist',
                            eval_metric='logloss', n_jobs=jobs, random_state=42),
        'lightgbm': LGBMClassifier(n_estimators=800, num_leaves=31, learning_rate=.04, min_child_samples=30,
                            subsample=.9, subsample_freq=1, colsample_bytree=.9, reg_lambda=3,
                            n_jobs=jobs, random_state=42, verbosity=-1, deterministic=True, force_col_wise=True),
    }


def split_data(x, y, groups):
    trainval, test = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=42).split(x, y, groups))
    train, development = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=43)
                              .split(x[trainval], y[trainval], groups[trainval]))
    train, development = trainval[train], trainval[development]
    calibration, validation = next(GroupShuffleSplit(n_splits=1, test_size=.5, random_state=44)
                                   .split(x[development], y[development], groups[development]))
    splits = dict(training=train, calibration=development[calibration], validation=development[validation], test=test)
    for name, indices in splits.items():
        if len(np.unique(y[indices])) != 2:
            raise ValueError(f'{name} needs both classes. Use more data.')
    for first, second in combinations(splits.values(), 2):
        if set(groups[first]) & set(groups[second]):
            raise ValueError('Domains overlap between data splits.')
    return splits


def train_models(clean, sources, output, max_fpr=.01, jobs=4):
    if output.exists():
        raise ValueError('Choose a new output folder to preserve existing models.')
    x = clean[list(FEATURE_NAMES)].to_numpy(dtype=float)
    y, groups = clean.target.to_numpy(), clean.group.to_numpy()
    splits = split_data(x, y, groups)
    train, calibration, validation, test = (splits[name] for name in splits)
    rules = np.array([evaluate_rules(dict(zip(FEATURE_NAMES, row)))[0] for row in x])
    version = datetime.now(timezone.utc).isoformat()
    artifacts, results = {}, {}
    for name, base in make_models(jobs).items():
        print(f'Training {NAMES[name]}...', flush=True)
        base.fit(x[train], y[train])
        base.set_params(n_jobs=1)
        model = CalibratedClassifierCV(FrozenEstimator(base), method='sigmoid')
        model.fit(x[calibration], y[calibration])
        scores = model.predict_proba(x[validation])[:, 1]
        policies = []
        for weight in [1., .9, .8]:
            index = hybrid_score(scores, rules[validation], weight)
            threshold = tune_threshold(y[validation], index, max_fpr)
            policies.append((weight, threshold, metrics(y[validation], index >= threshold)))
        weight, threshold, measured = max(policies, key=lambda item: (item[2]['recall'], item[2]['precision'], item[0]))
        artifacts[name] = dict(model=model, model_family=name, model_name=NAMES[name], features=list(FEATURE_NAMES),
                               threshold=threshold, model_weight=weight, calibrated=True, trained_at=version,
                               model_threshold=tune_threshold(y[validation], scores, max_fpr),
                               balanced_threshold=f1_threshold(y[validation],scores),
                               positive_class=sources[0].get('positive_class','phishing') if sources else 'phishing')
        results[name] = dict(validation_results=measured, validation_ap=float(average_precision_score(y[validation], scores)),
                              model_weight=weight, threshold=threshold)
    # Choose the winner before evaluating any held-out test predictions.
    winner = max(results, key=lambda name: (results[name]['validation_results']['recall'],
                                           results[name]['validation_results']['precision'], results[name]['validation_ap']))
    for name, artifact in artifacts.items():
        scores = artifact['model'].predict_proba(x[test])[:, 1]
        decisions = hybrid_score(scores, rules[test], artifact['model_weight']) >= artifact['threshold']
        results[name]['test_results'] = metrics(y[test], decisions)
        results[name]['balanced_test_results'] = metrics(y[test], scores>=artifact['balanced_threshold'])
        results[name]['balanced_threshold'] = artifact['balanced_threshold']
        results[name]['probabilistic_metrics'] = dict(roc_auc=float(roc_auc_score(y[test], scores)),
            average_precision=float(average_precision_score(y[test], scores)), brier_score=float(brier_score_loss(y[test], scores)))
    output.mkdir(parents=True)
    manifest = {'models': {}}
    for name, artifact in artifacts.items():
        path = output / f'{name}.joblib'
        joblib.dump(artifact, path, compress=('xz', 3))
        manifest['models'][name] = dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    report = dict(trained_at=version, selected_model=winner, selected_model_name=NAMES[winner], models=results,
                  dataset=dict(sources=sources, usable_rows=len(clean)),
                  methodology=dict(seed=42, validation_fpr_target=max_fpr,
                      positive_class=(sources[0].get('positive_class','phishing') if sources else 'phishing')+'=1',
                      model_selection='validation recall, precision, average precision; test never selects winner'),
                  splits={name:dict(rows=len(indices), domains=len(set(groups[indices]))) for name, indices in splits.items()})
    for filename, value in [('manifest.json', manifest), ('evaluation.json', report)]:
        (output / filename).write_text(json.dumps(value, indent=2, allow_nan=False), encoding='utf-8')
    np.savez_compressed(output / 'split-indices.npz', **splits)
    comparison=[]
    for name,result in results.items():
        comparison.append(dict(model=NAMES[name],policy='Conservative hybrid',threshold=result['threshold'],**result['test_results']))
        comparison.append(dict(model=NAMES[name],policy='Maximum validation F1, raw ML',threshold=result['balanced_threshold'],**result['balanced_test_results']))
    pd.DataFrame(comparison).to_csv(
        output / 'comparison.csv', index=False)
    print(f'Selected {NAMES[winner]} on validation. Models and reports saved to {output}.', flush=True)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,required=True,help='CSV or JSON with url/URL/text and label')
    parser.add_argument('--positive-label',type=int,choices=[0,1],default=1)
    parser.add_argument('--dataset-name',default='Provided URL dataset')
    parser.add_argument('--target-name',default='phishing',help='Meaning of the supplied positive label')
    parser.add_argument('--infer-https',action='store_true',help='Apply https:// equally to bare URLs in either class')
    parser.add_argument('--max-rows', type=int, default=0)
    parser.add_argument('--max-fpr', type=float, default=.01)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--output', type=Path, default=ROOT / 'training_output')
    args = parser.parse_args()
    if args.jobs < 1 or not 0 < args.max_fpr < 1 or args.max_rows < 0:
        parser.error('Use positive jobs, nonnegative row limits and 0 < max-fpr < 1.')
    try:
        clean, sources, *_ = load_dataset(args)
        train_models(clean, sources, args.output, args.max_fpr, args.jobs)
    except (ValueError, OSError) as error:
        parser.exit(1, f'Training failed: {error}\n')
