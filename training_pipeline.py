"""Reproducible domain-disjoint comparison of Random Forest, XGBoost and LightGBM."""
import hashlib
import json
import math
import os
import platform
import shutil
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from time import perf_counter

import joblib
import lightgbm
import numpy as np
import sklearn
import xgboost
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from detector import FEATURE_NAMES, analyze, evaluate_rules, hybrid_score
from training_metrics import metrics, tune_threshold

ROOT = Path(__file__).resolve().parent
SEED = 42
DISPLAY_NAMES = {'random_forest': 'Random Forest', 'xgboost': 'XGBoost', 'lightgbm': 'LightGBM'}


def json_safe(value):
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_safe(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return value


def make_partitions(x, y, groups):
    trainval, test = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED).split(x, y, groups))
    inner_train, development = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=SEED + 1)
                                   .split(x[trainval], y[trainval], groups[trainval]))
    training, development = trainval[inner_train], trainval[development]
    calibration, validation = next(GroupShuffleSplit(n_splits=1, test_size=.5, random_state=SEED + 2)
                                  .split(x[development], y[development], groups[development]))
    partitions = dict(training=training, calibration=development[calibration],
                      validation=development[validation], test=test)
    for name, indices in partitions.items():
        if set(np.unique(y[indices])) != {0, 1}:
            raise ValueError(f'{name} partition needs both classes; use more domains.')
    if any(set(groups[a]) & set(groups[b]) for a, b in combinations(partitions.values(), 2)):
        raise ValueError('Domain leakage between partitions.')
    return partitions


def model_candidates(jobs):
    return {
        'random_forest': [
            RandomForestClassifier(n_estimators=240, max_depth=24, min_samples_leaf=2,
                                   class_weight='balanced', n_jobs=jobs, random_state=SEED),
            RandomForestClassifier(n_estimators=480, max_depth=32, min_samples_leaf=1,
                                   max_features=.8, class_weight='balanced', n_jobs=jobs, random_state=SEED),
        ],
        'xgboost': [xgboost.XGBClassifier(
            n_estimators=trees, max_depth=depth, learning_rate=.05, min_child_weight=3,
            subsample=.9, colsample_bytree=.9, reg_lambda=5, tree_method='hist',
            objective='binary:logistic', eval_metric='logloss', n_jobs=jobs, random_state=SEED)
            for trees, depth in [(600, 6), (900, 8)]],
        'lightgbm': [lightgbm.LGBMClassifier(
            n_estimators=trees, num_leaves=leaves, learning_rate=.04, min_child_samples=30,
            subsample=.9, subsample_freq=1, colsample_bytree=.9, reg_lambda=3,
            objective='binary', n_jobs=jobs, random_state=SEED, verbosity=-1,
            deterministic=True, force_col_wise=True)
            for trees, leaves in [(800, 31), (1000, 63)]],
    }


def probability(model, matrix):
    return model.predict_proba(matrix)[:, list(model.classes_).index(1)]


def rank(result):
    m = result['validation_results']['hybrid']
    return m['recall'], m['precision'], result['validation_probability']['average_precision']


def probabilistic(labels, scores):
    return dict(roc_auc=float(roc_auc_score(labels, scores)),
                average_precision=float(average_precision_score(labels, scores)),
                brier_score=float(brier_score_loss(labels, scores)))


def atomic_copy(source, destination):
    temporary = destination.with_suffix(destination.suffix + '.tmp')
    shutil.copyfile(source, temporary)
    os.replace(temporary, destination)


def write_markdown(report, path):
    rows = ['# Phase 1 model comparison', '',
            f"Selected on validation: **{report['selected_model_name']}**. Test results never select the winner.", '',
            '| Model | Accuracy | Precision | Recall | F1 | FPR | ROC AUC |',
            '|---|---:|---:|---:|---:|---:|---:|']
    baseline = report.get('previous_baseline', {})
    if baseline.get('test_results'):
        m = baseline['test_results']['hybrid']
        rows.append('| Previous hybrid | ' + ' | '.join(f'{m[k]:.2%}' for k in
                    ['accuracy', 'precision', 'recall', 'f1', 'false_positive_rate']) + ' | — |')
    for key, result in report['models'].items():
        m = result['test_results']['hybrid']
        rows.append(f"| {DISPLAY_NAMES[key]} | " + ' | '.join(f'{m[k]:.2%}' for k in
                    ['accuracy', 'precision', 'recall', 'f1', 'false_positive_rate']) +
                    f" | {result['probabilistic_metrics']['roc_auc']:.4f} |")
    if baseline.get('test_results'):
        m = baseline['test_results']['hybrid']
        rows.extend(['', f"Previous hybrid: accuracy {m['accuracy']:.2%}, recall {m['recall']:.2%}, FPR {m['false_positive_rate']:.2%}.",
                     'Historical baseline figures are directly comparable only when dataset and split fingerprints match.'])
    audit = report.get('baseline_on_same_test', {})
    if audit.get('matches_historical_confusion_matrix'):
        rows.extend(['', 'Baseline audit: the unchanged previous model reproduces its original confusion matrix on this exact test partition.'])
    if report.get('improvement_percentage_points'):
        delta = report['improvement_percentage_points']
        rows.extend(['', f"Champion changes: accuracy {delta['accuracy']:+.2f}, recall {delta['recall']:+.2f}, F1 {delta['f1']:+.2f}, FPR {delta['false_positive_rate']:+.2f} percentage points."])
    rows.extend(['', '| Model | Median analysis (ms) | p95 analysis (ms) |', '|---|---:|---:|'])
    for key, result in report['models'].items():
        rows.append(f"| {DISPLAY_NAMES[key]} | {result['single_url_analysis_median_ms']:.2f} | {result['single_url_analysis_p95_ms']:.2f} |")
    rows.extend(['', 'All models use the same raw URL features, data, disjoint domain partitions, calibration method and validation FPR target.',
                 'Two fixed parameter settings per family; no test-driven parameter or threshold changes.',
                 'The historical split was used in earlier development. This is a regression comparison, not a new independent prospective benchmark.',
                 'Validation targets do not guarantee test or future false-positive rates. Production requires a future-time mixed-class audit.', ''])
    path.write_text('\n'.join(rows), encoding='utf-8')


def run_comparison(args, data):
    started = perf_counter()
    clean, provenance, raw_count, invalid, path = data
    x = clean[list(FEATURE_NAMES)].to_numpy(dtype=float)
    y, groups = clean.target.to_numpy(), clean.group.to_numpy()
    partitions = make_partitions(x, y, groups)
    training, calibration, validation, test = (partitions[k] for k in ['training', 'calibration', 'validation', 'test'])
    rules = np.array([evaluate_rules(dict(zip(FEATURE_NAMES, row)))[0] for row in x])
    trained_at = datetime.now(timezone.utc).isoformat()
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = args.output_dir / run_id
    output.mkdir(parents=True, exist_ok=False)
    np.savez_compressed(output / 'split-indices.npz', **partitions)
    dataset_fingerprint = hashlib.sha256('\n'.join(
        f'{url}\t{target}' for url, target in zip(clean.url, y)).encode()).hexdigest()
    split_fingerprint = hashlib.sha256(b''.join(partitions[k].astype('<i8').tobytes() for k in partitions)).hexdigest()
    seen = {hashlib.sha256(g.encode()).hexdigest() for g in groups}
    rule_threshold = tune_threshold(y[validation], rules[validation], args.max_fpr)
    baseline = {}
    if (ROOT / 'evaluation.json').exists():
        baseline = json.loads((ROOT / 'evaluation.json').read_text(encoding='utf-8'))
    report = dict(schema_version=2, run_id=run_id, trained_at=trained_at,
        dataset=dict(name='Multi-source raw URLs', sources=provenance, raw_rows=raw_count,
                     usable_rows=len(clean), invalid_sampled_urls=invalid, sample_limit=args.max_rows,
                     ordered_url_label_sha256=dataset_fingerprint),
        methodology=dict(seed=SEED, positive_class='phishing (1)',
            source_labels='UCI 0=phishing, 1=legitimate; supplementary 1=phishing, 0=legitimate',
            split='60/10/10/20 approximately: train/calibrate/validation/test; disjoint registered domains',
            split_indices_sha256=split_fingerprint, calibration='sigmoid on separate calibration domains',
            validation_fpr_target=args.max_fpr, thresholds_selected_on='validation only; exact empirical ROC points',
            model_selection='validation hybrid recall, then precision, then average precision',
            policy_weights=[1.0, .9, .8], candidates_per_family=2,
            features=list(FEATURE_NAMES), confusion_matrix_order=['legitimate', 'phishing'],
            test_usage='Historical regression split; not a new independent prospective benchmark'),
        splits={name: dict(rows=len(indices), phishing=int(y[indices].sum()),
                          legitimate=int(len(indices) - y[indices].sum()), domains=len(set(groups[indices])))
                for name, indices in partitions.items()},
        source_audit=[dict(source=source, label='phishing' if label else 'legitimate', rows=len(part),
                          non_root_path_fraction=float((part.path_length > 1).mean()))
                      for (source, label), part in clean.groupby(['source', 'target'])],
        environment=dict(python=platform.python_version(), sklearn=sklearn.__version__,
                         xgboost=xgboost.__version__, lightgbm=lightgbm.__version__,
                         numpy=np.__version__, platform=platform.platform()),
        previous_baseline=dict(trained_at=baseline.get('trained_at'), test_results=baseline.get('test_results'),
                               dataset=baseline.get('dataset'), methodology=baseline.get('methodology')),
        models={}, limitations=['Historical datasets and collection bias; not a safety guarantee.',
                               'No future-time mixed-class validation supplied.',
                               'Hybrid risk index is not a calibrated probability.',
                               'False-positive rate is constrained on validation only.'])
    # Freeze all family selections before running any test predictions.
    selected = {}
    for family, candidates in model_candidates(args.jobs).items():
        best, best_artifact, trials = None, None, []
        for number, estimator in enumerate(candidates, 1):
            print(f'Training {DISPLAY_NAMES[family]} candidate {number}/{len(candidates)}...', flush=True)
            tick = perf_counter()
            params = json_safe(estimator.get_params())
            estimator.fit(x[training], y[training])
            estimator.set_params(n_jobs=1)
            model = CalibratedClassifierCV(FrozenEstimator(estimator), method='sigmoid')
            model.fit(x[calibration], y[calibration])
            validation_probability = probability(model, x[validation])
            model_threshold = tune_threshold(y[validation], validation_probability, args.max_fpr)
            policies = []
            for weight in [1., .9, .8]:
                scores = hybrid_score(validation_probability, rules[validation], weight)
                threshold = tune_threshold(y[validation], scores, args.max_fpr)
                policies.append((weight, threshold, metrics(y[validation], scores >= threshold)))
            weight, threshold, policy = max(policies, key=lambda p: (p[2]['recall'], p[2]['precision'], p[0]))
            result = dict(candidate=number, parameters=params, model_weight=weight,
                          thresholds=dict(model=model_threshold, hybrid=threshold, rules=rule_threshold),
                          validation_results=dict(hybrid=policy, model=metrics(y[validation], validation_probability >= model_threshold)),
                          validation_probability=probabilistic(y[validation], validation_probability),
                          training_and_calibration_seconds=perf_counter() - tick)
            trials.append(result)
            if best is None or rank(result) > rank(best):
                best = result
                best_artifact = dict(model=model, model_name=DISPLAY_NAMES[family], model_family=family,
                    features=list(FEATURE_NAMES), threshold=threshold, model_threshold=model_threshold,
                    rf_threshold=model_threshold, model_weight=weight, calibrated=True,
                    development_group_hashes=seen, trained_at=trained_at, run_id=run_id,
                    sklearn_version=sklearn.__version__, environment=report['environment'],
                    dataset_sha256=dataset_fingerprint, split_sha256=split_fingerprint)
            print(f"  validation recall={policy['recall']:.4f}; FPR={policy['false_positive_rate']:.4f}", flush=True)
        best = dict(best, trials=[dict(trial) for trial in trials])
        selected[family] = best_artifact
        report['models'][family] = best
        joblib.dump(best_artifact, output / f'{family}.joblib', compress=3)
    winner = max(report['models'], key=lambda key: rank(report['models'][key]))
    report.update(selected_model=winner, selected_model_name=DISPLAY_NAMES[winner])
    print(f'Validation-selected champion: {DISPLAY_NAMES[winner]}. Evaluating frozen test partition...', flush=True)
    for family, artifact in selected.items():
        result = report['models'][family]
        tick = perf_counter()
        scores = probability(artifact['model'], x[test])
        result['batch_model_ms_per_url'] = (perf_counter() - tick) * 1000 / len(test)
        result['test_results'] = dict(
            model=metrics(y[test], scores >= artifact['model_threshold']),
            hybrid=metrics(y[test], hybrid_score(scores, rules[test], artifact['model_weight']) >= artifact['threshold']),
            default_05=metrics(y[test], scores >= .5), rules=metrics(y[test], rules[test] >= rule_threshold))
        result['probabilistic_metrics'] = probabilistic(y[test], scores)
        timings = []
        for url in clean.url.iloc[test[:100]]:
            tick = perf_counter()
            analyze(url, artifact)
            timings.append((perf_counter() - tick) * 1000)
        result['single_url_analysis_median_ms'] = float(np.median(timings))
        result['single_url_analysis_p95_ms'] = float(np.percentile(timings, 95))
    if (ROOT / 'model.joblib').exists():
        previous = joblib.load(ROOT / 'model.joblib')
        if (previous.get('features') == list(FEATURE_NAMES)
                and previous.get('development_group_hashes') == seen):
            old_scores = previous['model'].predict_proba(x[test])[:, list(previous['model'].classes_).index(1)]
            measured = metrics(y[test], hybrid_score(old_scores, rules[test], previous.get('model_weight', .8)) >= previous['threshold'])
            report['baseline_on_same_test'] = dict(trained_at=previous['trained_at'], hybrid=measured,
                matches_historical_confusion_matrix=measured['confusion_matrix'] == baseline.get('test_results', {}).get('hybrid', {}).get('confusion_matrix'))
            report['improvement_percentage_points'] = {
                key: 100 * (report['models'][winner]['test_results']['hybrid'][key] - measured[key])
                for key in ['accuracy', 'precision', 'recall', 'f1', 'false_positive_rate']}
    champion = dict(report)
    chosen = report['models'][winner]
    champion.update(test_results=dict(chosen['test_results'], random_forest=report['models']['random_forest']['test_results']['model']),
                    validation_results=chosen['validation_results'], thresholds=chosen['thresholds'],
                    probabilistic_metrics=chosen['probabilistic_metrics'],
                    timing=dict(total_training_pipeline_seconds=perf_counter() - started))
    for filename, content in [('comparison.json', report), ('evaluation.json', champion)]:
        (output / filename).write_text(json.dumps(json_safe(content), indent=2, allow_nan=False), encoding='utf-8')
    write_markdown(report, output / 'comparison.md')
    reports = ROOT / 'reports'
    reports.mkdir(exist_ok=True)
    for filename in ['comparison.json', 'comparison.md']:
        atomic_copy(output / filename, reports / filename)
    if not args.no_promote:
        # Preserve the previous release before replacing local serving files.
        backup = output / 'previous-release'
        backup.mkdir()
        for filename in ['model.joblib', 'runtime-model.joblib', 'evaluation.json', 'external-evaluation.json']:
            if (ROOT / filename).exists():
                shutil.copyfile(ROOT / filename, backup / filename)
        from prepare_runtime import prepare
        prepare(output / f'{winner}.joblib', output / 'runtime-model.joblib')
        atomic_copy(output / f'{winner}.joblib', ROOT / 'model.joblib')
        atomic_copy(output / 'runtime-model.joblib', ROOT / 'runtime-model.joblib')
        atomic_copy(output / 'evaluation.json', ROOT / 'evaluation.json')
    print(json.dumps({key: value['test_results']['hybrid'] for key, value in report['models'].items()}, indent=2), flush=True)
    print(f'Artifacts and exact split indices: {output}', flush=True)
    return report
