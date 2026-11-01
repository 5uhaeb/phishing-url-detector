"""Verify fixed final predictions and export domain-bootstrap uncertainty.

This report never fits models, selects thresholds, or changes the frozen run.
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from research_v3 import DATA, digest


def bootstrap(y, predicted, groups, seed=42, repeats=1000):
    """Resample whole registrable domains, preserving within-domain dependence."""
    _, inverse = np.unique(groups, return_inverse=True)
    cells = 2 * y.astype(int) + predicted.astype(int)
    counts = np.column_stack([
        np.bincount(inverse, weights=(cells == cell), minlength=inverse.max()+1)
        for cell in range(4)
    ])
    rng = np.random.default_rng(seed)
    values = []
    for _ in range(repeats):
        tn, fp, fn, tp = counts[rng.integers(len(counts), size=len(counts))].sum(axis=0)
        div = lambda a, b: a/b if b else np.nan
        values.append([div(tp+tn, tp+tn+fp+fn), div(tp, tp+fp),
                       div(tp, tp+fn), div(2*tp, 2*tp+fp+fn), div(fp, fp+tn)])
    return {name: np.nanpercentile(np.asarray(values)[:, index], [2.5, 97.5]).tolist()
            for index, name in enumerate(['accuracy', 'precision', 'recall', 'f1', 'false_positive_rate'])}


def report(output):
    protocol = json.loads((output/'frozen_protocol.json').read_text())
    if digest(output/'research_bundle.joblib') != protocol['bundle_sha256']:
        raise ValueError('Frozen bundle changed')
    bundle = joblib.load(output/'research_bundle.joblib')
    training, _, _ = joblib.load(DATA/'train_clean.joblib')
    frame, numeric, _ = joblib.load(DATA/'test_clean.joblib')
    selected = protocol['winners']
    needed = set().union(*(bundle['weights'][name] for name in selected.values()))
    probabilities = {}
    for name in needed:
        inputs = (bundle['vectorizer'].transform(frame.text) if name == 'character'
                  else numeric[:, bundle['columns'][name]])
        probabilities[name] = bundle['estimators'][name].predict_proba(inputs)[:, 1]
    mask = (~frame.group.isin(set(training.group)) & ~frame.url.isin(set(training.url))).to_numpy()
    actual = frame.label.to_numpy()[mask]
    exported = frame.loc[mask, ['url', 'group', 'label', 'date']].copy()
    scores = pd.read_csv(output/'final_test_scores.csv')
    intervals = {}
    for policy, name in selected.items():
        p = sum(weight*probabilities[base] for base, weight in bundle['weights'][name].items())[mask]
        predicted = p >= bundle['thresholds'][name][policy]
        row = scores[(scores.model == name) & (scores.policy == policy) &
                     (scores.cohort == 'new_model_unseen_domains')].iloc[0]
        # Confirm recomputation is identical to the already completed test.
        observed = [[int(((actual == a) & (predicted == b)).sum()) for b in [0, 1]] for a in [0, 1]]
        assert observed == json.loads(row.confusion_matrix), (observed, row.confusion_matrix)
        exported[policy+'_score'] = p
        exported[policy+'_prediction'] = predicted.astype(int)
        intervals[policy] = dict(model=name, resamples=1000, unit='registrable domain',
                                confidence_95=bootstrap(actual, predicted, exported.group.to_numpy()))
    exported.to_csv(output/'selected_test_predictions.csv', index=False)
    (output/'domain_bootstrap_intervals.json').write_text(json.dumps(intervals, indent=2))
    # Keep only the selected estimators in the standalone artifact.
    artifact = joblib.load(output/'candidate_url_model.joblib')
    candidate = artifact['model']
    candidate.estimators = {key: value for key, value in candidate.estimators.items()
                            if key in candidate.weights}
    check = np.linspace(0, len(exported)-1, 32, dtype=int)
    expected = exported['balanced_f1_score'].to_numpy()[check]
    np.testing.assert_allclose(candidate.predict_proba(exported.url.iloc[check])[:, 1],
                               expected, rtol=1e-6, atol=1e-7)
    joblib.dump(artifact, output/'candidate_url_model_compact.joblib', compress=3)
    print(json.dumps(intervals, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    report(parser.parse_args().output)
