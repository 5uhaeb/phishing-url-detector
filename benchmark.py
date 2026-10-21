"""Offline UCI-327 paper-context benchmark. Never used for URL inference."""

import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from urllib.request import urlopen
from zipfile import ZipFile

import numpy as np
from scipy.io import arff
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

from train import metrics

ROOT = Path(__file__).resolve().parent


def benchmark():
    path = ROOT / 'data' / 'paper-benchmark.zip'
    if not path.exists():
        path.parent.mkdir(exist_ok=True)
        with urlopen('https://archive.ics.uci.edu/static/public/327/phishing+websites.zip', timeout=60) as response:
            path.write_bytes(response.read(3 * 1024 * 1024))
    with ZipFile(path) as zipped:
        records, metadata = arff.loadarff(io.StringIO(zipped.read('Training Dataset.arff').decode('utf-8')))
    names = list(records.dtype.names)
    x = np.column_stack([records[name].astype(float) for name in names[:-1]])
    # Original Result: -1=phishing, +1=legitimate.
    y = (records[names[-1]].astype(int) == -1).astype(int)
    groups = np.array([hashlib.sha256(row.tobytes()).hexdigest() for row in x])
    splitters = dict(
        stratified_10fold=StratifiedKFold(10, shuffle=True, random_state=42),
        identical_feature_grouped_10fold=StratifiedGroupKFold(10, shuffle=True, random_state=42))
    report = dict(dataset='UCI Phishing Websites 327, 11,055 rows / 30 precomputed website features',
        source='https://archive.ics.uci.edu/dataset/327/phishing+websites', license='CC BY 4.0',
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        created_at=datetime.now(timezone.utc).isoformat(),
        paper_context=dict(title='EnLeM', doi='10.1186/s13635-025-00219-1',
                           reported_accuracy=.9721, reported_f1=.9751),
        comparison_status='Not an exact reproduction or proof of superiority: fold indices, hyperparameters, and reported metric averaging differ.',
        deployment='This offline model uses webpage features absent from a submitted URL. It is not loaded by app.py.',
        rows=len(y), unique_feature_vectors=len(set(groups)), experiments={})
    for name, splitter in splitters.items():
        started = perf_counter()
        predictions = np.zeros(len(y), dtype=int)
        folds = []
        for fold, (training, test) in enumerate(splitter.split(x, y, groups if 'grouped' in name else None), 1):
            model = RandomForestClassifier(n_estimators=240, min_samples_leaf=1,
                                           class_weight='balanced', random_state=42, n_jobs=-1)
            model.fit(x[training], y[training])
            predicted = model.predict(x[test])
            predictions[test] = predicted
            folds.append(dict(accuracy=float((predicted == y[test]).mean()),
                              f1_phishing=float(f1_score(y[test], predicted))))
            print(f'{name}: fold {fold}/10', flush=True)
        result = metrics(y, predictions)
        result.update(weighted_f1=float(f1_score(y, predictions, average='weighted')),
                      fold_mean_accuracy=float(np.mean([f['accuracy'] for f in folds])),
                      fold_std_accuracy=float(np.std([f['accuracy'] for f in folds])),
                      seconds=perf_counter() - started)
        report['experiments'][name] = result
    (ROOT / 'benchmark-results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    benchmark()
