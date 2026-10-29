"""Binary metrics and exact validation-only operating point selection."""
import numpy as np
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             precision_recall_fscore_support, roc_curve)


def metrics(labels, predictions):
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average='binary', zero_division=0)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return dict(accuracy=float(accuracy_score(labels, predictions)),
                precision=float(precision), recall=float(recall), f1=float(f1),
                false_positive_rate=float(fp / max(1, tn + fp)),
                missed_phishing_rate=float(fn / max(1, tp + fn)),
                confusion_matrix=[[int(tn), int(fp)], [int(fn), int(tp)]])


def tune_threshold(labels, scores, max_fpr=.01):
    labels, scores = np.asarray(labels), np.asarray(scores, dtype=float)
    if (not 0 < max_fpr < 1 or labels.ndim != 1 or scores.shape != labels.shape
            or set(np.unique(labels)) != {0, 1} or not np.isfinite(scores).all()
            or np.any((scores < 0) | (scores > 1))):
        raise ValueError('Threshold selection needs two classes and finite scores in [0, 1].')
    # Every distinct observed operating point, including ties and predict-none.
    # The old 0.01 grid could skip a materially better feasible threshold.
    fpr, recall, thresholds = roc_curve(labels, scores, drop_intermediate=False)
    thresholds[0] = np.nextafter(1., np.inf)
    feasible = np.flatnonzero(fpr <= max_fpr)
    best = max(feasible, key=lambda i: (recall[i], -fpr[i], -abs(thresholds[i] - .5)))
    return float(thresholds[best])
