"""Inference-only storage for this project's binary sigmoid-calibrated forest.

Retains every tree, split threshold and leaf probability. Does not import
scikit-learn or pandas in the serving process.
"""
import numpy as np
from scipy.special import expit


class CompactForest:
    def __init__(self, roots, features, left, right, thresholds, positive, a, b, n_features):
        self.roots = roots
        self.features = features
        self.left = left
        self.right = right
        self.thresholds = thresholds
        self.positive = positive
        self.a = a
        self.b = b
        self.n_features_in_ = n_features
        self.classes_ = np.array([0, 1])

    @classmethod
    def from_sklearn(cls, model):
        if (list(model.classes_) != [0, 1] or model.method != 'sigmoid' or
                len(model.calibrated_classifiers_) != 1):
            raise ValueError('Runtime export requires a binary, single-forest sigmoid model.')
        calibrated = model.calibrated_classifiers_[0]
        forest = calibrated.estimator
        if hasattr(forest, 'estimator'):
            forest = forest.estimator
        if len(calibrated.calibrators) != 1 or list(forest.classes_) != [0, 1]:
            raise ValueError('Unsupported calibration or forest class order.')
        trees = forest.estimators_
        size = sum(tree.tree_.node_count for tree in trees)
        if size >= np.iinfo(np.int32).max or forest.n_features_in_ >= np.iinfo(np.int16).max:
            raise ValueError('Model exceeds supported compact index range.')
        roots = np.empty(len(trees), dtype=np.int32)
        features = np.empty(size, dtype=np.int16)
        left = np.empty(size, dtype=np.int32)
        right = np.empty(size, dtype=np.int32)
        thresholds = np.empty(size, dtype=np.float64)
        positive = np.empty(size, dtype=np.float64)
        offset = 0
        for index, estimator in enumerate(trees):
            tree = estimator.tree_
            target = slice(offset, offset + tree.node_count)
            roots[index] = offset
            features[target] = tree.feature
            left[target] = np.where(tree.children_left >= 0, tree.children_left + offset, -1)
            right[target] = np.where(tree.children_right >= 0, tree.children_right + offset, -1)
            thresholds[target] = tree.threshold
            positive[target] = tree.value[:, 0, 1]
            offset += tree.node_count
        sigmoid = calibrated.calibrators[0]
        return cls(roots, features, left, right, thresholds, positive,
                   float(sigmoid.a_), float(sigmoid.b_), forest.n_features_in_)

    def predict_proba(self, values):
        # Match sklearn's float32 inputs and float64 split thresholds.
        matrix = np.asarray(values, dtype=np.float32)
        if matrix.ndim != 2 or matrix.shape[1] != self.n_features_in_ or not np.isfinite(matrix).all():
            raise ValueError('Expected a finite matrix of URL features.')
        raw = np.empty(len(matrix), dtype=np.float64)
        for row_index, row in enumerate(matrix):
            nodes = self.roots.copy()
            while True:
                active = self.left[nodes] >= 0
                if not active.any():
                    break
                current = nodes[active]
                go_left = row[self.features[current]] <= self.thresholds[current]
                nodes[active] = np.where(go_left, self.left[current], self.right[current])
            # Match sklearn's single-worker accumulation in estimator order.
            raw[row_index] = np.add.accumulate(self.positive[nodes])[-1] / len(nodes)
        positive = expit(-(self.a * raw + self.b))
        return np.column_stack((1.0 - positive, positive))
