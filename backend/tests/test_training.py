"""Verify leakage protection and run the complete training flow on small fixtures."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd

from detector import FEATURE_NAMES
from metrics import tune_threshold
from train import make_models, split_data, train_models


class TrainingTests(unittest.TestCase):
    def test_domains_never_overlap_across_partitions(self):
        groups = np.repeat([f'domain-{i}' for i in range(100)], 4)
        y = np.tile([0, 1, 0, 1], 100)
        splits = split_data(np.zeros((400, 2)), y, groups)
        seen = set()
        for indices in splits.values():
            self.assertFalse(seen & set(groups[indices]))
            seen.update(groups[indices])
        self.assertEqual(sum(map(len, splits.values())), 400)

    def test_threshold_respects_close_scores_and_ties(self):
        threshold = tune_threshold([0, 0, 1, 1], [.501, .1, .502, .503])
        self.assertTrue(.501 < threshold <= .502)
        self.assertGreater(tune_threshold([0, 1], [1., 1.]), 1.)

    def test_training_writes_all_models_without_overwriting_existing_output(self):
        rng = np.random.default_rng(42)
        data = pd.DataFrame(rng.uniform(0, 5, (400, len(FEATURE_NAMES))), columns=FEATURE_NAMES)
        data['target'] = np.tile([0, 1, 0, 1], 100)
        data['group'] = np.repeat([f'domain-{i}' for i in range(100)], 4)
        models = make_models(1)
        for model in models.values():
            model.set_params(n_estimators=8)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'models'
            with patch('train.make_models', return_value=models):
                report = train_models(data, [], output, jobs=1)
            self.assertEqual(set(report['models']), set(models))
            for name in models:
                artifact = joblib.load(output / f'{name}.joblib')
                self.assertEqual(artifact['trained_at'], report['trained_at'])
            self.assertTrue((output / 'manifest.json').exists())
            self.assertTrue((output / 'comparison.csv').exists())
            with self.assertRaises(ValueError):
                train_models(data, [], output)


if __name__ == '__main__':
    unittest.main()
