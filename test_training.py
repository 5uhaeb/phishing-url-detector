"""Leakage, operating-point and model-serving compatibility regressions."""
import tempfile
import json
import unittest
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator

from detector import FEATURE_NAMES, analyze, hybrid_score
from prepare_runtime import prepare
from training_metrics import metrics, tune_threshold
from training_pipeline import json_safe, make_partitions, model_candidates, probability


class TrainingTests(unittest.TestCase):
    def test_exact_threshold_finds_feasible_point_missed_by_old_grid(self):
        y = np.array([0, 0, 0, 1, 1, 1])
        scores = np.array([.501, .2, .1, .502, .503, .504])
        threshold = tune_threshold(y, scores, .01)
        m = metrics(y, scores >= threshold)
        self.assertEqual(m['recall'], 1)
        self.assertEqual(m['false_positive_rate'], 0)

    def test_threshold_respects_ties_and_can_predict_none(self):
        y, scores = np.array([0, 1]), np.array([1., 1.])
        threshold = tune_threshold(y, scores, .01)
        self.assertGreater(threshold, 1)
        self.assertFalse((scores >= threshold).any())
        for bad in ([np.nan, .5], [np.inf, .5], [-1, .5]):
            with self.assertRaises(ValueError):
                tune_threshold(y, bad)

    def test_splits_never_share_domains_and_are_reproducible(self):
        groups = np.repeat([f'domain-{i}' for i in range(120)], 4)
        y = np.tile([0, 1, 0, 1], 120)
        x = np.zeros((len(y), 2))
        partitions = make_partitions(x, y, groups)
        repeated = make_partitions(x, y, groups)
        observed = set()
        for name, indices in partitions.items():
            self.assertEqual(list(indices), list(repeated[name]))
            self.assertFalse(observed & set(groups[indices]))
            observed.update(groups[indices])
        self.assertEqual(sum(map(len, partitions.values())), len(y))

    def test_all_three_families_calibrate_export_and_serve_with_parity(self):
        rng = np.random.default_rng(32)
        x = rng.uniform(0, 5, (400, len(FEATURE_NAMES)))
        y = (x[:, 0] + x[:, 1] > 5).astype(int)
        for family, candidates in model_candidates(1).items():
            with self.subTest(family=family), tempfile.TemporaryDirectory() as directory:
                base = candidates[0].set_params(n_estimators=12)
                base.fit(x[:200], y[:200])
                model = CalibratedClassifierCV(FrozenEstimator(base), method='sigmoid').fit(x[200:300], y[200:300])
                np.testing.assert_allclose(probability(model, x[300:]), model.predict_proba(x[300:])[:, 1], atol=1e-12)
                artifact = dict(model=model, model_family=family, model_name=family,
                                features=list(FEATURE_NAMES), threshold=.5, model_threshold=.6,
                                model_weight=.9, trained_at='fixture', calibrated=True,
                                development_group_hashes={'test-hash'})
                source, dest = Path(directory) / 'full.joblib', Path(directory) / 'runtime.joblib'
                joblib.dump(artifact, source)
                prepare(source, dest)
                runtime = joblib.load(dest)
                self.assertNotIn('development_group_hashes', runtime)
                self.assertIn('development_group_hashes', joblib.load(source))
                np.testing.assert_allclose(runtime['model'].predict_proba(x[300:]), model.predict_proba(x[300:]), atol=1e-12)
                result = analyze('https://example.com/account', runtime)
                self.assertEqual(result, analyze('https://example.com/account', artifact))
                self.assertEqual(result['model_name'], family)
                self.assertEqual(result['model_weight'], .9)
                del runtime

    def test_hybrid_uses_frozen_weight(self):
        self.assertAlmostEqual(hybrid_score(.8, .2), .68)
        self.assertAlmostEqual(hybrid_score(.8, .2, 1.), .8)

    def test_report_parameters_are_strict_json(self):
        params = {'missing': float('nan'), 'other': [float('inf')]}
        encoded = json.dumps(json_safe(params), allow_nan=False)
        self.assertEqual(json.loads(encoded)['missing'], 'nan')


if __name__ == '__main__':
    unittest.main()
