"""All three preserved models must load and retain their measured scores."""
import hashlib
import json
import unittest
from pathlib import Path

import joblib
import numpy as np

from detector import FEATURE_NAMES, analyze, extract_features

ROOT = Path(__file__).resolve().parents[1]


class ModelTests(unittest.TestCase):
    def test_all_three_models_match_the_manifest_and_feature_schema(self):
        manifest = json.loads((ROOT / 'models/manifest.json').read_text())
        self.assertEqual(set(manifest['models']), {'random_forest', 'xgboost', 'lightgbm'})
        for family, record in manifest['models'].items():
            with self.subTest(model=family):
                path = ROOT / 'models' / record['file']
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), record['sha256'])
                artifact = joblib.load(path)
                self.assertEqual(artifact['features'], list(FEATURE_NAMES))
                self.assertNotIn('development_group_hashes', artifact)
                result = analyze('https://example.com/account', artifact)
                self.assertEqual(result['model_name'], artifact['model_name'])
                self.assertTrue(np.isfinite(result['model_score']))

    def test_url_validation_and_domain_grouping(self):
        for value in ['', None, 'example.com', 'https://bad host.com', 'https://example.com:99999', 'https://-bad.example']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                extract_features(value)
        self.assertEqual(extract_features('https://a.b.example.co.uk/path')[2], 'example.co.uk')
        self.assertNotEqual(extract_features('https://alice.blogspot.com')[2], extract_features('https://bob.blogspot.com')[2])
        self.assertEqual(extract_features('https://example.com/path')[1], extract_features('https://www.example.com/path')[1])


if __name__ == '__main__':
    unittest.main()
