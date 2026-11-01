import unittest

import numpy as np

from detector import FEATURE_NAMES, analyze, extract_features, rule_evidence, evaluate_rules
from reputation import combine_evidence


class FixedModel:
    classes_ = np.array([0, 1])

    def predict_proba(self, values):
        return np.tile([.15930, .84070], (len(values), 1))


class DecisionPolicyTests(unittest.TestCase):
    def test_display_rounding_cannot_promote_below_threshold_url(self):
        artifact = dict(model=FixedModel(), threshold=.840765, model_weight=1.,
                        trained_at='fixture', model_name='fixture')
        local = analyze('https://example.com/', artifact)
        self.assertEqual(local['hybrid_score'], local['threshold'])
        result = combine_evidence(local, {'status': 'not_requested'})
        self.assertFalse(result['local_is_phishing'])
        self.assertEqual(result['prediction'], 'Needs review')
        self.assertEqual(result['risk'], 'Medium')

    def test_rule_evidence_accounts_for_capped_rule_index(self):
        _, features, _ = extract_features('http://user@127.0.0.1:8080/login/verify/'+'9'*170)
        evidence = rule_evidence(features)
        self.assertTrue(all({'id','severity','description','evidence','contribution'} <= set(r) for r in evidence))
        self.assertEqual(len({r['id'] for r in evidence}), len(evidence))
        self.assertAlmostEqual(sum(r['contribution'] for r in evidence), evaluate_rules(features)[0])

    def test_destination_parsing_and_unusual_valid_urls(self):
        for url in ['https://faß.de/login', 'https://[2001:db8::1]:443/a%20b',
                    'https://paypal.com@evil.example/login', 'https://example.com/?next=https%3A%2F%2Fother.example']:
            _, features, group = extract_features(url)
            self.assertTrue(np.isfinite([features[n] for n in FEATURE_NAMES]).all())
        self.assertEqual(extract_features('https://paypal.com@evil.example/login')[2], 'evil.example')
        for url in ['https://example.com/%ZZ', 'https://example.com\\@evil.example/', 'https://[broken]/']:
            with self.assertRaises(ValueError): extract_features(url)
