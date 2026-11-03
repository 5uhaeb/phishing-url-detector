"""Research protocol checks; no benchmark scores are fixtures."""
import importlib.util
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from detector import FEATURE_NAMES, extract_features
from lexical_features import RichUrlFeatures, canonical_text, numeric_features


def benchmark_module():
    path = Path(__file__).resolve().parents[2] / 'tools' / 'fresh_benchmark.py'
    spec = importlib.util.spec_from_file_location('fresh_benchmark', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FreshExperimentTests(unittest.TestCase):
    def test_www_invariance_covers_numeric_and_text_features(self):
        urls = ['https://example.org/a/login?next=%2Fhome',
                'http://other.example.net:8080/security-confirm/123?x=ab',
                'https://account.example.com/path/with_opaque-12345']
        for first in urls:
            second = first.replace('://', '://www.', 1)
            self.assertEqual(canonical_text(first), canonical_text(second))
            np.testing.assert_array_equal(numeric_features(first), numeric_features(second))

    def test_feature_vocabulary_does_not_learn_future_inputs(self):
        urls = [f'https://training-{i}.example.com/login?account={i}' for i in range(12)]
        labels = np.array([0,1]*6)
        features = RichUrlFeatures(char_features=30, word_features=10).fit(urls,labels)
        before = dict(features.word_vectorizer_.vocabulary_)
        features.transform(['https://neverobservedfutureword.example.net/zzzz'])
        self.assertEqual(before,features.word_vectorizer_.vocabulary_)
        self.assertNotIn('neverobservedfutureword',before)
        original = features.transform([urls[0]])
        changed = features.transform([urls[0].replace('://','://www.',1)])
        self.assertEqual((original != changed).nnz,0)

    def test_rich_features_retain_shared_32_in_order(self):
        url='https://example.org/login?id=12'
        _,base,_=extract_features(url)
        np.testing.assert_allclose(numeric_features(url)[:32],[base[k] for k in FEATURE_NAMES],rtol=1e-6)

    def test_threshold_selection_uses_worst_metric(self):
        module=benchmark_module()
        labels=np.array([0,0,0,0,1,1,1,1])
        scores=np.array([.1,.2,.3,.65,.4,.6,.8,.9])
        threshold=module.target_threshold(labels,scores)
        measured=module.metrics(labels,scores>=threshold)
        achieved=min(measured[k] for k in ('accuracy','precision','recall','f1'))
        for value in np.unique(scores):
            alternative=module.metrics(labels,scores>=value)
            self.assertGreaterEqual(achieved,min(alternative[k] for k in ('accuracy','precision','recall','f1')))

    def test_group_bootstrap_counts_perfect_predictions_correctly(self):
        module=benchmark_module()
        labels=np.array([0,1,0,1,0,1])
        ci=module.confidence(labels,labels,np.array(['a','a','b','b','c','c']),resamples=20)
        self.assertEqual(ci['accuracy'],[1.,1.])
        self.assertEqual(ci['false_positive_rate'],[0.,0.])


if __name__=='__main__': unittest.main()
