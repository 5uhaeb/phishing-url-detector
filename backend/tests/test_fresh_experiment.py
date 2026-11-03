"""Research protocol checks; no benchmark scores are fixtures."""
import importlib.util
from pathlib import Path
import unittest
import sys
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from detector import FEATURE_NAMES, extract_features
from lexical_features import RichUrlFeatures, LatentUrlFeatures, canonical_text, numeric_features


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

    def test_parser_preserves_valid_ip_rows(self):
        module=benchmark_module()
        records,vectors,invalid=module.parse_batch(('train',[
            ('https://170.205.31.135/login','phish','2025-01-01','a'*64),
            ('not a valid URL','benign','2025-01-01','b'*64)]))
        self.assertEqual(len(records),1)
        self.assertEqual(records[0]['group'],'170.205.31.135')
        self.assertEqual(vectors[0][FEATURE_NAMES.index('ip_hostname')],1)
        self.assertEqual(invalid,1)

    def test_final_test_cannot_be_reopened(self):
        module=benchmark_module()
        with TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'test_opened.json').write_text('{}',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'already started'):
                module.final(root)

    def test_latent_factors_preserve_numeric_features_and_www_invariance(self):
        urls=[f'https://training-{i}.example.com/'+('account-confirm' if i%2 else 'community-guide')
              for i in range(12)]
        rich=RichUrlFeatures(char_features=30,word_features=10).fit(urls,np.array([0,1]*6))
        matrix=rich.transform(urls)
        latent=LatentUrlFeatures(n_components=4,sample_rows=10).fit_matrix(matrix,rich)
        transformed=latent.transform(urls[:1])
        self.assertTrue(np.isfinite(transformed).all())
        np.testing.assert_array_equal(transformed[0,:32],numeric_features(urls[0])[:32])
        np.testing.assert_array_equal(transformed,latent.transform([urls[0].replace('://','://www.',1)]))


if __name__=='__main__': unittest.main()
