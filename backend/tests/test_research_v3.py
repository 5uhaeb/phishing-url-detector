import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np

from research_data import RangeReader
from research_models import RESEARCH_FEATURES, domain_partition, url_features
from research_v3 import f1_threshold, test as evaluate_final_test


class ResearchProtocolTests(unittest.TestCase):
    def test_conventional_www_does_not_change_model_measurements(self):
        first = url_features('https://example.com/account/login?next=%2Fprofile')
        second = url_features('https://www.example.com/account/login?next=%2Fprofile')
        self.assertNotEqual(first[0], second[0])
        self.assertEqual(first[1:3], second[1:3])
        np.testing.assert_array_equal(first[3], second[3])

    def test_features_track_actual_destination_and_remain_finite(self):
        for value in ['https://trusted.com@evil.example/verify', 'https://[2001:db8::1]/',
                      'https://example.com/', 'https://example.com/a%20b?redirect=https%3A%2F%2Fother.example']:
            _, group, text, features = url_features(value)
            self.assertEqual(len(features), len(RESEARCH_FEATURES))
            self.assertTrue(np.isfinite(features).all())
        self.assertEqual(url_features('https://trusted.com@evil.example/verify')[1], 'evil.example')

    def test_same_registrable_domain_never_crosses_development_partitions(self):
        for first, second in [('https://a.example.com/', 'https://b.example.com/login'),
                              ('https://www.example.co.uk/', 'https://example.co.uk/path')]:
            a, b = url_features(first)[1], url_features(second)[1]
            self.assertEqual(a, b)
            self.assertEqual(domain_partition(a), domain_partition(b))
        self.assertNotEqual(url_features('https://alice.blogspot.com/')[1],
                            url_features('https://bob.blogspot.com/')[1])

    def test_final_test_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output/'final_test_started.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'already started'):
                evaluate_final_test(output)

    def test_balanced_threshold_is_fitted_from_supplied_validation_scores(self):
        labels = np.array([0, 0, 1, 1])
        scores = np.array([.1, .2, .8, .9])
        threshold = f1_threshold(labels, scores)
        np.testing.assert_array_equal(scores >= threshold, labels)

    def test_remote_reader_rejects_full_file_fallback(self):
        session = MagicMock()
        response = session.get.return_value.__enter__.return_value
        response.status_code = 200
        reader = RangeReader('https://example.com/test.parquet', 100, session)
        with self.assertRaisesRegex(ValueError, 'did not honor'):
            reader.read(10)
        self.assertEqual(reader.transferred, 0)
        self.assertEqual(reader.tell(), 0)

    def test_remote_reader_obeys_range_and_size_limit(self):
        session = MagicMock()
        response = session.get.return_value.__enter__.return_value
        response.status_code = 206
        response.headers = {'Content-Range':'bytes 0-2/100'}
        response.content = b'abc'
        reader = RangeReader('https://example.com/test.parquet', 100, session)
        self.assertEqual(reader.read(3), b'abc')
        self.assertEqual(reader.tell(), 3)
        self.assertEqual(session.get.call_args.kwargs['headers']['Range'], 'bytes=0-2')
        huge = RangeReader('https://example.com/large.parquet', 100*1024*1024, session)
        with self.assertRaisesRegex(ValueError, '32 MiB'):
            huge.read(33*1024*1024)
