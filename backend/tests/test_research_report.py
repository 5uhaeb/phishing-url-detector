import unittest

import numpy as np

from research_report import bootstrap


class BootstrapTests(unittest.TestCase):
    def test_perfect_predictions_remain_perfect_when_domains_resampled(self):
        y = np.array([0, 1, 0, 1])
        result = bootstrap(y, y, np.array(['a', 'a', 'b', 'b']), repeats=100)
        for metric in ['accuracy', 'precision', 'recall', 'f1']:
            self.assertEqual(result[metric], [1., 1.])
        self.assertEqual(result['false_positive_rate'], [0., 0.])

    def test_one_domain_is_resampled_as_one_cluster(self):
        result = bootstrap(np.array([0, 0, 1, 1]), np.array([0, 1, 0, 1]),
                           np.array(['same']*4), repeats=100)
        for bounds in result.values():
            self.assertEqual(bounds, [.5, .5])
