import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from phishing_benchmark import clean, final, partition, policies
from research_features import FEATURES, features


class PhishingBenchmarkTests(unittest.TestCase):
    def test_recent_cohort_accepts_mixed_date_and_iso_timestamp(self):
        dates=pd.to_datetime(['2025-09-08','2026-11-01T10:31:33+00:00',None],format='mixed',errors='coerce',utc=True)
        recent=dates>=pd.Timestamp('2026-10-02',tz='UTC')
        np.testing.assert_array_equal(recent,[False,True,False])

    def test_cleaning_preserves_types_and_removes_cross_type_conflicts(self):
        records = [dict(url=u, kind=k, source='fixture', collected_at=None) for u,k in [
            ('https://example.com:443/a',0), ('https://EXAMPLE.com/a',0),
            ('https://bad.example/a',1), ('https://bad.example/a',2),
            ('https://other.example/#login',1), ('https://other.example/#profile',1)]]
        frame,x,info=clean(records)
        self.assertEqual(len(frame),3)
        self.assertEqual(info['conflicting_urls'],1)
        self.assertEqual(info['duplicate_rows'],1)
        self.assertEqual(frame.url.str.contains('#').sum(),2)
        self.assertEqual(x.shape,(3,len(FEATURES)))

    def test_idna_views_and_fragments_are_inference_stable(self):
        first=features('https://faß.de/#login')
        second=features(first[0])
        self.assertEqual(first[:3],second[:3])
        np.testing.assert_array_equal(first[3],second[3])
        self.assertIn('#login',first[2])
        self.assertNotEqual(first[2],features('https://faß.de/#profile')[2])
        self.assertIn('user@',features('https://user@example.com/')[2])

    def test_threshold_constraints_and_final_reuse_guard(self):
        y=np.array([0,0,1,1]);p=np.array([.1,.6,.7,.9])
        thresholds=policies(y,p)
        self.assertGreater(thresholds['fpr_1pct'],.6)
        self.assertEqual(partition('same.example'),partition('same.example'))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/'final_started.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'already started'):final(out)
