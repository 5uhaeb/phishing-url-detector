import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

import pandas as pd
from flask import Flask

from dataset import load_dataset
from metrics import f1_threshold,metrics,tune_threshold

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from launcher import mount_frontend


class ClientDeliveryTests(unittest.TestCase):
    def test_launcher_serves_only_expected_frontend_assets(self):
        app=Flask('client-test');app.add_url_rule('/',endpoint='index',view_func=lambda:'API')
        mount_frontend(app,ROOT/'frontend');client=app.test_client()
        with client.get('/') as response:self.assertIn(b'LinkGuard',response.data)
        for path in ['/app.js','/style.css']:
            with client.get(path) as response:self.assertEqual(response.status_code,200)
        for path in ['/backend/models/xgboost.joblib','/.env','/../backend/main.py']:
            self.assertEqual(client.get(path).status_code,404)

    def test_explicit_dataset_labels_conflicts_and_bare_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.json'
            path.write_text(json.dumps([{'text':u,'label':y} for u,y in [
                ('legit.example/path',0),('legit.example/path',0),('phish.example/login',1),
                ('conflict.example/',0),('conflict.example/',1)]]))
            args=SimpleNamespace(dataset=path,infer_https=True,max_rows=0,positive_label=1,
                                 dataset_name='fixture',target_name='phishing')
            frame,source,*_=load_dataset(args)
            self.assertEqual(len(frame),2)
            self.assertEqual(set(frame.target),{0,1})
            self.assertEqual(source[0]['contradictory_urls'],1)
            self.assertEqual(source[0]['duplicates_removed'],1)
            self.assertTrue(frame.url.str.startswith('https://').all())
            path.write_text('[{"text":"https://a.example","label":2},{"text":"https://b.example","label":0}]')
            with self.assertRaises(ValueError):load_dataset(args)

    def test_balanced_and_conservative_policies_handle_tied_scores(self):
        labels=[0,1];scores=[.5,.5]
        balanced=f1_threshold(labels,scores)
        conservative=tune_threshold(labels,scores,.01)
        self.assertAlmostEqual(metrics(labels,[s>=balanced for s in scores])['recall'],1.)
        self.assertGreater(conservative,max(scores))
        with self.assertRaises(ValueError):f1_threshold([0,1],[float('nan'),.5])

    def test_client_score_csv_matches_exact_confusion_counts(self):
        frame=pd.read_csv(ROOT/'reports/model_scores.csv')
        self.assertEqual(len(frame),14)
        paired=frame[frame.benchmark=='independent_phishing']
        self.assertEqual(paired.cohort_sha256.nunique(),1)
        for row in frame.itertuples():
            self.assertEqual(row.tn+row.fp+row.fn+row.tp,row.test_rows)
            self.assertAlmostEqual(100*(row.tn+row.tp)/row.test_rows,row.accuracy_pct,places=7)
            self.assertAlmostEqual(100*row.fp/(row.tn+row.fp),row.false_positive_rate_pct,places=7)
