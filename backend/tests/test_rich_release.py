"""Production must preserve the frozen research transform and decision policy."""
import unittest
from unittest.mock import patch

import numpy as np

import main
from detector import analyze


class RichReleaseTests(unittest.TestCase):
    def setUp(self):
        main.limiter.reset()

    def test_api_uses_full_fitted_transform_and_frozen_threshold(self):
        artifact=main.artifact
        self.assertEqual(artifact['input_mode'],'rich_url_v1')
        self.assertEqual(artifact['model_identifier'],'xgboost_domain')
        self.assertEqual(artifact['model_weight'],1.)
        self.assertAlmostEqual(artifact['threshold'],.5800396476112477,places=15)
        urls=['https://github.com/5uhaeb','https://github.com/openai/codex',
              'https://example.com/','http://user@127.0.0.1/login/verify']
        scores=artifact['model'].predict_proba(artifact['url_transformer'].transform(urls))[:,1]
        with patch.object(main.feed_store,'lookup',return_value={
            'status':'not_listed','provider':'Fixture','sources':[],'threats':[],'message':'Fixture'}), \
             patch.object(main.reputation_client,'lookup',return_value={'status':'not_requested','threats':[]}):
            for url,score in zip(urls,scores):
                with self.subTest(url=url):
                    response=main.app.test_client().post('/api/predict',json={'url':url})
                    self.assertEqual(response.status_code,200)
                    result=response.json
                    self.assertEqual(result['feature_pipeline'],'rich_url_v1')
                    self.assertEqual(result['model_score'],round(float(score)*100,1))
                    self.assertEqual(result['local_is_phishing'],bool(score>=artifact['threshold']))

    def test_www_cannot_change_live_model_score(self):
        artifact=main.artifact
        first=analyze('https://example.org/account?id=123',artifact)
        second=analyze('https://www.example.org/account?id=123',artifact)
        self.assertEqual(first['model_score'],second['model_score'])
        self.assertEqual(first['local_is_phishing'],second['local_is_phishing'])

    def test_loader_rejects_missing_transformer_and_unknown_mode(self):
        for updates in ({'url_transformer':None},{'input_mode':'unrecognized'}):
            with self.subTest(updates=updates),patch('main.joblib.load',return_value=dict(main.artifact,**updates)):
                with self.assertRaises(ValueError):main.load_model()

    def test_comparison_keeps_legacy_cohorts_explicit(self):
        report=main.read_report()
        self.assertEqual(report['trained_at'],main.artifact['trained_at'])
        self.assertEqual(report['models']['xgboost']['model_identifier'],'xgboost_domain')
        self.assertAlmostEqual(report['models']['xgboost']['test_results']['model']['accuracy'],.9246069443784733)
        for family in ('random_forest','lightgbm'):
            self.assertEqual(report['models'][family]['deployment_status'],'preserved legacy artifact')


if __name__=='__main__':unittest.main()
