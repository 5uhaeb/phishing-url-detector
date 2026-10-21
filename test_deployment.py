"""Verify the API boundary when frontend and backend use separate hosts."""
import unittest
import tempfile
import gc
from pathlib import Path
from unittest.mock import patch

import joblib
import numpy as np
import app as application
from detector import analyze
from prepare_runtime import prepare


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        application.limiter.reset()
        self.client = application.app.test_client()
        self.origins = patch.object(application, 'frontend_origins', {'https://linkguard.vercel.app'})
        self.origins.start()
        self.addCleanup(self.origins.stop)

    def test_deployed_frontend_can_submit_and_read_api_result(self):
        headers = {'Origin': 'https://linkguard.vercel.app', 'Sec-Fetch-Site': 'cross-site'}
        response = self.client.post('/api/predict', json={'url': 'https://example.com'}, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('prediction', response.json)
        self.assertEqual(response.headers['Access-Control-Allow-Origin'], headers['Origin'])
        self.assertIn('Origin', response.headers['Vary'])

    def test_preflight_allows_only_explicit_frontend_origin(self):
        for origin, allowed in [('https://linkguard.vercel.app', True),
                                ('https://attacker.vercel.app', False),
                                ('https://linkguard.vercel.app.evil.example', False)]:
            response = self.client.options('/api/predict', headers={
                'Origin': origin, 'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type'})
            self.assertEqual('Access-Control-Allow-Origin' in response.headers, allowed)
            if allowed:
                self.assertIn('POST', response.headers['Access-Control-Allow-Methods'])
                self.assertEqual(response.headers['Access-Control-Allow-Headers'], 'Content-Type')

    def test_trusted_frontend_does_not_relax_html_form_protection(self):
        response = self.client.post('/', data={'url': 'https://example.com'}, headers={
            'Origin': 'https://linkguard.vercel.app', 'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(response.status_code, 403)

    def test_untrusted_frontend_still_cannot_submit(self):
        response = self.client.post('/api/predict', json={'url': 'https://example.com'}, headers={
            'Origin': 'https://attacker.vercel.app', 'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('Access-Control-Allow-Origin', response.headers)

    def test_status_does_not_expose_credentials_and_handles_missing_model(self):
        with patch.object(application, 'artifact', None):
            response = self.client.get('/api/status')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json['model_ready'])
        self.assertIsInstance(response.json['reputation_configured'], bool)
        self.assertEqual(set(response.json), {'model_ready', 'reputation_configured', 'public_feeds'})

    def test_runtime_artifact_preserves_scores_and_full_research_model(self):
        source = application.ROOT / 'model.joblib'
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'runtime.joblib'
            prepare(source, destination)
            runtime = joblib.load(destination, mmap_mode='r')
            self.assertNotIn('development_group_hashes', runtime)
            self.assertIn('development_group_hashes', application.artifact)
            for url in ['https://example.com', 'http://192.0.2.1/verify/account',
                        'https://trusted.com@evil.example/login',
                        'https://example.com/' + 'a' * 250]:
                self.assertEqual(analyze(url, runtime), analyze(url, application.artifact))
            model = runtime['model']
            rng = np.random.default_rng(79)
            splits = np.flatnonzero(model.features >= 0)
            chosen = rng.choice(splits, size=512, replace=False)
            probes = rng.uniform(0, 1000, (512, model.n_features_in_))
            for row, node in enumerate(chosen):
                probes[row, model.features[node]] = model.thresholds[node]
            below, above = probes.copy(), probes.copy()
            for row, node in enumerate(chosen):
                feature = model.features[node]
                below[row, feature] = np.nextafter(np.float32(model.thresholds[node]), np.float32(-np.inf))
                above[row, feature] = np.nextafter(np.float32(model.thresholds[node]), np.float32(np.inf))
            vectors = np.concatenate((probes, below, above))
            np.testing.assert_allclose(model.predict_proba(vectors),
                                       application.artifact['model'].predict_proba(vectors),
                                       rtol=0, atol=1e-12)
            del model
            del runtime
            gc.collect()  # Release file mappings before Windows removes the fixture.

    def test_runtime_packing_never_overwrites_research_model(self):
        with self.assertRaises(ValueError):
            prepare(application.ROOT / 'model.joblib', application.ROOT / 'model.joblib')


if __name__ == '__main__':
    unittest.main()
