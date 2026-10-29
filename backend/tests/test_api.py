"""The JSON API stays compatible with the separate frontend."""
import unittest
from unittest.mock import patch

import main


class ApiTests(unittest.TestCase):
    def setUp(self):
        main.limiter.reset()
        self.client = main.app.test_client()
        origins = patch.object(main, 'frontend_origins', {'https://linkguard.vercel.app'})
        origins.start()
        self.addCleanup(origins.stop)

    def test_health_status_and_comparison(self):
        self.assertEqual(self.client.get('/health').json['model_name'], 'XGBoost')
        self.assertTrue(self.client.get('/api/status').json['model_ready'])
        comparison = self.client.get('/api/models')
        self.assertEqual(comparison.status_code, 200)
        self.assertEqual(set(comparison.json['models']), set(main.MODEL_NAMES))
        self.assertEqual(self.client.get('/evaluation').json['trained_at'], main.artifact['trained_at'])

    def test_prediction_works_without_network(self):
        with patch('socket.socket.connect', side_effect=AssertionError('Network attempted')):
            response = self.client.post('/api/predict', json={'url': 'https://github.com/openai/codex'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['model_name'], 'XGBoost')
        self.assertNotEqual(response.json['risk'], 'High')
        self.assertIn('verification', response.json)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_invalid_payloads_and_oversized_body(self):
        for body in [[], None, {'url': None}, {'url': 'invalid'}, {'url': 'https://example.com', 'consent': 'false'}]:
            with self.subTest(body=body):
                self.assertEqual(self.client.post('/api/predict', json=body).status_code, 400)
        response = self.client.post('/api/predict', json={'url': 'x' * 20000})
        self.assertEqual(response.status_code, 413)
        self.assertIn('error', response.json)

    def test_cors_only_allows_the_configured_frontend(self):
        for origin, expected in [('https://linkguard.vercel.app', 200), ('https://attacker.vercel.app', 403)]:
            response = self.client.post('/api/predict', json={'url': 'https://example.com'},
                                         headers={'Origin': origin, 'Sec-Fetch-Site': 'cross-site'})
            self.assertEqual(response.status_code, expected)
            self.assertEqual('Access-Control-Allow-Origin' in response.headers, expected == 200)
        response = self.client.options('/api/predict', headers={'Origin': 'https://linkguard.vercel.app'})
        self.assertIn('POST', response.headers['Access-Control-Allow-Methods'])

    def test_opaque_and_malformed_origins_are_rejected(self):
        for origin in ['null', 'http://localhost/path', 'http://user@localhost', 'http://localhost:99999']:
            response = self.client.post('/api/predict', json={'url': 'https://example.com'}, headers={'Origin': origin})
            self.assertEqual(response.status_code, 403)

    def test_consent_is_never_inferred(self):
        with patch.object(main.reputation_client, 'lookup', wraps=main.reputation_client.lookup) as lookup:
            self.client.post('/api/predict', json={'url': 'https://example.com'})
            self.assertFalse(lookup.call_args.kwargs['consent'])

    def test_feed_match_overrides_low_model_score(self):
        match = dict(status='match', provider='Fixture', threats=['SOCIAL_ENGINEERING'], sources=[], message='Fixture')
        with patch.object(main.feed_store, 'lookup', return_value=match):
            response = self.client.post('/api/predict', json={'url': 'https://example.com'})
        self.assertEqual(response.json['risk'], 'High')
        self.assertEqual(response.json['prediction'], 'Known phishing threat')

    def test_missing_model_and_stale_report_are_explicit(self):
        with patch.object(main, 'artifact', None):
            self.assertEqual(self.client.get('/health').status_code, 503)
            self.assertEqual(self.client.post('/api/predict', json={'url': 'https://example.com'}).status_code, 503)
        with patch.object(main, 'read_report', return_value={'trained_at': 'old'}):
            self.assertEqual(self.client.get('/api/models').status_code, 503)
            self.assertEqual(self.client.get('/evaluation').status_code, 503)

    def test_rate_limit_returns_json_and_retry_header(self):
        for _ in range(30):
            self.assertEqual(self.client.post('/api/predict', json={'url': 'invalid'}).status_code, 400)
        response = self.client.post('/api/predict', json={'url': 'invalid'})
        self.assertEqual(response.status_code, 429)
        self.assertIn('error', response.json)
        self.assertIn('Retry-After', response.headers)
        self.assertEqual(self.client.get('/health').status_code, 200)


if __name__ == '__main__':
    unittest.main()
