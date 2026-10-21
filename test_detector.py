"""Run after training: python -m unittest -v."""

import unittest
import json
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import requests

from detector import analyze, evaluate_rules, extract_features
import app as application
from reputation import ReputationClient, combine_evidence, ENDPOINT
from feeds import FeedStore, canonical_url


class DetectorTests(unittest.TestCase):
    def setUp(self):
        application.limiter.reset()
    def test_invalid_inputs(self):
        for value in ('', None, 12, 'example.com', 'javascript:alert(1)',
                      'https://', 'https://example.com:99999', 'https://bad host.com',
                      'https://example.com\\@evil.com', 'https://-bad.example', 'x' * 4097):
            with self.subTest(value=value), self.assertRaises(ValueError):
                extract_features(value)

    def test_actual_host_and_domain_group(self):
        _, features, group = extract_features('https://trusted.com@evil.example/login')
        self.assertEqual(group, 'evil.example')
        self.assertEqual(features['ats'], 1)
        self.assertEqual(extract_features('https://a.b.example.co.uk/path')[2], 'example.co.uk')
        self.assertNotEqual(extract_features('https://alice.blogspot.com')[2],
                            extract_features('https://bob.blogspot.com')[2])

    def test_normalization_and_unicode(self):
        a = extract_features('HTTPS://EXAMPLE.COM#fragment')[0]
        b = extract_features('https://example.com/')[0]
        self.assertEqual(a, b)
        self.assertEqual(extract_features('https://bücher.de')[1]['punycode'], 1)
        self.assertEqual(extract_features('https://faß.de')[2], 'xn--fa-hia.de')

    def test_www_collection_style_does_not_change_features(self):
        for first, second in [('https://example.com/path', 'https://www.example.com/path'),
                              ('https://a.example.com/login', 'https://www.a.example.com/login')]:
            self.assertEqual(extract_features(first)[1], extract_features(second)[1])
        self.assertEqual(extract_features('https://www.example.com')[0], 'https://www.example.com/')

    def test_ip_rules_and_https(self):
        _, features, _ = extract_features('http://192.0.2.1/verify/account')
        score, reasons = evaluate_rules(features)
        self.assertGreaterEqual(score, .5)
        self.assertTrue(any('IP address' in reason for reason in reasons))
        self.assertEqual(extract_features('https://[2001:db8::1]/')[1]['ip_hostname'], 1)
        _, secure, _ = extract_features('https://example.com')
        self.assertFalse(any('HTTP rather' in reason for reason in evaluate_rules(secure)[1]))

    def test_model_missing_is_explicit(self):
        with patch.object(application, 'artifact', None):
            client = application.app.test_client()
            self.assertEqual(client.get('/health').status_code, 503)
            response = client.post('/api/predict', json={'url': 'https://example.com'})
            self.assertEqual(response.status_code, 503)

    def test_downloaded_report_and_invalid_download(self):
        self.assertIsNotNone(application.artifact)
        client = application.app.test_client()
        response = client.post('/report', data={'url': 'https://example.com'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/json')
        self.assertIn('attachment;', response.headers['Content-Disposition'])
        self.assertEqual(response.json['prediction'],
                         client.post('/api/predict', json={'url': 'https://example.com'}).json['prediction'])
        self.assertEqual(client.post('/report', data={'url': 'invalid'}).status_code, 400)

    def test_oversized_requests_have_useful_errors(self):
        client = application.app.test_client()
        response = client.post('/api/predict', json={'url': 'x' * 20000})
        self.assertEqual(response.status_code, 413)
        self.assertIn('Input is too large', response.json['error'])
        page = client.post('/', data={'url': 'x' * 20000})
        self.assertEqual(page.status_code, 413)
        self.assertIn(b'Input is too large', page.data)

    def test_trained_model_and_api_work_without_network(self):
        self.assertIsNotNone(application.artifact, 'Train the model before integration tests.')
        client = application.app.test_client()
        with patch('socket.socket.connect', side_effect=AssertionError('Network access attempted')):
            response = client.post('/api/predict', json={'url': 'https://example.com'})
            self.assertEqual(response.status_code, 200)
            self.assertIn(response.json['risk'], ('Low', 'Medium', 'High', 'Unknown'))
            self.assertEqual(response.json['local_prediction'], analyze('https://example.com', application.artifact)['prediction'])
            self.assertEqual(client.get('/health').status_code, 200)
            self.assertEqual(client.get('/').status_code, 200)
            self.assertEqual(client.post('/api/predict', json=[]).status_code, 400)
            self.assertEqual(client.post('/api/predict', json={'url': None}).status_code, 400)
            page = client.post('/', data={'url': 'https://example.com/<script>alert(1)</script>'})
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'&lt;script&gt;', page.data)
            self.assertNotIn(b'<script>alert(1)</script>', page.data)
            self.assertEqual(page.headers['Cache-Control'], 'no-store')

    def test_consent_is_boolean_and_never_inferred(self):
        client = application.app.test_client()
        for consent in ('false', 'true', 1, None):
            self.assertEqual(client.post('/api/predict', json={
                'url': 'https://example.com', 'consent': consent}).status_code, 400)
        with patch.object(application.reputation_client, 'lookup', wraps=application.reputation_client.lookup) as lookup:
            client.post('/api/predict', json={'url': 'https://example.com'})
            self.assertFalse(lookup.call_args.kwargs['consent'])

    def test_cross_site_checks_are_rejected(self):
        response = application.app.test_client().post('/api/predict',
            json={'url': 'https://example.com', 'consent': True}, headers={'Origin': 'https://evil.example'})
        self.assertEqual(response.status_code, 403)

    def test_same_origin_forms_allow_privacy_suppressed_origin(self):
        client = application.app.test_client()
        for host in ('http://127.0.0.1:5000', 'http://localhost:5000'):
            for origin in ('null', host):
                headers = {'Origin': origin, 'Sec-Fetch-Site': 'same-origin'}
                with self.subTest(host=host, origin=origin):
                    response = client.post('/', base_url=host, data={'url': 'https://example.com'}, headers=headers)
                    self.assertEqual(response.status_code, 200)
                    self.assertIn(b'Analyzed URL:', response.data)
                    self.assertEqual(response.headers['Referrer-Policy'], 'same-origin')
                    report = client.post('/report', base_url=host, data={'url': 'https://example.com'}, headers=headers)
                    self.assertEqual(report.status_code, 200)
                    self.assertIn('attachment;', report.headers['Content-Disposition'])

    def test_opaque_or_cross_site_requests_are_still_rejected(self):
        client = application.app.test_client()
        for headers in ({'Origin': 'null'},
                        {'Origin': 'null', 'Sec-Fetch-Site': 'cross-site'},
                        {'Origin': 'null', 'Sec-Fetch-Site': 'same-site'},
                        {'Origin': 'https://evil.example', 'Sec-Fetch-Site': 'same-origin'},
                        {'Origin': 'http://localhost', 'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                self.assertEqual(client.post('/api/predict', json={'url': 'https://example.com'}, headers=headers).status_code, 403)
        rejected_form = client.post('/', data={'url': 'https://example.com'}, headers={'Origin': 'null'})
        self.assertEqual(rejected_form.status_code, 403)
        self.assertEqual(rejected_form.mimetype, 'text/html')
        self.assertIn(b'Reload this page', rejected_form.data)

    def test_default_port_origins_are_compared_by_origin(self):
        client = application.app.test_client()
        response = client.post('/api/predict', json={'url': 'https://example.com'},
                               headers={'Origin': 'http://localhost:80', 'Sec-Fetch-Site': 'same-origin'})
        self.assertEqual(response.status_code, 200)

    def test_local_server_rejects_untrusted_host_headers(self):
        response = application.app.test_client().post('/api/predict',
            base_url='http://evil.example:5000', json={'url': 'https://example.com'},
            headers={'Origin': 'http://evil.example:5000', 'Sec-Fetch-Site': 'same-origin'})
        self.assertEqual(response.status_code, 400)

    def test_fresh_feed_match_overrides_low_model_and_negative_external_lookup(self):
        match = dict(provider='Fixture feed', status='match', threats=['SOCIAL_ENGINEERING'],
                     sources=[], message='Fixture threat report')
        with patch.object(application.feed_store, 'lookup', return_value=match):
            result = self.client_result('https://example.com')
        self.assertEqual(result['prediction'], 'Known phishing threat')
        self.assertEqual(result['risk'], 'High')
        self.assertEqual(result['public_feeds']['provider'], 'Fixture feed')

    def client_result(self, value):
        response = application.app.test_client().post('/api/predict', json={'url': value})
        self.assertEqual(response.status_code, 200)
        return response.json

    def test_obvious_attack_patterns_raise_local_warnings(self):
        for url in ('http://paypal.com@192.0.2.10/verify-account',
                    'http://secure-bank-login.verify-account.test/update-password',
                    'http://microsoft-password-reset.security-alert.test/login',
                    'http://192.0.2.25/banking/confirm-password?account=123456789',
                    'https://google.com.account-verification.test/signin'):
            with self.subTest(url=url):
                result = self.client_result(url)
                self.assertIn(result['risk'], ('High', 'Medium'))
                self.assertTrue(result['indicators'])

    def test_ordinary_real_urls_are_not_marked_high_just_for_having_paths(self):
        # Curated regression examples, not a measured production accuracy dataset.
        urls = ('https://youtube.com', 'https://www.youtube.com',
                'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
                'https://github.com/Kinzalune/Phishing-URL-Detection',
                'https://github.com/openai/codex', 'https://github.com/openphish/public_feed',
                'https://www.wikipedia.org', 'https://en.wikipedia.org/wiki/Phishing',
                'https://accounts.google.com/signin', 'https://docs.python.org/3/',
                'https://www.microsoft.com', 'https://www.amazon.in',
                'https://www.paypal.com/signin')
        for url in urls:
            with self.subTest(url=url):
                result = self.client_result(url)
                self.assertNotEqual(result['risk'], 'High', result)
                self.assertIn('verification', result)

    def test_low_local_risk_is_separate_from_verification(self):
        result = self.client_result('https://youtube.com')
        self.assertEqual(result['risk'], 'Low')
        self.assertIn('verification', result)
        self.assertNotIn('safe', result['prediction'].lower())

    def test_evaluation_export(self):
        response = application.app.test_client().get('/evaluation')
        self.assertEqual(response.status_code, 200)
        self.assertIn('attachment;', response.headers['Content-Disposition'])
        self.assertIn('test_results', response.json['model'])

    def test_rate_limit_is_shared_across_analysis_routes(self):
        client = application.app.test_client()
        for _ in range(30):
            self.assertEqual(client.post('/api/predict', json={'url': ''}).status_code, 400)
        response = client.post('/api/predict', json={'url': ''})
        self.assertEqual(response.status_code, 429)
        self.assertIn('Retry-After', response.headers)
        self.assertEqual(client.post('/report', data={'url': ''}).status_code, 429)
        self.assertEqual(client.get('/health').status_code, 200)


class ReputationTests(unittest.TestCase):
    def setUp(self):
        self.client = ReputationClient('test-key')

    def response(self, body, status=200):
        response = MagicMock()
        response.status_code = status
        response.json.return_value = body
        return response

    def match(self, threats=None, minutes=5):
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()
        return {'threat': {'threatTypes': threats or ['SOCIAL_ENGINEERING'], 'expireTime': expiry}}

    def test_no_consent_means_no_request_even_with_configured_key(self):
        with patch('reputation.requests.get') as get:
            for consent in (False, 'true', 1, None):
                self.assertEqual(self.client.lookup('https://example.com', consent)['status'], 'not_requested')
            get.assert_not_called()

    def test_missing_key_and_sensitive_urls_are_not_sent(self):
        with patch('reputation.requests.get') as get:
            self.assertEqual(ReputationClient('').lookup('https://example.com', True)['status'], 'not_configured')
            for url in ('https://user:password@example.com', 'https://127.0.0.1',
                        'https://[::1]', 'https://company.internal', 'https://reserved.test'):
                self.assertEqual(self.client.lookup(url, True)['status'], 'skipped')
            get.assert_not_called()

    def test_match_uses_fixed_endpoint_and_cache_requires_consent(self):
        with patch('reputation.requests.get', return_value=self.response(self.match())) as get:
            result = self.client.lookup('https://example.com', True)
            self.assertEqual(result['status'], 'match')
            self.assertEqual(get.call_args.args[0], ENDPOINT)
            self.assertFalse(get.call_args.kwargs['allow_redirects'])
            self.assertEqual(get.call_args.kwargs['headers']['X-Goog-Api-Key'], 'test-key')
            self.assertTrue(self.client.lookup('https://example.com', True)['cached'])
            self.assertEqual(self.client.lookup('https://example.com', False)['status'], 'not_requested')
            self.assertEqual(get.call_count, 1)

    def test_empty_response_is_no_match_not_safe(self):
        with patch('reputation.requests.get', return_value=self.response({})):
            result = self.client.lookup('https://example.com', True)
            self.assertEqual(result['status'], 'no_match')
            self.assertIn('Safety is not established', result['message'])

    def test_failures_and_bad_responses_never_become_clean_results(self):
        bodies = [[], {'error': 'bad request'}, {'threat': {}}, self.match(minutes=-1),
                  self.match(threats=['UNKNOWN'])]
        for body in bodies:
            with self.subTest(body=body), patch('reputation.requests.get', return_value=self.response(body)):
                result = ReputationClient('key').lookup('https://example.com', True)
                self.assertEqual(result['status'], 'unavailable')
        for status in (302, 403, 429, 500):
            with patch('reputation.requests.get', return_value=self.response({}, status)):
                self.assertEqual(ReputationClient('key').lookup('https://example.com', True)['status'], 'unavailable')
        with patch('reputation.requests.get', side_effect=requests.Timeout('secret url')) as get:
            for _ in range(4):
                result = self.client.lookup('https://example.com', True)
                self.assertEqual(result['status'], 'unavailable')
                self.assertNotIn('secret', result['message'])
            self.assertEqual(get.call_count, 3)

    def test_cached_match_expiry(self):
        with patch('reputation.requests.get', return_value=self.response(self.match())) as get:
            self.client.lookup('https://example.com', True)
            digest = next(iter(self.client.cache))
            _, result = self.client.cache[digest]
            self.client.cache[digest] = (0, result)
            self.client.lookup('https://example.com', True)
            self.assertEqual(get.call_count, 2)

    def test_evidence_precedence_and_uncertainty(self):
        low = dict(prediction='Potentially legitimate', hybrid_score=5, threshold=50, risk='Low')
        high = dict(low, hybrid_score=90, prediction='Potential phishing', risk='High')
        for status in ('not_requested', 'not_configured', 'unavailable', 'skipped'):
            result = combine_evidence(low, {'status': status, 'threats': []})
            self.assertEqual(result['risk'], 'Low')
            self.assertIn('verification', result)
        negative = {'status': 'no_match', 'threats': []}
        self.assertEqual(combine_evidence(high, negative)['prediction'], 'Suspicious URL')
        self.assertEqual(combine_evidence(low, negative)['prediction'], 'No known threat found')
        positive = {'status': 'match', 'threats': ['SOCIAL_ENGINEERING']}
        self.assertEqual(combine_evidence(low, positive)['prediction'], 'Known phishing threat')
        self.assertEqual(combine_evidence(low, {'status': 'match', 'threats': ['MALWARE']})['prediction'], 'Known malicious URL')
        self.assertEqual(combine_evidence(dict(low, hybrid_score=45), negative)['prediction'], 'Needs review')


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FeedStore(self.temp.name)
        self.source = {'fixture': dict(name='Fixture', url='https://feed.example/list.txt',
                                      terms='fixture', license='fixture', ttl_hours=24)}

    def tearDown(self):
        self.temp.cleanup()

    def refresh_fixture(self, content=b'https://phish.example/login\nhttps://other.example/a\n'):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.iter_content.return_value = [content]
        with patch('feeds.SOURCES', self.source), patch('feeds.requests.get', return_value=response) as get:
            result = self.store.refresh()
            self.assertEqual(result[0]['status'], 'updated')
            self.assertEqual(get.call_args.args[0], self.source['fixture']['url'])
            self.assertFalse(get.call_args.kwargs['allow_redirects'])

    def test_matching_is_exact_not_a_whole_domain_block(self):
        self.refresh_fixture()
        self.assertEqual(self.store.lookup('https://phish.example/login')['status'], 'match')
        self.assertNotEqual(self.store.lookup('https://phish.example/innocent')['status'], 'match')
        self.assertNotEqual(self.store.lookup('https://phish.example.attacker.test/login')['status'], 'match')

    def test_expired_feed_cannot_supply_a_current_match(self):
        self.refresh_fixture()
        with closing(sqlite3.connect(self.store.database)) as db, db:
            metadata = json.loads(db.execute('SELECT metadata FROM sources').fetchone()[0])
            metadata['fetched_at'] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
            db.execute('UPDATE sources SET metadata=?', (json.dumps(metadata),))
        self.assertEqual(self.store.lookup('https://phish.example/login')['status'], 'stale_match')

    def test_failed_or_html_refresh_keeps_previous_valid_data(self):
        self.refresh_fixture()
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.iter_content.return_value = [b'<html>Access denied</html>']
        with patch('feeds.SOURCES', self.source), patch('feeds.requests.get', return_value=response):
            self.assertEqual(self.store.refresh()[0]['status'], 'unavailable')
        self.assertEqual(self.store.lookup('https://phish.example/login')['status'], 'match')

    def test_missing_feed_is_not_a_negative_reputation_verdict(self):
        self.assertEqual(self.store.lookup('https://example.com')['status'], 'missing')

    def test_canonicalization_preserves_destination_and_fragment_distinctions(self):
        self.assertEqual(canonical_url('HTTPS://EXAMPLE.COM:443'), canonical_url('https://example.com/'))
        self.assertNotEqual(canonical_url('https://www.example.com'), canonical_url('https://example.com'))
        self.assertNotEqual(canonical_url('https://example.com/#one'), canonical_url('https://example.com/#two'))
        self.assertNotEqual(canonical_url('https://example.com/a?token=A'), canonical_url('https://example.com/a?token=a'))


if __name__ == '__main__':
    unittest.main()
