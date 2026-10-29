"""Provider and public-feed behavior, using local fixtures only."""
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import requests
from feeds import FeedStore, canonical_url
from reputation import ReputationClient, combine_evidence, ENDPOINT


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
        self.source = {'fixture': dict(name='Fixture', url='https://feed.example/list.txt',
                                      terms='fixture', license='fixture', ttl_hours=24)}
        sources = patch('feeds.SOURCES', self.source)
        sources.start()
        self.addCleanup(sources.stop)
        environment = patch.dict('os.environ', {'PUBLIC_FEED_KEYS': 'fixture'})
        environment.start()
        self.addCleanup(environment.stop)
        self.store = FeedStore(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def refresh_fixture(self, content=b'https://phish.example/login\nhttps://other.example/a\n'):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.iter_content.return_value = [content]
        with patch('feeds.requests.get', return_value=response) as get:
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
        with patch('feeds.requests.get', return_value=response):
            self.assertEqual(self.store.refresh()[0]['status'], 'unavailable')
        self.assertEqual(self.store.lookup('https://phish.example/login')['status'], 'match')

    def test_missing_feed_is_not_a_negative_reputation_verdict(self):
        self.assertEqual(self.store.lookup('https://example.com')['status'], 'missing')

    def test_canonicalization_preserves_destination_and_fragment_distinctions(self):
        self.assertEqual(canonical_url('HTTPS://EXAMPLE.COM:443'), canonical_url('https://example.com/'))
        self.assertNotEqual(canonical_url('https://www.example.com'), canonical_url('https://example.com'))
        self.assertNotEqual(canonical_url('https://example.com/#one'), canonical_url('https://example.com/#two'))
        self.assertNotEqual(canonical_url('https://example.com/a?token=A'), canonical_url('https://example.com/a?token=a'))
