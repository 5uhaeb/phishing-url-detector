"""Feed ingestion must stay bounded and retain previous evidence on failure."""
import hashlib
import sqlite3
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from feeds import FeedStore


class StreamingFeedTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.sources = {'fixture': dict(name='Fixture', url='https://feed.example/list',
                                       ttl_hours=24, terms='fixture', license='fixture')}
        for context in [patch('feeds.SOURCES', self.sources),
                        patch.dict('os.environ', {'PUBLIC_FEED_KEYS': 'fixture'})]:
            context.start()
            self.addCleanup(context.stop)
        self.store = FeedStore(self.directory.name)

    def response(self, chunks):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.iter_content.side_effect = lambda size: iter(chunks)
        return response

    def refresh(self, chunks):
        with patch('feeds.requests.get', return_value=self.response(chunks)):
            return self.store.refresh()[0]

    def seed(self):
        self.assertEqual(self.refresh([b'https://previous.example/login\n'])['status'], 'updated')
        return (Path(self.directory.name)/'fixture.txt').read_bytes()

    def test_duplicate_heavy_chunked_feed_uses_sql_deduplication(self):
        body = b'\xef\xbb\xbf# header\n' + b'https://phish.example/login\n'*8
        result = self.refresh([body[:7], body[7:19], body[19:]])
        self.assertEqual(result['indicator_count'], 1)
        source = self.store.status()['sources'][0]
        self.assertEqual(source['sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(source['skipped_lines'], 7)
        self.assertEqual(self.store.lookup('https://phish.example/login')['status'], 'match')

    def test_invalid_or_oversized_download_preserves_snapshot_and_rows(self):
        previous = self.seed()
        for content, guard in [(b'<html>denied</html>', patch('feeds.MAX_FEED_BYTES', 1000)),
                               (b'x'*300, patch('feeds.MAX_LINE_BYTES', 128)),
                               (b'x'*300, patch('feeds.MAX_FEED_BYTES', 128)),
                               (b'\xff\xfe\n', patch('feeds.MAX_FEED_BYTES', 1000))]:
            with self.subTest(content=content[:8]), guard:
                self.assertEqual(self.refresh([content])['status'], 'unavailable')
                self.assertEqual(self.store.lookup('https://previous.example/login')['status'], 'match')
                self.assertEqual((Path(self.directory.name)/'fixture.txt').read_bytes(), previous)
        self.assertEqual(list(Path(self.directory.name).glob('refresh-*')), [])

    def test_mid_download_network_failure_preserves_previous_data(self):
        self.seed()
        def broken():
            yield b'https://new.example/\n'
            raise requests.ConnectionError('interrupted')
        self.assertEqual(self.refresh(broken())['status'], 'unavailable')
        self.assertEqual(self.store.lookup('https://previous.example/login')['status'], 'match')

    def test_sql_replacement_failure_rolls_back_deleted_rows(self):
        self.seed()
        connect = sqlite3.connect
        class FailingConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if sql.startswith('INSERT INTO indicators SELECT'):
                    raise sqlite3.OperationalError('simulated write failure')
                return super().execute(sql, *args, **kwargs)
        with patch('feeds.sqlite3.connect', side_effect=lambda *a, **k: connect(*a, **k, factory=FailingConnection)):
            self.assertEqual(self.refresh([b'https://new.example/login\n'])['status'], 'unavailable')
        self.assertEqual(self.store.lookup('https://previous.example/login')['status'], 'match')
        self.assertNotEqual(self.store.lookup('https://new.example/login')['status'], 'match')

    def test_large_feed_python_allocations_remain_bounded(self):
        def chunks():
            for i in range(25000):
                yield ('https://phish.example/'+str(i)+'/'+'a'*150+'\n').encode()
        tracemalloc.start()
        try:
            result = self.refresh(chunks())
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(result['indicator_count'], 25000)
        self.assertLess(peak, 6*1024*1024)
