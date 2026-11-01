import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch
import json

from research_sources import SOURCES, acquire, bounded_get
from research_data import manifest


class ResearchSourceTests(unittest.TestCase):
    def test_revision_pin_cannot_silently_reuse_different_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            (path/'upstream_manifest.json').write_text(json.dumps({'revision':'a'*40}))
            with patch('research_data.DATA',path), patch('research_data.requests.get') as get:
                with self.assertRaises(ValueError):manifest('b'*40)
                with self.assertRaises(ValueError):manifest('../wrong')
                get.assert_not_called()

    def test_redirect_cannot_change_feed_publisher_or_scheme(self):
        for target in ['https://attacker.example/dump','http://cdn.phishtank.com/datadumps/a',
                       'https://cdn.phishtank.com:9999/datadumps/a','https://cdn.phishtank.com/private/a']:
            response=MagicMock();response.__enter__.return_value=response
            response.status_code=302;response.headers={'Location':target}
            session=MagicMock();session.get.return_value=response
            with self.assertRaises(ValueError):bounded_get(SOURCES['phishtank'][0],session)
            self.assertEqual(session.get.call_count,1)

    def test_frozen_snapshot_directory_cannot_be_refreshed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);(path/'openphish.txt').write_text('reserved')
            with self.assertRaises(ValueError):acquire(path)
            self.assertEqual((path/'openphish.txt').read_text(),'reserved')
