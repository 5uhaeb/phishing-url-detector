"""Release integrity checks without loading pickle or contacting the network."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from model_contract import validate_artifact
from release import FILES, fetch, install, sha256, verify
from detector import FEATURE_NAMES


class ReleaseTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory) / 'source'
        root.mkdir()
        (root / 'runtime-model.joblib').write_bytes(b'unloaded-model')
        (root / 'evaluation.json').write_text(json.dumps({'trained_at': 'fixture'}))
        (root / 'dependencies.lock.txt').write_text('fixture==1')
        manifest = dict(schema_version=1, trained_at='fixture', files={name: sha256(root / name) for name in FILES})
        (root / 'manifest.json').write_text(json.dumps(manifest))
        archive = Path(directory) / 'release.zip'
        with ZipFile(archive, 'w') as zipped:
            for name in (*FILES, 'manifest.json'):
                zipped.write(root / name, name)
        return root, archive

    def test_install_verifies_archive_and_each_file_before_using_release(self):
        with tempfile.TemporaryDirectory() as directory:
            source, archive = self.fixture(directory)
            destination = Path(directory) / 'installed'
            with patch('joblib.load', side_effect=AssertionError('Must not deserialize')):
                manifest = install(archive, sha256(archive), destination)
                self.assertEqual(manifest, verify(destination))
            with self.assertRaises(ValueError):
                install(archive, sha256(archive), destination)
            (destination / 'runtime-model.joblib').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                verify(destination)

    def test_wrong_archive_hash_and_unexpected_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            _, archive = self.fixture(directory)
            destination = Path(directory) / 'installed'
            with self.assertRaisesRegex(ValueError, 'checksum'):
                install(archive, '0' * 64, destination)
            self.assertFalse(destination.exists())
            with ZipFile(archive, 'a') as zipped:
                zipped.writestr('../outside', 'malicious')
            with self.assertRaisesRegex(ValueError, 'Unexpected files'):
                install(archive, sha256(archive), destination)
            self.assertFalse(destination.exists())
            self.assertFalse((Path(directory) / 'outside').exists())

    def test_report_version_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _ = self.fixture(directory)
            manifest = json.loads((source / 'manifest.json').read_text())
            manifest['trained_at'] = 'other'
            (source / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'version mismatch'):
                verify(source)

    def test_fetch_requires_trusted_https_url_and_hash_before_network(self):
        with patch.dict('os.environ', {'RELEASE_URL': 'http://example.com/release.zip', 'RELEASE_SHA256': '0' * 64}):
            with patch('requests.get') as get, self.assertRaises(ValueError):
                fetch('unused')
            get.assert_not_called()

    def test_bundled_release_installs_offline_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            _, archive = self.fixture(directory)
            bundled = Path(directory) / 'deployment'
            bundled.mkdir()
            (bundled / 'model-release.zip').write_bytes(archive.read_bytes())
            (bundled / 'release.json').write_text(json.dumps(dict(schema_version=1, sha256=sha256(archive))))
            with patch('release.ROOT', Path(directory)), patch.dict('os.environ', {}, clear=True), patch('requests.get') as get:
                destination = Path(directory) / 'installed'
                self.assertEqual(fetch(destination)['trained_at'], 'fixture')
                get.assert_not_called()
                (bundled / 'model-release.zip').write_bytes(b'tampered')
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    fetch(Path(directory) / 'tampered')

    def test_model_contract_rejects_invalid_metadata(self):
        for artifact in [{}, {'features': []}, {'features': None}, None]:
            with self.assertRaises(ValueError):
                validate_artifact(artifact)
        class FakeModel:
            classes_ = [0, 1]
            def predict_proba(self, values):
                return [[.5, .5]]
        valid = dict(model=FakeModel(), features=list(FEATURE_NAMES),
                     threshold=.8, trained_at='fixture', model_weight=.9)
        self.assertIs(validate_artifact(valid), valid)
        for changes in [{'threshold': float('nan')}, {'model_weight': 1.1},
                        {'threshold': True}, {'threshold': 2}, {'trained_at': ''}]:
            with self.assertRaises(ValueError):
                validate_artifact(dict(valid, **changes))
        missing = dict(valid)
        missing.pop('threshold')
        with self.assertRaises(ValueError):
            validate_artifact(missing)


if __name__ == '__main__':
    unittest.main()
