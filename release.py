"""Build, verify or install a checksum-pinned model release. Never retrains."""
import argparse
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

import requests

ROOT = Path(__file__).resolve().parent
FILES = ('runtime-model.joblib', 'evaluation.json', 'dependencies.lock.txt')
MAX_BYTES = 512 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify(directory):
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('schema_version') != 1 or set(manifest.get('files', {})) != set(FILES):
        raise ValueError('Unsupported release manifest.')
    for name in FILES:
        if sha256(directory / name) != manifest['files'][name]:
            raise ValueError(f'Release checksum mismatch: {name}')
    report = json.loads((directory / 'evaluation.json').read_text(encoding='utf-8'))
    if not manifest.get('trained_at') or report.get('trained_at') != manifest['trained_at']:
        raise ValueError('Release model/report version mismatch.')
    return manifest


def build(destination):
    destination = Path(destination)
    archive = destination.with_suffix('.zip')
    if destination.exists() or archive.exists():
        raise ValueError('Choose a new release directory; existing releases are immutable.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    report = json.loads((ROOT / 'evaluation.json').read_text(encoding='utf-8'))
    import joblib
    artifact = joblib.load(ROOT / 'model.joblib')
    from model_contract import validate_artifact
    validate_artifact(artifact)
    if artifact['trained_at'] != report.get('trained_at'):
        raise ValueError('The model and evaluation report must belong to the same run.')
    if artifact.get('model_family') != report.get('selected_model'):
        raise ValueError('The serving model must match the selected model in the report.')
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        staged = Path(temporary)
        from prepare_runtime import prepare
        prepare(ROOT / 'model.joblib', staged / 'runtime-model.joblib')
        for name in FILES[1:]:
            shutil.copyfile(ROOT / name, staged / name)
        manifest = dict(schema_version=1, trained_at=report['trained_at'],
                        run_id=report.get('run_id'), model_name=report.get('selected_model_name', 'Random Forest'),
                        files={name: sha256(staged / name) for name in FILES})
        (staged / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        verify(staged)
        shutil.copytree(staged, destination)
    with ZipFile(archive, 'x', compression=ZIP_DEFLATED) as zipped:
        for name in (*FILES, 'manifest.json'):
            zipped.write(destination / name, name)
    print(f'Release: {archive}\nSHA256: {sha256(archive)}')
    return archive


def install(archive, expected_sha256, destination):
    if not expected_sha256 or sha256(archive) != expected_sha256.lower():
        raise ValueError('Archive checksum does not match RELEASE_SHA256.')
    destination = Path(destination)
    if destination.exists():
        raise ValueError('Choose a new destination to retain the existing release for rollback.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(archive) as zipped, tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        if (set(zipped.namelist()) != {*FILES, 'manifest.json'} or len(zipped.infolist()) != 4
                or sum(item.file_size for item in zipped.infolist()) > MAX_BYTES):
            raise ValueError('Unexpected files or oversized release archive.')
        staged = Path(temporary)
        # Fixed filenames only: never extract arbitrary archive paths.
        for name in (*FILES, 'manifest.json'):
            (staged / name).write_bytes(zipped.read(name))
        verify(staged)
        shutil.copytree(staged, destination)
    return verify(destination)


def fetch(destination):
    url = os.environ.get('RELEASE_URL', '')
    expected = os.environ.get('RELEASE_SHA256', '')
    if not url and not expected:
        # The private source repository can carry the small, tested release.
        # Render already authenticates the checkout; no second download token is needed.
        bundled = ROOT / 'deployment'
        metadata = json.loads((bundled / 'release.json').read_text(encoding='utf-8'))
        if metadata.get('schema_version') != 1 or len(metadata.get('sha256', '')) != 64:
            raise ValueError('Invalid bundled release metadata.')
        return install(bundled / 'model-release.zip', metadata['sha256'], destination)
    if not url.startswith('https://') or len(expected) != 64:
        raise ValueError('Set HTTPS RELEASE_URL and the trusted release archive RELEASE_SHA256.')
    # Verify configuration before any download or model deserialization.
    int(expected, 16)
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / 'release.zip'
        with requests.get(url, stream=True, timeout=(5, 120)) as response:
            response.raise_for_status()
            if not response.url.startswith('https://'):
                raise ValueError('Release redirect must remain HTTPS.')
            size = 0
            with archive.open('wb') as output:
                for chunk in response.iter_content(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise ValueError('Release archive exceeds size limit.')
                    output.write(chunk)
        return install(archive, expected, destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'verify', 'fetch'])
    parser.add_argument('--directory', type=Path, default=ROOT / 'release' / 'current')
    args = parser.parse_args()
    try:
        result = globals()[args.action](args.directory)
        if args.action != 'build':
            print(json.dumps(result, indent=2))
    except (OSError, ValueError, requests.RequestException) as exc:
        parser.exit(1, f'Release failed: {exc}\n')
