"""Download only projected URL metadata from pinned PhreshPhish Parquet files.

This reader never requests webpage destinations or the large HTML column.
Optional dependency: pyarrow (install separately for research, not serving).
"""
import argparse
import io
import json
import re
from pathlib import Path
import sys
from urllib.parse import quote

import requests

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data' / 'research_v3'
sys.path.insert(0, str(DATA / 'deps'))
REPO = 'phreshphish/phreshphish'
COLUMNS = ['sha256', 'url', 'label', 'date', 'target', 'lang']


class RangeReader(io.RawIOBase):
    """Seekable HTTPS range reader; reject full-file fallback and oversized reads."""
    def __init__(self, url, size, session=None):
        self.url, self.size, self.position = url, size, 0
        self.session = session or requests.Session()
        self.transferred = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        if position < 0 or position > self.size:
            raise ValueError('Seek outside remote file.')
        self.position = position
        return position

    def read(self, count=-1):
        count = min(self.size - self.position, count if count >= 0 else self.size)
        if count == 0:
            return b''
        if count > 32 * 1024 * 1024:
            raise ValueError('Refusing a remote read over 32 MiB; use column projection.')
        start, end = self.position, self.position + count - 1
        # Distinct query keys prevent an intermediary reusing a cached range.
        url = self.url + f'?download=true&range_start={start}&range_end={end}'
        with self.session.get(url, headers={'Range': f'bytes={start}-{end}'}, stream=True, timeout=(15, 90)) as response:
            response.raise_for_status()
            if response.status_code != 206 or not response.headers.get('Content-Range', '').startswith(f'bytes {start}-{end}/'):
                raise ValueError('Server did not honor the requested byte range; no full-file download attempted.')
            content = response.content
        if len(content) != count:
            raise ValueError('Truncated remote Parquet range.')
        self.position += count
        self.transferred += count
        return content

    def readinto(self, buffer):
        content = self.read(len(buffer))
        buffer[:len(content)] = content
        return len(content)


def manifest(revision=None):
    if revision is not None and not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Use a full 40-character dataset revision SHA.')
    DATA.mkdir(parents=True, exist_ok=True)
    path = DATA / 'upstream_manifest.json'
    if path.exists():
        cached = json.loads(path.read_text(encoding='utf-8'))
        if revision is not None and cached['revision'] != revision:
            raise ValueError('Cached metadata has a different dataset revision; use a separate research cache.')
        return cached
    if revision is None:
        response = requests.get(f'https://huggingface.co/api/datasets/{REPO}', timeout=45)
        response.raise_for_status()
        revision = response.json()['sha']
    response = requests.get(f'https://huggingface.co/api/datasets/{REPO}/tree/{revision}/data?limit=1000', timeout=45)
    response.raise_for_status()
    files = [entry for entry in response.json() if entry['path'].endswith('.parquet')]
    value = dict(repo=REPO, revision=revision, columns=COLUMNS,
                 license='CC-BY-4.0; anti-phishing research use per publisher', files=files)
    path.write_text(json.dumps(value, indent=2), encoding='utf-8')
    card = requests.get(f'https://huggingface.co/datasets/{REPO}/raw/{revision}/README.md', timeout=45)
    card.raise_for_status()
    (DATA / 'UPSTREAM_README.md').write_text(card.text, encoding='utf-8')
    return value


def acquire(split, limit=0, revision=None):
    import pyarrow.parquet as pq
    info = manifest(revision)
    entries = sorted((entry for entry in info['files'] if entry['path'].startswith(f'data/{split}-')), key=lambda entry: entry['path'])
    if limit:
        entries = entries[:limit]
    target = DATA / split
    target.mkdir(exist_ok=True)
    total_bytes = 0
    for index, entry in enumerate(entries, 1):
        output = target / (Path(entry['path']).stem + '.csv')
        if output.exists():
            print(f'{split} {index}/{len(entries)} cached: {output.name}', flush=True)
            continue
        url = f'https://huggingface.co/datasets/{REPO}/resolve/{info["revision"]}/{quote(entry["path"], safe="/")}'
        remote = RangeReader(url, entry['size'])
        parquet = pq.ParquetFile(remote)
        columns = [name for name in COLUMNS if name in parquet.schema_arrow.names]
        if not {'url', 'label', 'date'}.issubset(columns):
            raise ValueError(f'Unexpected dataset schema: {parquet.schema_arrow.names}')
        table = parquet.read(columns=columns, use_threads=False)
        frame = table.to_pandas()
        temporary = output.with_suffix('.tmp')
        frame.to_csv(temporary, index=False)
        temporary.replace(output)
        total_bytes += remote.transferred
        print(f'{split} {index}/{len(entries)}: {len(frame):,} rows; metadata transfer {remote.transferred/1e6:.2f} MB; labels {frame.label.value_counts().to_dict()}', flush=True)
    print(f'Completed {split}: newly transferred {total_bytes/1e6:.2f} MB; no HTML fetched.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', choices=['train', 'test'], required=True)
    parser.add_argument('--limit', type=int, default=0)
    parser.add_argument('--revision', help='Pin a full dataset revision SHA for exact reproduction')
    args = parser.parse_args()
    acquire(args.split, args.limit, args.revision)
