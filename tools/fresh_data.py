"""Download only URL/label metadata from a pinned official PhreshPhish snapshot.

No submitted site is visited and no HTML payload is downloaded. HTTP byte ranges
allow Arrow to read the metadata columns of the upstream Parquet files.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import io
import json
from pathlib import Path
import time

import pyarrow.parquet as pq
import requests

REPO = 'phreshphish/phreshphish'
BASE = 'https://huggingface.co'
COLUMNS = ['sha256', 'url', 'label', 'date', 'target', 'lang']


class RangeFile(io.RawIOBase):
    def __init__(self, url, size):
        self.url, self.size, self.position = url, size, 0
        self.session = requests.Session()
        self.bytes_received = 0

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position

    def seek(self, offset, whence=0):
        self.position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        if self.position < 0: raise ValueError('Negative file position')
        return self.position

    def read(self, size=-1):
        end = self.size if size < 0 else min(self.size, self.position + size)
        if end <= self.position: return b''
        expected = end - self.position
        for attempt in range(5):
            try:
                # The query differentiates ranges in intermediary HTTP caches.
                response = self.session.get(self.url + f'?download=true&range_start={self.position}&range_end={end-1}',
                    headers={'Range': f'bytes={self.position}-{end-1}'}, timeout=(30, 180), stream=True)
                response.raise_for_status()
                if response.status_code != 206:
                    response.close()
                    raise ValueError('Upstream did not honor a byte range; refusing full HTML download.')
                value = response.raw.read(expected + 1)
                response.close()
                if len(value) != expected: raise ValueError('Incomplete range')
                self.position = end
                self.bytes_received += len(value)
                return value
            except (requests.RequestException, ValueError):
                if attempt == 4: raise
                time.sleep(attempt + 1)

    def close(self):
        self.session.close()
        super().close()


def fetch_one(item, revision, root):
    name = Path(item['path']).name.replace('.parquet', '.csv')
    output = root / name
    if output.exists():
        return dict(file=name, sha256=hashlib.sha256(output.read_bytes()).hexdigest(), cached=True)
    url = f'{BASE}/datasets/{REPO}/resolve/{revision}/{item["path"]}'
    with RangeFile(url, item['size']) as handle:
        table = pq.ParquetFile(handle, pre_buffer=False).read(columns=COLUMNS, use_threads=False)
        frame = table.to_pandas()
        frame.to_csv(output.with_suffix('.tmp'), index=False)
        output.with_suffix('.tmp').replace(output)
        return dict(file=name, upstream_file=item['path'], rows=len(frame), received_bytes=handle.bytes_received,
                    sha256=hashlib.sha256(output.read_bytes()).hexdigest())


def download(output, workers=4):
    output.mkdir(parents=True, exist_ok=True)
    manifest = output / 'source.json'
    if manifest.exists():
        info = json.loads(manifest.read_text(encoding='utf-8'))
        revision, files = info['revision'], info['files']
    else:
        response = requests.get(f'{BASE}/api/datasets/{REPO}', timeout=45)
        response.raise_for_status()
        revision = response.json()['sha']
        response = requests.get(f'{BASE}/api/datasets/{REPO}/tree/{revision}/data?limit=1000', timeout=45)
        response.raise_for_status()
        files = [item for item in response.json() if item['path'].endswith('.parquet')]
        info = dict(repository=REPO, revision=revision, files=files, license='CC-BY-4.0',
                    source=f'{BASE}/datasets/{REPO}', columns=COLUMNS,
                    policy='Official train and test metadata only; no prior scores or models are inputs.')
        manifest.write_text(json.dumps(info, indent=2), encoding='utf-8')
    records = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        tasks = [pool.submit(fetch_one, item, revision, output) for item in files]
        for task in as_completed(tasks):
            record = task.result()
            records.append(record)
            print(json.dumps(record), flush=True)
    info['downloads'] = sorted(records, key=lambda r: r['file'])
    manifest.write_text(json.dumps(info, indent=2), encoding='utf-8')
    print(f'Finished {len(records)} metadata shards at revision {revision}.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    download(args.output, args.workers)
