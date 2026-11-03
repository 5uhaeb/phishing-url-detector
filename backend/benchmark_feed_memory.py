"""Measure feed-refresh RSS with the serving model loaded; no network calls.

Use a local publisher snapshot. Legacy mode is capped to avoid recreating an
unbounded full-feed allocation on a developer's machine.
"""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from threading import Event, Thread
from time import perf_counter
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent/'data/research_v3/deps'))
import psutil
import main
from feeds import FeedStore, canonical_url
import hashlib


class LocalSnapshot:
    status_code = 200

    def __init__(self, path, limit):
        self.path, self.limit = path, limit

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def raise_for_status(self):
        pass

    def iter_content(self, size):
        remaining = self.limit or self.path.stat().st_size
        with self.path.open('rb') as source:
            while remaining:
                chunk = source.read(min(size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk


def measure(args):
    if args.mode=='legacy' and not 0 < args.limit <= 8*1024*1024:
        raise ValueError('Legacy comparison requires --limit at most 8 MiB.')
    process = psutil.Process()
    baseline = process.memory_info().rss
    peak = [baseline]
    stop = Event()
    def sample():
        while not stop.wait(.01):
            peak[0] = max(peak[0], process.memory_info().rss)
    sampler = Thread(target=sample, daemon=True)
    sampler.start()
    tick = perf_counter()
    try:
        response = LocalSnapshot(args.snapshot, args.limit)
        if args.mode=='legacy':
            chunks = list(response.iter_content(65536))
            content = b''.join(chunks)
            lines = [line.strip() for line in content.decode('utf-8-sig').splitlines()
                     if line.strip() and not line.startswith('#')]
            entries = {}
            for line in lines:
                try: entries[hashlib.sha256(canonical_url(line).encode()).hexdigest()] = None
                except ValueError: continue
            result = dict(status='updated',indicator_count=len(entries))
        else:
            with tempfile.TemporaryDirectory() as directory:
                store = FeedStore(directory)
                with patch('feeds.requests.get', return_value=response):
                    result = store.refresh(only=['phishing_database'])[0]
        peak[0] = max(peak[0], process.memory_info().rss)
    finally:
        stop.set();sampler.join()
    report = dict(mode=args.mode, bytes_processed=min(args.limit,args.snapshot.stat().st_size) if args.limit else args.snapshot.stat().st_size,
        model=main.artifact['model_name'],model_version=main.artifact['trained_at'],
        baseline_rss_mib=baseline/2**20,peak_rss_mib=peak[0]/2**20,
        additional_peak_mib=(peak[0]-baseline)/2**20,seconds=perf_counter()-tick,**result)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--mode',choices=['streaming','legacy'],default='streaming')
    parser.add_argument('--limit',type=int,default=0)
    parser.add_argument('--output',type=Path)
    measure(parser.parse_args())
