"""Acquire permitted research holdouts from fixed feed publishers, never sites.

Snapshots are private local research inputs, not public repository artifacts.
Use a new directory for each independent run; never refresh a frozen holdout.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

SOURCES = {
    'openphish': ('https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt', 'openphish.txt'),
    'phishtank': ('https://data.phishtank.com/data/online-valid.csv.gz', 'phishtank.csv.gz'),
}


def bounded_get(url, session):
    with session.get(url, timeout=(5, 40), stream=True, allow_redirects=False) as response:
        if response.status_code == 302:
            destination=response.headers.get('Location', '')
            parts=urlsplit(destination)
            if (url==SOURCES['phishtank'][0] and parts.scheme=='https' and parts.hostname=='cdn.phishtank.com'
                    and parts.port in (None,443) and not parts.username and parts.path.startswith('/datadumps/')):
                return bounded_get(destination, session)
            raise ValueError('Unexpected feed redirect')
        response.raise_for_status()
        if response.status_code != 200:raise ValueError('Unexpected feed status')
        chunks=[];size=0
        for chunk in response.iter_content(65536):
            size+=len(chunk)
            if size>15_000_000:raise ValueError('Research snapshot exceeds size limit')
            chunks.append(chunk)
        return b''.join(chunks)


def acquire(directory):
    directory.mkdir(parents=True,exist_ok=True)
    if any(directory.iterdir()):raise ValueError('Use an empty new snapshot directory')
    session=requests.Session();session.headers['User-Agent']='LinkGuard-Capstone-Research/1.0'
    manifest={}
    for name,(url,filename) in SOURCES.items():
        try:
            content=bounded_get(url,session)
            if name=='phishtank' and not content.startswith(b'\x1f\x8b'):raise ValueError('Expected compressed CSV')
            if name=='openphish' and not content.startswith((b'http://',b'https://')):raise ValueError('Expected URL text feed')
            path=directory/filename;path.write_bytes(content)
            manifest[name]=dict(url=url,status=200,path=str(path),bytes=len(content),
                retrieved_at=datetime.now(timezone.utc).isoformat(),sha256=hashlib.sha256(content).hexdigest())
        except (requests.RequestException,ValueError) as error:
            manifest[name]=dict(url=url,error=type(error).__name__)
    (directory/'fresh_source_manifest.json').write_text(json.dumps(manifest,indent=2))
    print(json.dumps(manifest,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True)
    acquire(parser.parse_args().directory)
