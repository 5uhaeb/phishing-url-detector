"""Free public phishing-feed snapshots and private, exact-URL local matching."""

import hashlib
import json
import logging
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit, urlunsplit

import requests

from detector import parse_url

ROOT = Path(__file__).resolve().parent
MAX_FEED_BYTES = 100 * 1024 * 1024
MAX_LINE_BYTES = 32 * 1024
INSERT_BATCH_SIZE = 512
SOURCES = {
    'openphish': dict(name='OpenPhish Community',
        url='https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt',
        terms='https://openphish.com/terms.html', license='Non-commercial personal/academic research', ttl_hours=24),
    'phishing_database': dict(name='Phishing.Database',
        url='https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt',
        terms='https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE',
        license='MIT; preserve source copyright and permission notice', ttl_hours=24),
}


def canonical_url(value):
    normalized, parts, _, _ = parse_url(value)
    authority = parts.netloc
    if (parts.scheme == 'http' and parts.port == 80) or (parts.scheme == 'https' and parts.port == 443):
        authority = authority.rsplit(':', 1)[0]
    # Keep fragment differences for conservative exact matches (SPA routes can differ).
    fragment = urlsplit(value.strip()).fragment
    return urlunsplit((parts.scheme, authority, parts.path, parts.query, fragment))


class FeedStore:
    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else ROOT / 'data' / 'feeds'
        self.database = self.directory / 'indicators.sqlite'
        keys = os.getenv('PUBLIC_FEED_KEYS', ','.join(SOURCES)).split(',')
        if not keys or any(key not in SOURCES for key in keys):
            raise ValueError('PUBLIC_FEED_KEYS must list known feed keys.')
        self._source_keys = tuple(keys) if 'PUBLIC_FEED_KEYS' in os.environ else None

    @property
    def sources(self):
        return ({key: SOURCES[key] for key in self._source_keys}
                if self._source_keys is not None else SOURCES)

    def status(self):
        if not self.database.exists():
            return dict(status='missing', sources=[], total_indicators=0)
        try:
            with closing(sqlite3.connect(self.database, timeout=3)) as db:
                rows = db.execute('SELECT source, metadata FROM sources').fetchall()
            sources = []
            now = datetime.now(timezone.utc)
            for key, payload in rows:
                if self._source_keys is not None and key not in self._source_keys:
                    continue
                item = json.loads(payload)
                age = (now - datetime.fromisoformat(item['fetched_at'])).total_seconds()
                item.update(key=key, fresh=0 <= age <= item['ttl_hours'] * 3600,
                            age_hours=round(age / 3600, 2))
                sources.append(item)
            fresh = sum(source['fresh'] for source in sources)
            state = 'fresh' if fresh == len(self.sources) else ('partial' if fresh else 'stale')
            return dict(status=state, sources=sources,
                        total_indicators=sum(s['indicator_count'] for s in sources))
        except (sqlite3.Error, ValueError, KeyError, TypeError):
            return dict(status='unavailable', sources=[], total_indicators=0)

    @staticmethod
    def _download(source, destination):
        digest = hashlib.sha256()
        total = 0
        with requests.get(source['url'], timeout=(3, 30), stream=True,
                          allow_redirects=False, headers={'User-Agent': 'AcademicPhishingDetector/2.0'}) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError('Unexpected redirect/status.')
            with destination.open('wb') as output:
                for chunk in response.iter_content(65536):
                    total += len(chunk)
                    if total > MAX_FEED_BYTES:
                        raise ValueError('Feed exceeds size limit.')
                    digest.update(chunk)
                    output.write(chunk)
        return digest.hexdigest()

    def _import(self, key, source, downloaded, checksum):
        # TEMP rows live on disk. Python holds at most one bounded line and
        # 512 digests, rather than copies of the whole feed and a large dict.
        with closing(sqlite3.connect(self.database, timeout=10)) as db:
            db.execute('PRAGMA temp_store=FILE')
            db.execute('PRAGMA cache_size=-1024')
            db.execute('PRAGMA temp.cache_size=-1024')
            db.execute('PRAGMA mmap_size=0')
            with db:
                db.execute('CREATE TABLE IF NOT EXISTS sources (source TEXT PRIMARY KEY, metadata TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS indicators (digest TEXT, source TEXT, PRIMARY KEY(digest, source))')
                db.execute('CREATE TEMP TABLE incoming (digest TEXT PRIMARY KEY) WITHOUT ROWID')
                total_lines, valid_lines, batch = 0, 0, []
                with downloaded.open('rb') as stream:
                    while True:
                        raw = stream.readline(MAX_LINE_BYTES + 1)
                        if not raw:
                            break
                        if len(raw) > MAX_LINE_BYTES:
                            raise ValueError('Feed line exceeds size limit.')
                        line = raw.decode('utf-8-sig').strip()
                        if not line or line.startswith('#'):
                            continue
                        total_lines += 1
                        if total_lines % 100000 == 0:
                            logging.getLogger(__name__).info('Feed import source=%s lines=%d', key, total_lines)
                        try:
                            canonical = canonical_url(line)
                        except ValueError:
                            continue
                        valid_lines += 1
                        batch.append((hashlib.sha256(canonical.encode()).hexdigest(),))
                        if len(batch) == INSERT_BATCH_SIZE:
                            db.executemany('INSERT OR IGNORE INTO incoming VALUES (?)', batch)
                            batch.clear()
                if batch:
                    db.executemany('INSERT OR IGNORE INTO incoming VALUES (?)', batch)
                count = db.execute('SELECT COUNT(*) FROM incoming').fetchone()[0]
                if not count or valid_lines * 2 < total_lines:
                    raise ValueError('Feed contains too few valid URLs.')
                metadata = dict(source, fetched_at=datetime.now(timezone.utc).isoformat(),
                                sha256=checksum, indicator_count=count,
                                skipped_lines=total_lines-count)
                # The old indicators/metadata remain visible until this complete
                # validated replacement commits. Any parsing/SQL failure rolls back.
                db.execute('DELETE FROM indicators WHERE source=?', (key,))
                db.execute('INSERT INTO indicators SELECT digest, ? FROM incoming', (key,))
                db.execute('INSERT OR REPLACE INTO sources VALUES (?,?)', (key, json.dumps(metadata)))
        return count

    def refresh(self, only=None):
        self.directory.mkdir(parents=True, exist_ok=True)
        results = []
        for key, source in self.sources.items():
            if only and key not in only:
                continue
            try:
                with TemporaryDirectory(prefix='refresh-', dir=self.directory) as temporary:
                    downloaded = Path(temporary) / 'feed.txt'
                    checksum = self._download(source, downloaded)
                    count = self._import(key, source, downloaded, checksum)
                    os.replace(downloaded, self.directory / f'{key}.txt')
                results.append(dict(source=key, status='updated', indicator_count=count))
            except (requests.RequestException, ValueError, OSError, sqlite3.Error):
                results.append(dict(source=key, status='unavailable'))
        return results

    def lookup(self, value):
        normalized = canonical_url(value)
        summary = self.status()
        result = dict(provider='Local public-feed snapshots', status='not_listed', threats=[],
                      sources=[], message='No exact URL match. These limited feeds do not establish safety.')
        if summary['status'] in ('missing', 'unavailable'):
            return dict(result, status=summary['status'], message='Public-feed evidence is not available.')
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        try:
            with closing(sqlite3.connect(self.database, timeout=3)) as db:
                keys = {row[0] for row in db.execute('SELECT source FROM indicators WHERE digest=?', (digest,))}
            matches = [source for source in summary['sources'] if source['key'] in keys]
            fresh = [source for source in matches if source['fresh']]
            if fresh:
                return dict(result, status='match', threats=['SOCIAL_ENGINEERING'], sources=fresh,
                            checked_at=datetime.now(timezone.utc).isoformat(),
                            message='Exact URL is listed in a recently downloaded public phishing feed. Source reports can contain errors.')
            if matches:
                return dict(result, status='stale_match', sources=matches,
                            message='URL appears in an expired feed snapshot. Refresh evidence before relying on it.')
            if summary['status'] != 'fresh':
                result.update(status='incomplete', message='No exact match; one or more feed snapshots are stale or missing.')
            return result
        except sqlite3.Error:
            return dict(result, status='unavailable', message='Local feed lookup failed.')


if __name__ == '__main__':
    store = FeedStore()
    print(json.dumps(dict(refresh=store.refresh(), status=store.status()), indent=2))
