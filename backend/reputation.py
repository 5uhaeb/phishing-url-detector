"""Consent-gated Google Web Risk lookups. Never fetch submitted websites."""

import hashlib
import ipaddress
import os
from collections import OrderedDict
from datetime import datetime, timezone
from threading import Lock
from time import monotonic

import requests

from detector import parse_url

ENDPOINT = 'https://webrisk.googleapis.com/v1/uris:search'
THREAT_TYPES = ('SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE')


class ReputationClient:
    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else os.getenv('WEB_RISK_API_KEY', '')
        self.cache = OrderedDict()
        self.lock = Lock()
        self.failures = 0
        self.retry_after = 0

    def lookup(self, value, consent=False):
        result = dict(provider='Google Web Risk', status='not_requested', threats=[], cached=False)
        # Gate before validation/cache/network: only literal True is consent.
        if consent is not True:
            return dict(result, message='Not checked: external lookup was not authorized.')
        normalized, parts, host, is_ip = parse_url(value)
        if parts.username is not None or parts.password is not None:
            return dict(result, status='skipped', message='Lookup skipped: URL contains embedded credentials.')
        if (is_ip and not ipaddress.ip_address(host).is_global) or host.endswith(
                ('.localhost', '.local', '.internal', '.test', '.invalid', '.example', '.onion')):
            return dict(result, status='skipped', message='Lookup skipped: destination is private or reserved.')
        if not self.api_key:
            return dict(result, status='not_configured', message='Web Risk API key is not configured.')
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        with self.lock:
            now = monotonic()
            if digest in self.cache:
                expires, cached = self.cache[digest]
                if expires > now:
                    self.cache.move_to_end(digest)
                    return dict(cached, cached=True)
                del self.cache[digest]
            if now < self.retry_after:
                return dict(result, status='unavailable', message='Lookup temporarily unavailable; retry shortly.')
        params = [('uri', normalized)] + [('threatTypes', threat) for threat in THREAT_TYPES]
        try:
            # Fixed destination, no redirects, no retries, finite connect/read timeout.
            # Key is a header so it does not appear in the request URL.
            response = requests.get(ENDPOINT, params=params,
                                    headers={'X-Goog-Api-Key': self.api_key},
                                    timeout=(2, 4), allow_redirects=False)
            with response:
                if response.status_code != 200:
                    raise ValueError('Provider returned an unsuccessful status.')
                body = response.json()
            if not isinstance(body, dict):
                raise ValueError('Unexpected provider response.')
            if body == {}:
                result.update(status='no_match', message='No match in the queried threat lists. Safety is not established.')
            else:
                threat = body.get('threat')
                if not isinstance(threat, dict):
                    raise ValueError('Missing threat object.')
                threats = threat.get('threatTypes')
                if not isinstance(threats, list) or not threats or any(t not in THREAT_TYPES for t in threats):
                    raise ValueError('Invalid threat categories.')
                expiry = datetime.fromisoformat(threat['expireTime'].replace('Z', '+00:00'))
                ttl = (expiry - datetime.now(timezone.utc)).total_seconds()
                if ttl <= 0:
                    raise ValueError('Expired threat evidence.')
                result.update(status='match', threats=sorted(set(threats)),
                              expires_at=expiry.isoformat(), checked_at=datetime.now(timezone.utc).isoformat(),
                              message='URL matched a Google Web Risk threat list.')
                with self.lock:
                    self.cache[digest] = (monotonic() + min(ttl, 3600), dict(result))
                    while len(self.cache) > 512:
                        self.cache.popitem(last=False)
            result['checked_at'] = datetime.now(timezone.utc).isoformat()
            with self.lock:
                self.failures = 0
                self.retry_after = 0
            return result
        except (requests.RequestException, ValueError, KeyError, TypeError, OverflowError):
            # Do not expose exception strings: they can include the submitted URL.
            with self.lock:
                self.failures += 1
                if self.failures >= 3:
                    self.retry_after = monotonic() + 30
            return dict(result, status='unavailable', threats=[], message='Threat lookup failed. No reputation verdict is available.')


def combine_evidence(local, reputation):
    """A negative/missing lookup never overrides a local warning or establishes safety."""
    result = dict(local, local_prediction=local['prediction'], reputation=reputation)
    result['verification'] = {
        'match': 'Threat reported by a reputation source',
        'no_match': 'External lookup returned no match',
        'not_requested': 'External lookup not requested',
        'not_configured': 'External service not configured',
        'unavailable': 'External service unavailable',
        'skipped': 'External lookup skipped',
    }.get(reputation['status'], 'No independent verification')
    suspicious = local['hybrid_score'] >= local['threshold']
    near_boundary = abs(local['hybrid_score'] - local['threshold']) <= 10
    if reputation['status'] == 'match':
        result.update(prediction='Known phishing threat' if 'SOCIAL_ENGINEERING' in reputation['threats']
                      else 'Known malicious URL', risk='High', evidence='Threat-list match',
                      action='Do not open this URL or enter credentials.')
    elif suspicious:
        result.update(prediction='Suspicious URL', risk='High', evidence='Local model and rules only',
                      action='Avoid this URL until independently verified.')
    elif near_boundary or local['risk'] == 'Medium':
        result.update(prediction='Needs review', risk='Medium', evidence='Inconclusive local signals',
                      action='Verify the destination through a separate trusted channel.')
    elif reputation['status'] == 'no_match':
        result.update(prediction='No known threat found', risk='Low', evidence='No list match and low local risk',
                      action='Not a safety guarantee. Verify the destination before entering sensitive information.')
    else:
        result.update(prediction='Low predicted risk', risk='Low', evidence='Local model and rules; independent verification is separate',
                      action='No strong local warning was found. This is not a safety guarantee; check the verification evidence separately.')
    return result
