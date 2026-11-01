"""Research-only URL models; no network access and no production model changes."""
import re
from urllib.parse import parse_qsl, unquote, urlsplit

import numpy as np

from detector import FEATURE_NAMES, SUFFIXES, extract_features, text_entropy

EXTRA_FEATURES = (
    'registered_length', 'registered_entropy', 'host_token_count',
    'path_token_count', 'query_token_count', 'path_digit_ratio',
    'query_digit_ratio', 'path_percent_ratio', 'query_percent_ratio',
    'path_max_segment_ratio', 'path_mean_segment_length', 'url_unique_ratio',
    'host_unique_ratio', 'decoded_path_auth_words', 'query_redirect_fields',
    'path_extension_length', 'query_max_value_length', 'host_digit_runs',
)
RESEARCH_FEATURES = FEATURE_NAMES + EXTRA_FEATURES
SHAPE_FEATURES = {
    'hostname_length', 'subdomains', 'dots', 'hyphens', 'hostname_entropy',
    'hostname_digit_ratio', 'known_suffix', 'registered_length',
    'registered_entropy', 'host_unique_ratio', 'host_digit_runs',
}


def url_features(value):
    normalized, features, group = extract_features(value)
    parts = urlsplit(normalized)
    host = parts.hostname or ''
    if host.startswith('www.') and not features['ip_hostname']:
        host = host[4:]
    registered = SUFFIXES(host).top_domain_under_public_suffix or host
    path, query = parts.path, parts.query
    segments = [segment for segment in path.split('/') if segment]
    parameters = parse_qsl(query, keep_blank_values=True)
    decoded = unquote(path).lower()
    extension = re.search(r'\.([A-Za-z0-9]{1,10})$', path)
    extras = (
        len(registered), text_entropy(registered), len(re.findall(r'[A-Za-z0-9]+', host)),
        len(re.findall(r'[A-Za-z0-9]+', path)), len(re.findall(r'[A-Za-z0-9]+', query)),
        sum(c.isdigit() for c in path)/max(1, len(path)),
        sum(c.isdigit() for c in query)/max(1, len(query)),
        path.count('%')/max(1, len(path)), query.count('%')/max(1, len(query)),
        max(map(len, segments), default=0)/max(1, len(path)),
        sum(map(len, segments))/max(1, len(segments)),
        len(set(host+path+query))/max(1, len(host+path+query)),
        len(set(host))/max(1, len(host)),
        sum(decoded.count(word) for word in ['login', 'signin', 'password', 'verify', 'account', 'credential', 'authenticate']),
        sum(key.lower() in {'url', 'redirect', 'redirect_uri', 'next', 'return', 'continue', 'callback'} for key, _ in parameters),
        len(extension.group(1)) if extension else 0,
        max((len(value) for _, value in parameters), default=0),
        len(re.findall(r'\d{3,}', host)),
    )
    # Text view deliberately ignores the conventional www prefix and scheme.
    # Original URLs remain intact for provenance and exact deduplication.
    text = host + (f':{parts.port}' if parts.port else '') + path + ('?'+query if query else '')
    return normalized, group, text, np.asarray([features[name] for name in FEATURE_NAMES]+list(extras), dtype=np.float32)


def domain_partition(group, seed=42):
    import hashlib
    value = int.from_bytes(hashlib.sha256(f'{seed}:{group}'.encode()).digest()[:8], 'big') % 10000
    return 'training' if value < 7000 else 'calibration' if value < 8500 else 'validation'


class URLResearchCandidate:
    """Portable candidate bundle; predicts URL phishing probability without fetching."""
    classes_ = np.array([0, 1])

    def __init__(self, estimators, vectorizer, columns, weights):
        self.estimators, self.vectorizer = estimators, vectorizer
        self.columns, self.weights = columns, weights

    def predict_proba(self, urls):
        rows = [url_features(value) for value in urls]
        numeric = np.asarray([row[3] for row in rows], dtype=np.float32)
        text = [row[2] for row in rows]
        sparse = None
        positive = np.zeros(len(rows))
        for name, weight in self.weights.items():
            if not weight:
                continue
            if name == 'character':
                if sparse is None:
                    sparse = self.vectorizer.transform(text)
                values = sparse
            else:
                values = numeric[:, self.columns[name]]
            positive += weight*self.estimators[name].predict_proba(values)[:, 1]
        return np.column_stack((1-positive, positive))
