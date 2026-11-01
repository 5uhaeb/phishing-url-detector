"""Versioned, offline URL features for phishing-specific research.

The production 32-feature schema is unchanged. Fragments, userinfo and query
values remain in the research text view; no destination is resolved or fetched.
"""
import re
from urllib.parse import urlsplit, unquote

import numpy as np
import idna

from detector import text_entropy
from feeds import canonical_url
from research_models import RESEARCH_FEATURES, url_features

FEATURE_VERSION = 'phishing-url-v2-64'
ADDITIONAL_FEATURES = (
    'url_entropy', 'special_ratio', 'longest_repeat', 'unicode_host',
    'greek_cyrillic_host', 'fragment_length', 'fragment_auth_words',
    'fragment_entropy', 'shortener_host', 'auth_query_values',
    'userinfo_length', 'embedded_url_count', 'decoded_percent_delta',
    'hostname_label_count',
)
FEATURES = RESEARCH_FEATURES + ADDITIONAL_FEATURES
AUTH = ('login', 'signin', 'password', 'verify', 'account', 'credential', 'authenticate')
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly'}


def features(value):
    url = canonical_url(value)
    _, group, _, numeric = url_features(url)
    parts = urlsplit(url)
    host = parts.hostname or ''
    text_host = host[4:] if host.startswith('www.') else host
    authority = (parts.netloc.rsplit('@', 1)[0]+'@' if '@' in parts.netloc else '')+text_host
    if parts.port: authority += ':'+str(parts.port)
    text = authority+parts.path+('?' + parts.query if parts.query else '')+('#'+parts.fragment if parts.fragment else '')
    decoded_query = unquote(parts.query).lower()
    fragment = unquote(parts.fragment).lower()
    try:
        raw_host = idna.decode(host, uts46=True)
    except idna.IDNAError:
        raw_host = host
    extras = (
        text_entropy(url), sum(not c.isalnum() for c in url)/len(url),
        max((len(m.group()) for m in re.finditer(r'(.)\1*', url)), default=0),
        int(any(ord(c) > 127 for c in raw_host)),
        sum('\u0370' <= c <= '\u052f' for c in raw_host),
        len(parts.fragment), sum(fragment.count(w) for w in AUTH), text_entropy(parts.fragment),
        int(host in SHORTENERS), sum(decoded_query.count(w) for w in AUTH),
        len(parts.netloc.rsplit('@', 1)[0]) if '@' in parts.netloc else 0,
        len(re.findall(r'https?://', unquote(url), re.I))-1,
        len(url)-len(unquote(url)), host.count('.')+1,
    )
    return url, group, text, np.concatenate([numeric, np.asarray(extras, dtype=np.float32)])


class PhishingCandidate:
    """Small inference-only bundle; the hybrid index is not a probability."""
    classes_ = np.array([0, 1])

    def __init__(self, models, columns, vectorizer, weights):
        self.models, self.columns = models, columns
        self.vectorizer, self.weights = vectorizer, weights

    def predict_proba(self, urls):
        rows = [features(url) for url in urls]
        numeric = np.asarray([row[3] for row in rows])
        result = np.zeros(len(rows))
        for name, weight in self.weights.items():
            values = (self.vectorizer.transform([row[2] for row in rows]) if name.startswith('char_')
                      else numeric[:, self.columns[name]])
            model = self.models[name]
            result += weight*model.predict_proba(values)[:, list(model.classes_).index(1)]
        return np.column_stack((1-result, result))
