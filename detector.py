"""Shared URL features and explicit rules. Submitted sites are never contacted."""

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit, urlunsplit

import idna
import tldextract

# Bundled suffix list: no runtime network requests, including during training.
SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
KEYWORDS = ('login', 'verify', 'password', 'account', 'secure', 'update', 'signin', 'bank')
FEATURE_NAMES = (
    'url_length', 'hostname_length', 'path_length', 'query_length', 'subdomains',
    'dots', 'hyphens', 'digits', 'digit_ratio', 'ats', 'percent_signs',
    'question_marks', 'equals', 'slashes', 'keyword_count', 'https',
    'ip_hostname', 'punycode', 'explicit_port', 'hostname_entropy',
    'path_entropy', 'hostname_digit_ratio', 'longest_path_segment', 'opaque_path_token',
    'encoded_destination', 'userinfo', 'brand_in_subdomain', 'hostname_keywords',
    'path_keywords', 'known_suffix', 'path_depth', 'query_parameters',
)


def text_entropy(value):
    if not value:
        return 0.0
    return -sum((count / len(value)) * math.log2(count / len(value))
                for count in Counter(value).values())


def parse_url(value):
    if not isinstance(value, str):
        raise ValueError('Enter a URL as text.')
    value = value.strip()
    if not value or len(value) > 4096:
        raise ValueError('Enter a URL between 1 and 4,096 characters.')
    if re.search(r'\s|[\x00-\x1f\x7f\\]', value):
        raise ValueError('URL must not contain whitespace, control characters or backslashes.')
    if re.search(r'%(?![0-9a-fA-F]{2})', value):
        raise ValueError('URL contains invalid percent encoding.')
    # Require an explicit scheme so ambiguous values cannot silently change meaning.
    parts = urlsplit(value)
    if parts.scheme.lower() not in ('http', 'https') or not parts.netloc:
        raise ValueError('Enter a complete URL starting with http:// or https://.')
    host = parts.hostname
    if not host:
        raise ValueError('URL must contain a hostname.')
    try:
        host = host.rstrip('.')
        # Preserve IPv6; use modern IDNA for domains (ß must not become ss).
        if ':' not in host:
            host = idna.encode(host, uts46=True, std3_rules=True).decode('ascii').lower()
        port = parts.port  # Validates malformed and out-of-range ports.
    except (UnicodeError, ValueError) as exc:
        raise ValueError('Invalid hostname or port.') from exc
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
        labels = host.split('.')
        if len(host) > 253 or len(labels) < 2 or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in labels
        ) or labels[-1].isdigit():
            raise ValueError('Enter a valid domain name or IP address.')
    # Strip fragments and normalize scheme/host for duplicate detection.
    hostname = f'[{host}]' if ':' in host else host
    userinfo = parts.netloc.rsplit('@', 1)[0] + '@' if '@' in parts.netloc else ''
    authority = userinfo + hostname + (f':{port}' if port is not None else '')
    normalized = urlunsplit((parts.scheme.lower(), authority, parts.path or '/', parts.query, ''))
    return normalized, urlsplit(normalized), host, is_ip


def extract_features(value):
    url, parts, host, is_ip = parse_url(value)
    original_url = url
    # UCI collection styles differ in their use of www. Make lexical features
    # invariant to that conventional prefix instead of learning a label shortcut.
    # This changes feature measurement only; never rewrite or visit the submitted URL.
    if host.startswith('www.') and not is_ip:
        host = host[4:]
        userinfo, separator, authority = parts.netloc.rpartition('@')
        authority = authority[4:]
        url = urlunsplit(parts._replace(netloc=userinfo + separator + authority))
    suffix = SUFFIXES(host) if not is_ip else None
    subdomains = len(suffix.subdomain.split('.')) if suffix and suffix.subdomain else 0
    digits = sum(c.isdigit() for c in url)
    entropy = text_entropy(host)
    segments = [segment for segment in parts.path.split('/') if segment]
    opaque = any(re.fullmatch(r'[0-9a-fA-F]{24,}|[A-Za-z0-9_-]{32,}', segment)
                 for segment in segments)
    subdomain_text = suffix.subdomain.lower() if suffix else ''
    brands = ('paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix')
    brand_in_subdomain = any(brand in subdomain_text.split('.') for brand in brands)
    values = (
        len(url), len(host), len(parts.path), len(parts.query), subdomains,
        url.count('.'), url.count('-'), digits, digits / len(url), url.count('@'),
        url.count('%'), url.count('?'), url.count('='), url.count('/'),
        sum(word in url.lower() for word in KEYWORDS), int(parts.scheme == 'https'),
        int(is_ip), int(any(label.startswith('xn--') for label in host.split('.'))),
        int(parts.port is not None), entropy, text_entropy(parts.path),
        sum(c.isdigit() for c in host) / len(host), max(map(len, segments), default=0),
        int(opaque), int(bool(re.search(r'https?://', unquote(parts.path + '?' + parts.query), re.I))),
        int(parts.username is not None), int(brand_in_subdomain),
        sum(word in host for word in KEYWORDS),
        sum(word in parts.path.lower() for word in KEYWORDS),
        int(bool(suffix and suffix.suffix)), len(segments), parts.query.count('&') + bool(parts.query),
    )
    group = host if is_ip else (suffix.top_domain_under_public_suffix or host)
    return original_url, dict(zip(FEATURE_NAMES, values)), group


def evaluate_rules(features):
    checks = (
        (features['ip_hostname'], .35, 'Hostname is an IP address.'),
        (features['ats'], .35, 'URL contains @; text before it may disguise the destination.'),
        (features['subdomains'] >= 3, .20, 'Hostname has three or more subdomains.'),
        (features['url_length'] > 150, .15, 'URL is longer than 150 characters.'),
        (features['hyphens'] >= 4, .10, 'URL contains four or more hyphens.'),
        (features['digit_ratio'] > .25, .10, 'More than a quarter of the URL is digits.'),
        (features['keyword_count'] >= 2, .15, 'URL contains multiple account/security keywords.'),
        (not features['https'], .10, 'URL uses HTTP rather than HTTPS.'),
        (features['punycode'], .15, 'Hostname uses punycode; inspect possible lookalike text.'),
        (features['percent_signs'] >= 4, .10, 'URL contains substantial percent encoding.'),
        (features.get('opaque_path_token', 0), .15, 'Path contains a long opaque token; legitimate session links can also contain these.'),
        (features.get('brand_in_subdomain', 0), .25, 'A familiar brand appears in a subdomain rather than the registered domain.'),
        (features.get('encoded_destination', 0), .10, 'Path or query contains another URL; inspect the final destination independently.'),
    )
    indicators = [message for active, _, message in checks if active]
    return min(1.0, sum(weight for active, weight, _ in checks if active)), indicators


def hybrid_score(probability, rule_score, model_weight=.8):
    # A risk index, not a calibrated probability. Weight is frozen before testing.
    return model_weight * probability + (1 - model_weight) * rule_score


def analyze(value, artifact):
    url, features, _ = extract_features(value)
    rule_score, indicators = evaluate_rules(features)
    vector = [[features[name] for name in FEATURE_NAMES]]
    model = artifact['model']
    phishing_column = list(model.classes_).index(1)
    probability = float(model.predict_proba(vector)[0, phishing_column])
    score = hybrid_score(probability, rule_score, artifact.get('model_weight', .8))
    threshold = artifact['threshold']
    phishing = score >= threshold
    risk = 'High' if phishing else ('Medium' if score >= min(.3, threshold * .6)
                                   or rule_score >= .4 else 'Low')
    return dict(url=url, prediction='Potential phishing' if phishing else 'Potentially legitimate',
                risk=risk, model_score=round(probability * 100, 1),
                rule_score=round(rule_score * 100, 1), hybrid_score=round(score * 100, 1),
                threshold=round(threshold * 100, 1), indicators=indicators,
                model_prediction='Phishing' if probability >= artifact.get('model_threshold', artifact.get('rf_threshold', .5)) else 'Legitimate',
                model_name=artifact.get('model_name', 'Random Forest'),
                model_weight=artifact.get('model_weight', .8),
                features=features, model_version=artifact['trained_at'],
                calibrated=artifact.get('calibrated', False))
