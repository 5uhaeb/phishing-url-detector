"""Train-only URL text features for isolated research; the live API is unchanged."""
import re
from urllib.parse import unquote, urlsplit, urlunsplit

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.decomposition import TruncatedSVD

from detector import FEATURE_NAMES, extract_features, text_entropy


def canonical_text(value):
    """Ignore conventional www and transport spelling in every text feature."""
    parts = urlsplit(value)
    host = parts.hostname.lower()
    if host.startswith('www.'): host = host[4:]
    authority = (parts.username or '') + ('@' if parts.username is not None else '') + host
    if parts.port is not None: authority += ':' + str(parts.port)
    return authority + (parts.path or '/') + ('?' + parts.query if parts.query else '')


def numeric_features(value):
    normalized, base, group = extract_features(value)
    text = canonical_text(normalized)
    parts = urlsplit(normalized)
    host = parts.hostname.lower()
    if host.startswith('www.'): host = host[4:]
    decoded = unquote(parts.path + '?' + parts.query)
    values = [base[key] for key in FEATURE_NAMES]
    for part in (host, parts.path, parts.query, decoded):
        words = re.findall(r'[A-Za-z]+', part)
        runs = re.findall(r'\d+', part)
        values.extend([
            len(part), text_entropy(part), len(words), max(map(len, words), default=0),
            sum(map(len, words)) / max(1, len(words)), len(runs), max(map(len, runs), default=0),
            sum(c.isupper() for c in part), sum(c.isdigit() for c in part),
            sum(c.lower() in 'aeiou' for c in part) / max(1, len(part)),
            len(set(part)) / max(1, len(part)),
        ])
        values.extend(part.count(symbol) for symbol in ('-', '_', '.', '/', '%', '=', '&', '@', '+', ':', '~'))
    lower = text.lower()
    values.extend([
        len(group), len(host) - len(group), len(host.split('.')[-1]),
        len(re.findall(r'[a-z]+\d+[a-z]+', lower)),
        len(re.findall(r'\d+[a-z]+\d+', lower)),
        len(re.findall(r'(.)\1{2,}', lower)),
        max((len(x) for x in re.findall(r'[bcdfghjklmnpqrstvwxyz]+', host)), default=0),
        max((len(x) for x in re.findall(r'[aeiou]+', host)), default=0),
        int(parts.path.endswith('/')), int(bool(parts.query)),
        int(bool(re.search(r'\.(?:php|asp|aspx|html|htm|jsp)(?:/|$)', parts.path, re.I))),
        int(bool(re.search(r'\.(?:zip|exe|apk|scr|msi)(?:/|$)', parts.path, re.I))),
    ])
    return np.asarray(values, dtype=np.float32)


class RichUrlFeatures(BaseEstimator, TransformerMixin):
    """No label, source, date, target brand annotation, or reputation inputs.

    Vocabularies and supervised chi-square feature selection are fitted exclusively
    on training URLs/labels, never calibration, validation, or final-test rows.
    """
    def __init__(self, char_features=2048, word_features=512):
        self.char_features = char_features
        self.word_features = word_features

    def fit(self, urls, y):
        texts = [canonical_text(url)[:1024].lower() for url in urls]
        self.char_vectorizer_ = CountVectorizer(analyzer='char', ngram_range=(3, 5),
            min_df=5, max_features=60000, binary=True, dtype=np.float32)
        self.word_vectorizer_ = CountVectorizer(token_pattern=r'(?u)[a-z]{2,}|[0-9]{2,}',
            min_df=3, max_features=20000, binary=True, dtype=np.float32)
        char = self.char_vectorizer_.fit_transform(texts)
        self.char_selector_ = SelectKBest(chi2, k=min(self.char_features, char.shape[1])).fit(char, y)
        del char
        word = self.word_vectorizer_.fit_transform(texts)
        self.word_selector_ = SelectKBest(chi2, k=min(self.word_features, word.shape[1])).fit(word, y)
        return self

    def transform(self, urls):
        texts = [canonical_text(url)[:1024].lower() for url in urls]
        char = self.char_selector_.transform(self.char_vectorizer_.transform(texts))
        word = self.word_selector_.transform(self.word_vectorizer_.transform(texts))
        numeric = np.stack([numeric_features(url) for url in urls])
        return sparse.hstack([sparse.csr_matrix(numeric), char, word], format='csr', dtype=np.float32)


class LatentUrlFeatures(BaseEstimator, TransformerMixin):
    """Train-only latent text factors, not predictions from another classifier."""
    def __init__(self,n_components=96,sample_rows=75000,random_state=20261103):
        self.n_components=n_components
        self.sample_rows=sample_rows
        self.random_state=random_state

    def fit_matrix(self,matrix,url_features):
        self.url_features_=url_features
        text_columns=(url_features.char_selector_.get_support().sum()+
                      url_features.word_selector_.get_support().sum())
        self.numeric_columns_=matrix.shape[1]-int(text_columns)
        self.tfidf_=TfidfTransformer()
        text=self.tfidf_.fit_transform(matrix[:,self.numeric_columns_:])
        rng=np.random.default_rng(self.random_state)
        sample=rng.choice(len(text.indptr)-1,size=min(matrix.shape[0],self.sample_rows),replace=False)
        self.svd_=TruncatedSVD(n_components=min(self.n_components,text.shape[1]-1),
                              n_iter=5,random_state=self.random_state)
        self.svd_.fit(text[sample])
        return self

    def transform_matrix(self,matrix):
        text=self.tfidf_.transform(matrix[:,self.numeric_columns_:])
        latent=self.svd_.transform(text)
        return np.hstack([matrix[:,:self.numeric_columns_].toarray(),latent]).astype(np.float32)

    def transform(self,urls):
        return self.transform_matrix(self.url_features_.transform(urls))
