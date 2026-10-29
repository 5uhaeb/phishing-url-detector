"""Download, clean and extract the two training datasets."""

import hashlib
import io
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile

import pandas as pd
import requests
from sklearn.model_selection import train_test_split

from detector import extract_features

ROOT = Path(__file__).resolve().parent
DATA_URL = 'https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip'
DATA_FILE = ROOT / 'data' / 'PhiUSIIL_Phishing_URL_Dataset.csv'
SEED = 42
ADDITIONAL_FILE = ROOT / 'data' / 'additional-urls.json'
ADDITIONAL_URL = 'https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/urls.json'


def download_additional():
    ADDITIONAL_FILE.parent.mkdir(exist_ok=True)
    temporary = ADDITIONAL_FILE.with_suffix('.tmp')
    print('Downloading supplementary raw URL dataset (~73 MB)...', flush=True)
    with requests.get(ADDITIONAL_URL, timeout=(5, 60), stream=True) as response:
        response.raise_for_status()
        total = 0
        with temporary.open('wb') as output:
            for chunk in response.iter_content(1024 * 1024):
                total += len(chunk)
                if total > 100_000_000:
                    raise ValueError('Supplementary dataset exceeds size limit.')
                output.write(chunk)
    temporary.replace(ADDITIONAL_FILE)


def download():
    DATA_FILE.parent.mkdir(exist_ok=True)
    print('Downloading UCI PhiUSIIL dataset (about 15 MB)...', flush=True)
    with urlopen(DATA_URL, timeout=120) as response:
        archive = response.read(50 * 1024 * 1024)
    with ZipFile(io.BytesIO(archive)) as zipped:
        names = [name for name in zipped.namelist() if name.endswith(DATA_FILE.name)]
        if len(names) != 1:
            raise ValueError('Dataset archive did not contain the expected CSV.')
        DATA_FILE.write_bytes(zipped.read(names[0]))




def load_dataset(args):
    if args.download and not DATA_FILE.exists():
        download()
    path = args.csv or DATA_FILE
    if not path.exists():
        raise ValueError('Dataset missing. Run python train.py --download first.')
    frame = pd.read_csv(path, usecols=['URL', 'label'])[['URL', 'label']].dropna()
    frame['source'] = 'UCI PhiUSIIL'
    raw_count = len(frame)
    provenance = [dict(name='UCI PhiUSIIL', rows=len(frame), source=DATA_URL, license='CC BY 4.0',
                       sha256=hashlib.sha256(path.read_bytes()).hexdigest())]
    if not set(frame.label.unique()).issubset({0, 1}) or frame.label.nunique() != 2:
        raise ValueError('Expected UCI labels: 0=phishing and 1=legitimate, with both classes.')
    if not args.no_additional_data:
        extra_path = args.additional_data
        if not extra_path.exists() and args.download and extra_path == ADDITIONAL_FILE:
            download_additional()
        if not extra_path.exists():
            raise ValueError('Supplementary dataset missing. Use --download, or explicitly --no-additional-data for the biased UCI-only baseline.')
        extra = pd.read_json(extra_path)[['text', 'label']].dropna()
        if not set(extra.label.unique()).issubset({0, 1}) or extra.label.nunique() != 2:
            raise ValueError('Supplementary labels must be 1=phishing, 0=legitimate.')
        extra_raw_count = len(extra)
        if args.additional_limit and len(extra) > args.additional_limit:
            extra, _ = train_test_split(extra, train_size=args.additional_limit,
                                        stratify=extra.label, random_state=SEED)
        # Original corpus includes bare URLs. Apply the same documented scheme
        # convention to both classes, never only to benign samples.
        missing_scheme = ~extra.text.str.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
        extra.loc[missing_scheme, 'text'] = 'https://' + extra.loc[missing_scheme, 'text']
        extra = extra.rename(columns={'text': 'URL'})
        extra['label'] = 1 - extra['label'].astype(int)  # Match UCI convention until extraction.
        extra['source'] = 'ealvaradob raw URLs'
        provenance.append(dict(name='ealvaradob raw URLs', source=ADDITIONAL_URL,
            card='https://huggingface.co/datasets/ealvaradob/phishing-dataset',
            license='Apache-2.0 as declared by dataset publisher; underlying sources listed on dataset card',
            raw_rows=extra_raw_count, sampled_rows=len(extra), inferred_https_schemes=int(missing_scheme.sum()),
            sha256=hashlib.sha256(extra_path.read_bytes()).hexdigest()))
        frame = pd.concat([frame, extra], ignore_index=True)
        raw_count = len(frame)
    # Remove contradictory exact labels, then sample without using test labels to tune anything.
    conflicts = frame.groupby('URL').label.nunique()
    frame = frame[~frame.URL.isin(conflicts[conflicts > 1].index)].drop_duplicates('URL')
    if args.max_rows and len(frame) > args.max_rows:
        frame, _ = train_test_split(frame, train_size=args.max_rows,
                                    stratify=frame.label, random_state=SEED)
    print(f'Extracting text features from {len(frame):,} URLs...', flush=True)
    records = []
    invalid = 0
    for url, label, source in frame[['URL', 'label', 'source']].itertuples(index=False, name=None):
        try:
            normalized, features, group = extract_features(url)
        except ValueError:
            invalid += 1
            continue
        records.append(dict(url=normalized, group=group, target=1 - int(label), source=source, **features))
    clean = pd.DataFrame(records)
    if clean.empty:
        raise ValueError('No valid URLs found.')
    normalized_conflicts = clean.groupby('url').target.nunique()
    clean = clean[~clean.url.isin(normalized_conflicts[normalized_conflicts > 1].index)]
    clean = clean.drop_duplicates('url').reset_index(drop=True)
    return clean, provenance, raw_count, invalid, path
