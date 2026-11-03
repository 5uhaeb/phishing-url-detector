"""Clean an explicitly supplied URL dataset; no automatic UCI mixing/downloads."""
import hashlib
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from detector import extract_features

ROOT=Path(__file__).resolve().parent


def load_dataset(args):
    path=args.dataset
    frame=pd.read_json(path) if path.suffix.lower()=='.json' else pd.read_csv(path)
    url_column=next((name for name in ['url','URL','text'] if name in frame.columns),None)
    if not url_column or 'label' not in frame.columns:
        raise ValueError('Dataset must contain url/URL/text and label columns.')
    labels=pd.to_numeric(frame.label,errors='raise')
    if labels.isna().any() or set(labels.unique())!={0,1}:
        raise ValueError('Provide both classes with labels exactly 0 or 1; missing/non-binary labels are rejected.')
    frame=frame.copy();frame['label']=labels.astype(int)
    raw_count=len(frame)
    if args.max_rows and len(frame)>args.max_rows:
        frame,_=train_test_split(frame,train_size=args.max_rows,stratify=frame.label,random_state=42)
    records=[];invalid=0;inferred=0
    for row in frame.itertuples(index=False,name=None):
        record=dict(zip(frame.columns,row));value=record[url_column]
        if isinstance(value,str) and args.infer_https and '://' not in value:
            value='https://'+value;inferred+=1
        try:normalized,features,group=extract_features(value)
        except (TypeError,ValueError):invalid+=1;continue
        records.append(dict(url=normalized,group=group,target=int(record['label']==args.positive_label),
                            source=str(record.get('source',args.dataset_name)),**features))
    clean=pd.DataFrame(records)
    if clean.empty:raise ValueError('No valid URLs found.')
    conflicts=clean.groupby('url').target.nunique();bad=conflicts[conflicts>1].index
    conflicting_rows=int(clean.url.isin(bad).sum());clean=clean[~clean.url.isin(bad)]
    before=len(clean);clean=clean.drop_duplicates('url').reset_index(drop=True)
    if clean.target.nunique()!=2:raise ValueError('Cleaning left fewer than two classes.')
    provenance=[dict(name=args.dataset_name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        raw_rows=raw_count,sampled_rows=len(frame),usable_rows=len(clean),invalid_rows=invalid,
        contradictory_urls=len(bad),contradictory_rows=conflicting_rows,duplicates_removed=before-len(clean),
        positive_input_label=args.positive_label,positive_class=args.target_name,
        inferred_https_schemes=inferred,feature_policy='32 shared offline features; conventional www ignored')]
    print(f'Cleaned {len(clean):,} URLs from {args.dataset_name}.',flush=True)
    return clean,provenance,raw_count,invalid,path
