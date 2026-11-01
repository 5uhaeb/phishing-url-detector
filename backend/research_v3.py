"""Improvement experiment with validation-only selection and a locked final test.

First acquire the upstream TRAIN split, run --stage train, then acquire TEST and
run --stage test once. No script modifies backend/models or the live service.
"""
import argparse
import gc
import hashlib
import json
from pathlib import Path
from time import perf_counter
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_curve, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from detector import FEATURE_NAMES, SUFFIXES, evaluate_rules, hybrid_score
from metrics import metrics, tune_threshold
from research_models import RESEARCH_FEATURES, SHAPE_FEATURES, URLResearchCandidate, domain_partition, url_features

ROOT = Path(__file__).resolve().parent
DATA = ROOT/'data/research_v3'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(split):
    cache = DATA/f'{split}_clean.joblib'
    if cache.exists():
        return joblib.load(cache)
    paths = sorted((DATA/split).glob('*.csv'))
    if not paths:
        raise ValueError(f'Acquire the upstream {split} split first.')
    raw = pd.concat([pd.read_csv(path) for path in paths], ignore_index=True)
    if set(raw.label.unique()) != {'phish', 'benign'}:
        raise ValueError('Unexpected upstream labels.')
    records, vectors, invalid = [], [], 0
    for index, row in enumerate(raw.itertuples(index=False)):
        try:
            normalized, group, text, features = url_features(row.url)
        except (ValueError, TypeError):
            invalid += 1
            continue
        records.append(dict(url=normalized, group=group, text=text, label=int(row.label=='phish'),
                            date=row.date, sha256=row.sha256))
        vectors.append(features)
        if index and index % 100000 == 0:
            print(f'{split} features: {index:,}/{len(raw):,}', flush=True)
    frame = pd.DataFrame(records)
    numeric = np.asarray(vectors, dtype=np.float32)
    conflicts = frame.groupby('url').label.nunique()
    keep = ~frame.url.isin(conflicts[conflicts > 1].index) & ~frame.url.duplicated()
    frame, numeric = frame.loc[keep].reset_index(drop=True), numeric[keep.to_numpy()]
    info = dict(raw_rows=len(raw), valid_rows=len(frame), invalid_rows=invalid,
                conflicting_urls=int((conflicts>1).sum()),
                files={str(path.relative_to(DATA)):digest(path) for path in paths})
    result = frame, numeric, info
    joblib.dump(result, cache, compress=3)
    return result


def f1_threshold(y, scores):
    precision, recall, thresholds = precision_recall_curve(y, scores)
    f1 = np.divide(2*precision[:-1]*recall[:-1], precision[:-1]+recall[:-1],
                   out=np.zeros(len(thresholds)), where=(precision[:-1]+recall[:-1])>0)
    return float(thresholds[int(np.argmax(f1))])


def measured(y, scores, threshold):
    result = metrics(y, scores >= threshold)
    result.update(rows=len(y), legitimate=int((y==0).sum()), phishing=int((y==1).sum()),
                  threshold=float(threshold), roc_auc=float(roc_auc_score(y, scores)),
                  pr_auc=float(average_precision_score(y, scores)))
    # Precision under specified prevalence makes the operating-point cost clear.
    for prevalence in [.001, .01, .05]:
        tp = result['recall']*prevalence
        fp = result['false_positive_rate']*(1-prevalence)
        result[f'precision_at_prevalence_{prevalence}'] = tp/(tp+fp) if tp+fp else None
    return result


def train(output):
    if output.exists():
        raise ValueError('Use a new output path; never overwrite a frozen experiment.')
    started = perf_counter()
    frame, numeric, info = prepare('train')
    partition = frame.group.map(domain_partition)
    indexes = {name:np.flatnonzero(partition.to_numpy()==name) for name in ['training','calibration','validation']}
    for name, idx in indexes.items():
        if frame.label.iloc[idx].nunique() != 2:
            raise ValueError(f'{name} needs both classes.')
    groups = {name:set(frame.group.iloc[idx]) for name, idx in indexes.items()}
    assert not groups['training']&groups['validation'] and not groups['calibration']&groups['validation'] and not groups['training']&groups['calibration']
    fit, cal, val = (indexes[key] for key in ['training','calibration','validation'])
    y = frame.label.to_numpy()
    columns = {name:np.arange(numeric.shape[1]) for name in ['lightgbm','xgboost']}
    columns['shape_reduced'] = np.array([i for i,name in enumerate(RESEARCH_FEATURES) if name not in SHAPE_FEATURES])
    bases = {
        'lightgbm':LGBMClassifier(n_estimators=600,learning_rate=.04,num_leaves=40,min_child_samples=50,
            colsample_bytree=.85,reg_lambda=5,class_weight='balanced',random_state=42,n_jobs=4,verbosity=-1,deterministic=True,force_col_wise=True),
        'xgboost':XGBClassifier(n_estimators=650,max_depth=7,learning_rate=.04,min_child_weight=5,
            subsample=.85,colsample_bytree=.85,reg_lambda=5,objective='binary:logistic',eval_metric='logloss',
            scale_pos_weight=float((y[fit]==0).sum()/max(1,(y[fit]==1).sum())),random_state=42,n_jobs=4,tree_method='hist'),
        'shape_reduced':LGBMClassifier(n_estimators=600,learning_rate=.04,num_leaves=40,min_child_samples=50,
            colsample_bytree=.85,reg_lambda=5,class_weight='balanced',random_state=42,n_jobs=4,verbosity=-1,deterministic=True,force_col_wise=True),
    }
    estimators, val_scores = {}, {}
    for name, base in bases.items():
        print(f'Training {name}: {len(fit):,} fit rows, {len(cal):,} calibration rows...', flush=True)
        c = columns[name]
        base.fit(numeric[fit][:,c], y[fit])
        base.set_params(n_jobs=1)
        model = CalibratedClassifierCV(FrozenEstimator(base),method='sigmoid')
        model.fit(numeric[cal][:,c],y[cal])
        estimators[name] = model
        val_scores[name] = model.predict_proba(numeric[val][:,c])[:,1]
    print('Training www/scheme-invariant character model...', flush=True)
    sample = fit
    if len(sample) > 180000:
        sample,_ = train_test_split(sample,train_size=180000,stratify=y[sample],random_state=42)
    vectorizer = TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=5,max_features=50000,
                                 sublinear_tf=True,dtype=np.float32)
    sparse = vectorizer.fit_transform(frame.text.iloc[sample])
    base = SGDClassifier(loss='log_loss',alpha=1e-5,max_iter=35,tol=1e-4,class_weight='balanced',random_state=42,n_jobs=4)
    base.fit(sparse,y[sample])
    del sparse
    gc.collect()
    model = CalibratedClassifierCV(FrozenEstimator(base),method='sigmoid')
    model.fit(vectorizer.transform(frame.text.iloc[cal]),y[cal])
    estimators['character'] = model
    val_scores['character'] = model.predict_proba(vectorizer.transform(frame.text.iloc[val]))[:,1]
    weights = {name:{name:1.} for name in estimators}
    for fraction in [.25,.5,.75]:
        weights[f'lightgbm_character_{fraction}'] = {'lightgbm':1-fraction,'character':fraction}
    weights['tree_average'] = {'lightgbm':.5,'xgboost':.5}
    weights['three_way'] = {'lightgbm':.4,'xgboost':.4,'character':.2}
    weights['reduced_character'] = {'shape_reduced':.5,'character':.5}
    policies, rows = {}, []
    for name, mixture in weights.items():
        scores = sum(weight*val_scores[base] for base,weight in mixture.items())
        policies[name] = {'fpr_1pct':tune_threshold(y[val],scores,.01), 'balanced_f1':f1_threshold(y[val],scores)}
        for policy,threshold in policies[name].items():
            rows.append(dict(model=name,policy=policy,**measured(y[val],scores,threshold)))
    winners = {}
    for policy in ['fpr_1pct','balanced_f1']:
        candidates = [row for row in rows if row['policy']==policy]
        best = max(candidates,key=lambda row:(row['recall'],row['precision'])) if policy=='fpr_1pct' else max(candidates,key=lambda row:(row['f1'],row['precision']))
        winners[policy] = best['model']
    output.mkdir(parents=True)
    bundle = dict(estimators=estimators,vectorizer=vectorizer,columns=columns,weights=weights,thresholds=policies)
    joblib.dump(bundle,output/'research_bundle.joblib',compress=3)
    protocol = dict(dataset='phreshphish/phreshphish',upstream=json.loads((DATA/'upstream_manifest.json').read_text())['revision'],
        training_info=info,features=list(RESEARCH_FEATURES),training_rows=len(frame),
        partitions={name:dict(rows=len(idx),domains=len(groups[name]),phishing=int(y[idx].sum()),
                    min_date=str(frame.date.iloc[idx].min()),max_date=str(frame.date.iloc[idx].max())) for name,idx in indexes.items()},
        winners=winners,weights=weights,thresholds=policies,bundle_sha256=digest(output/'research_bundle.joblib'),
        source_code_sha256={name:digest(ROOT/name) for name in ['research_v3.py','research_models.py','research_data.py']},
        policy='Selection uses upstream train partition only; final test is scored once after this protocol is frozen.',
        primary_test='provided test URLs and domains absent from all PhreshPhish train records; paired baseline also excludes prior combined-corpus domains',
        temporal_audit='Report observed collection ranges and a strictly-later-than-train subset separately; never infer missing timestamps.',
        runtime_seconds=perf_counter()-started)
    (output/'frozen_protocol.json').write_text(json.dumps(protocol,indent=2))
    np.savez_compressed(output/'development_indices.npz',**indexes)
    pd.DataFrame(rows).to_csv(output/'validation_scores.csv',index=False)
    print(pd.DataFrame(rows)[['model','policy','accuracy','precision','recall','f1','false_positive_rate']].round(4).to_string(index=False),flush=True)
    print('Frozen validation winners:',winners,flush=True)
    print('Final test has not been read. Training minutes:',round((perf_counter()-started)/60,2),flush=True)


def test(output):
    marker = output/'final_test_started.json'
    if marker.exists():
        raise ValueError('Final test already started. Do not tune and rerun against this same test.')
    protocol=json.loads((output/'frozen_protocol.json').read_text())
    if digest(output/'research_bundle.joblib') != protocol['bundle_sha256']:
        raise ValueError('The frozen model bundle changed.')
    for name,expected in protocol['source_code_sha256'].items():
        if digest(ROOT/name)!=expected:
            raise ValueError(f'Frozen experiment source changed: {name}')
    marker.write_text(json.dumps(dict(protocol_sha256=digest(output/'frozen_protocol.json'))))
    bundle=joblib.load(output/'research_bundle.joblib')
    training,_,_=prepare('train')
    frame,numeric,info=prepare('test')
    overlap=frame.group.isin(set(training.group)) | frame.url.isin(set(training.url))
    primary=~overlap.to_numpy()
    old=pd.read_csv(Path.home()/'Downloads/LinkGuard-Combined-Dataset/combined_phishing_dataset.csv',usecols=['url'])
    old_groups=set()
    for value in old.url:
        host=urlsplit(value).hostname or ''
        if host.startswith('www.'):host=host[4:]
        old_groups.add(SUFFIXES(host).top_domain_under_public_suffix or host)
    paired=primary&~frame.group.isin(old_groups).to_numpy()
    train_max=pd.to_datetime(training.date,errors='coerce').max()
    later=primary&(pd.to_datetime(frame.date,errors='coerce')>train_max).to_numpy()
    cohorts={'new_model_unseen_domains':primary,'paired_with_existing_model_unseen_domains':paired,
             'strictly_later_unseen_domains':later}
    base_scores={}
    for name,model in bundle['estimators'].items():
        values=bundle['vectorizer'].transform(frame.text) if name=='character' else numeric[:,bundle['columns'][name]]
        base_scores[name]=model.predict_proba(values)[:,1]
    rows=[]
    for name,mixture in bundle['weights'].items():
        scores=sum(weight*base_scores[base] for base,weight in mixture.items())
        for policy,threshold in bundle['thresholds'][name].items():
            for cohort,mask in cohorts.items():
                if frame.label.loc[mask].nunique()!=2:continue
                rows.append(dict(model=name,policy=policy,cohort=cohort,
                                 selected_on_validation=protocol['winners'][policy]==name,
                                 **measured(frame.label.to_numpy()[mask],scores[mask],threshold)))
    deployed=joblib.load(ROOT/'models/xgboost.joblib')
    raw=numeric[:,:len(FEATURE_NAMES)]
    probabilities=deployed['model'].predict_proba(raw)[:,1]
    rules=np.array([evaluate_rules(dict(zip(FEATURE_NAMES,row)))[0] for row in raw])
    scores=hybrid_score(probabilities,rules,deployed.get('model_weight',.8))
    for cohort,mask in [('paired_with_existing_model_unseen_domains',paired)]:
        if frame.label.loc[mask].nunique()==2:
            rows.append(dict(model='existing_deployed_xgboost',policy='existing_frozen_threshold',cohort=cohort,
                selected_on_validation=False,**measured(frame.label.to_numpy()[mask],scores[mask],deployed['threshold'])))
    pd.DataFrame(rows).to_csv(output/'final_test_scores.csv',index=False)
    summary=dict(test_info=info,train_date_max=str(train_max),test_date_min=str(frame.date.min()),test_date_max=str(frame.date.max()),
        cohorts={name:dict(rows=int(mask.sum()),domains=int(frame.loc[mask,'group'].nunique()),phishing=int(frame.loc[mask,'label'].sum())) for name,mask in cohorts.items()},
        excluded_seen_train_rows=int(overlap.sum()),frozen_winners=protocol['winners'],
        limitations=['URL-only features; no HTML, screenshots or reputation were used.',
                     'Domain/URL disjointness was verified; campaign/template disjointness is not independently established.',
                     'Temporal results are only valid for rows with actual collection dates later than every development record.'])
    (output/'final_test_summary.json').write_text(json.dumps(summary,indent=2))
    print(pd.DataFrame(rows).query('selected_on_validation == True')[['model','policy','cohort','rows','accuracy','precision','recall','f1','false_positive_rate']].round(4).to_string(index=False),flush=True)
    selected=protocol['winners']['balanced_f1']
    candidate=URLResearchCandidate(bundle['estimators'],bundle['vectorizer'],bundle['columns'],bundle['weights'][selected])
    joblib.dump(dict(model=candidate,threshold=bundle['thresholds'][selected]['balanced_f1'],
                     selected_on='validation balanced F1',protocol_sha256=digest(output/'frozen_protocol.json')),
                output/'candidate_url_model.joblib',compress=3)
    print('Saved candidate separately from production models.',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',choices=['train','test'],required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    train(args.output) if args.stage=='train' else test(args.output)
