"""Typed phishing research: prepare -> train/freeze -> independently evaluate.

No model or threshold is selected using the fresh feed holdouts. No URL in a
dataset is visited. Production models are read-only baselines.
"""
import argparse
import gc
import hashlib
import json
from pathlib import Path
from time import perf_counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier, early_stopping
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from detector import FEATURE_NAMES, SUFFIXES, evaluate_rules, hybrid_score
from metrics import tune_threshold
from research_audit import _safe_metrics
from research_features import FEATURES, FEATURE_VERSION, PhishingCandidate, features
from research_v3 import f1_threshold

ROOT = Path(__file__).resolve().parent
DATA = ROOT/'data/capstone_run'
CODE = ['phishing_benchmark.py', 'research_features.py', 'research_models.py',
        'detector.py', 'reputation.py', 'metrics.py', 'feeds.py',
        'research_audit.py', 'research_report.py', 'research_v3.py']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def partition(group):
    value = int(hashlib.sha256(('20261101:'+group).encode()).hexdigest()[:12], 16) % 10000
    return 'fit' if value < 6000 else 'calibration' if value < 7000 else 'validation' if value < 8000 else 'test'


def clean(records):
    rows, vectors, invalid = [], [], 0
    for i, record in enumerate(records):
        try:
            url, group, text, vector = features(record['url'])
        except (ValueError, TypeError):
            invalid += 1
            continue
        rows.append(dict(record, url=url, group=group, text=text))
        vectors.append(vector)
        if i and i % 100000 == 0: print(f'Features: {i:,}', flush=True)
    frame, numeric = pd.DataFrame(rows), np.asarray(vectors, dtype=np.float32)
    conflicts = frame.groupby('url').kind.nunique()
    bad = conflicts[conflicts > 1].index
    keep = ~frame.url.isin(bad) & ~frame.url.duplicated()
    info = dict(raw_rows=len(records), invalid_rows=invalid, conflicting_urls=len(bad),
                conflicting_rows=int(frame.url.isin(bad).sum()),
                duplicate_rows=int((~frame.url.isin(bad) & frame.url.duplicated()).sum()),
                cleaned_rows=int(keep.sum()))
    return frame.loc[keep].reset_index(drop=True), numeric[keep.to_numpy()], info


def prepare(source_directory=None):
    DATA.mkdir(parents=True, exist_ok=True)
    if (DATA/'development.joblib').exists():
        raise ValueError('Prepared data already exists; use the recorded cache.')
    files = sorted((ROOT/'data/research_v3/train').glob('*.csv'))
    if len(files) != 56: raise ValueError('Acquire all 56 pinned PhreshPhish TRAIN metadata shards first.')
    phresh = pd.concat([pd.read_csv(p) for p in files], ignore_index=True)
    if set(phresh.label.unique()) != {'phish', 'benign'}: raise ValueError('Unexpected PhreshPhish labels')
    records = [dict(url=r.url, kind=1 if r.label=='phish' else 0, source='PhreshPhish',
                    collected_at=r.date) for r in phresh.itertuples(index=False)]
    old = source_directory or Path.home()/'Downloads/phishing-url-detector/data'
    extra = pd.read_json(old/'additional-urls.json')
    if not set(extra.label.unique()).issubset({0,1}): raise ValueError('Unexpected supplementary labels')
    benign = extra[extra.label==0].sample(n=100000, random_state=20261101)
    for url in benign.text:
        if '://' not in url: url='https://'+url
        records.append(dict(url=url, kind=0, source='ealvaradob_benign', collected_at=None))
    kaggle = pd.read_csv(old/'kaggle-real-world-phishing/phishing_url_dataset_unique.csv')
    malware = kaggle[kaggle.source=='urlhaus']
    if set(malware.label.unique()) != {1}: raise ValueError('Unexpected URLhaus labels')
    records.extend(dict(url=url, kind=2, source='URLhaus_historical', collected_at=None) for url in malware.url)
    frame, numeric, info = clean(records)
    frame['partition'] = frame.group.map(partition)
    for name, part in frame.groupby('partition'):
        if set(part.kind.unique()) != {0,1,2}: raise ValueError(f'{name} missing a class')
    source_paths = [*files, old/'additional-urls.json', old/'kaggle-real-world-phishing/phishing_url_dataset_unique.csv']
    info.update(label_map={'0':'legitimate','1':'phishing','2':'malware'},
                feature_version=FEATURE_VERSION, features=list(FEATURES),
                source_sha256={str(p):digest(p) for p in source_paths},
                partitions={name:dict(rows=len(part), domains=part.group.nunique(),
                    types={str(k):int(v) for k,v in part.kind.value_counts().items()},
                    sources={str(k):int(v) for k,v in part.source.value_counts().items()})
                    for name,part in frame.groupby('partition')})
    joblib.dump((frame,numeric), DATA/'development.joblib', compress=3)
    (DATA/'dataset_audit.json').write_text(json.dumps(info,indent=2))
    print(json.dumps({k:v for k,v in info.items() if k!='source_sha256'},indent=2),flush=True)


def policies(y, p):
    precision, recall, thresholds = precision_recall_curve(y,p)
    eligible = np.flatnonzero(precision[:-1] >= .95)
    constrained = float(thresholds[eligible[np.argmax(recall[:-1][eligible])]]) if len(eligible) else float(np.nextafter(1.,np.inf))
    return dict(fpr_1pct=tune_threshold(y,p,.01), fpr_05pct=tune_threshold(y,p,.005),
                max_f1=f1_threshold(y,p), precision_95=constrained)


def measured(y,p,threshold):
    result = _safe_metrics(y,p>=threshold)
    both = len(np.unique(y))==2
    result.update(rows=len(y),threshold=float(threshold),
                  roc_auc=float(roc_auc_score(y,p)) if both else None,
                  pr_auc=float(average_precision_score(y,p)) if both else None)
    return result


def train(output):
    if output.exists(): raise ValueError('Use a new output path, never overwrite an experiment.')
    output.mkdir(parents=True)
    started=perf_counter()
    frame,x=joblib.load(DATA/'development.joblib')
    kind=frame.kind.to_numpy()
    splits={name:np.flatnonzero(frame.partition.to_numpy()==name) for name in ['fit','calibration','validation','test']}
    fit=splits['fit']
    if len(fit)>180000:
        fit,_=train_test_split(fit,train_size=180000,stratify=frame.source.iloc[fit].astype(str)+'_'+frame.kind.iloc[fit].astype(str),random_state=20261101)
    phish_fit=fit[kind[fit]!=2]; cal=splits['calibration'];cal=cal[kind[cal]!=2]
    val=splits['validation'];val=val[kind[val]!=2];y=(kind==1).astype(int)
    specs={
        'rf_120':RandomForestClassifier(n_estimators=120,max_depth=20,min_samples_split=4,min_samples_leaf=4,max_features='sqrt',class_weight='balanced',n_jobs=4,random_state=42),
        'rf_200':RandomForestClassifier(n_estimators=200,max_depth=24,min_samples_split=2,min_samples_leaf=2,max_features=.7,class_weight='balanced_subsample',n_jobs=4,random_state=42),
        'xgb_450':XGBClassifier(n_estimators=450,max_depth=5,learning_rate=.05,min_child_weight=5,subsample=.85,colsample_bytree=.85,gamma=.1,reg_lambda=8,n_jobs=4,tree_method='hist',random_state=42),
        'xgb_650':XGBClassifier(n_estimators=650,max_depth=7,learning_rate=.04,min_child_weight=5,subsample=.9,colsample_bytree=.85,gamma=0,reg_lambda=5,n_jobs=4,tree_method='hist',random_state=42),
        'lgb_400':LGBMClassifier(n_estimators=400,num_leaves=31,learning_rate=.05,min_child_samples=50,reg_lambda=5,n_jobs=4,verbosity=-1,random_state=42,deterministic=True,force_col_wise=True),
        'lgb_600':LGBMClassifier(n_estimators=600,num_leaves=47,learning_rate=.04,min_child_samples=50,reg_lambda=8,n_jobs=4,verbosity=-1,random_state=42,deterministic=True,force_col_wise=True),
    }
    # A retrained ablation checks whether the extra 14 features help.
    specs['xgb_original50']=XGBClassifier(n_estimators=450,max_depth=5,learning_rate=.05,min_child_weight=5,subsample=.85,colsample_bytree=.85,gamma=.1,reg_lambda=8,n_jobs=4,tree_method='hist',random_state=42)
    models,columns,timing,scores={}, {}, {}, {}
    def fit_model(name,base,training,calibration,target,cols):
        tick=perf_counter()
        stopping=splits['validation']
        if name=='malware_specialist':stopping=stopping[kind[stopping]!=1]
        elif name not in ['binary_malicious','three_class']:stopping=stopping[kind[stopping]!=2]
        kwargs={}
        if isinstance(base,XGBClassifier):
            base.set_params(early_stopping_rounds=40)
            kwargs=dict(eval_set=[(x[stopping][:,cols],target[stopping])],verbose=False)
        elif isinstance(base,LGBMClassifier):
            kwargs=dict(eval_set=[(x[stopping][:,cols],target[stopping])],callbacks=[early_stopping(40,verbose=False)])
        base.fit(x[training][:,cols],target[training],**kwargs);base.set_params(n_jobs=1)
        model=CalibratedClassifierCV(FrozenEstimator(base),method='sigmoid')
        model.fit(x[calibration][:,cols],target[calibration])
        models[name]=model;columns[name]=cols;timing[name]=perf_counter()-tick
        scores[name]=model.predict_proba(x[val][:,cols])[:,list(model.classes_).index(1)]
        print(f'Finished {name}: {timing[name]:.1f}s',flush=True)
    for name,base in specs.items():
        print('Training',name,flush=True)
        fit_model(name,base,phish_fit,cal,y,np.arange(50 if name=='xgb_original50' else x.shape[1]))
    vectorizer=TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=5,max_features=60000,sublinear_tf=True,dtype=np.float32)
    sample=phish_fit
    if len(sample)>120000:sample,_=train_test_split(sample,train_size=120000,stratify=y[sample],random_state=42)
    sparse=vectorizer.fit_transform(frame.text.iloc[sample]);cal_sparse=vectorizer.transform(frame.text.iloc[cal]);val_sparse=vectorizer.transform(frame.text.iloc[val])
    for alpha in [1e-5,3e-5]:
        name=f'char_{alpha}';tick=perf_counter()
        base=SGDClassifier(loss='log_loss',alpha=alpha,max_iter=40,tol=1e-4,class_weight='balanced',random_state=42)
        base.fit(sparse,y[sample]);model=CalibratedClassifierCV(FrozenEstimator(base),method='sigmoid');model.fit(cal_sparse,y[cal])
        models[name]=model;timing[name]=perf_counter()-tick;scores[name]=model.predict_proba(val_sparse)[:,1]
        print('Finished',name,flush=True)
    del sparse,cal_sparse,val_sparse;gc.collect()
    # Controlled alternative label formulations, on the same domain partitions.
    allcal=splits['calibration']
    fit_model('binary_malicious',XGBClassifier(n_estimators=450,max_depth=5,learning_rate=.05,min_child_weight=5,subsample=.85,colsample_bytree=.85,reg_lambda=8,n_jobs=4,tree_method='hist',random_state=42),fit,allcal,(kind!=0).astype(int),np.arange(x.shape[1]))
    fit_model('three_class',XGBClassifier(n_estimators=450,max_depth=5,learning_rate=.05,min_child_weight=5,subsample=.85,colsample_bytree=.85,reg_lambda=8,n_jobs=4,tree_method='hist',random_state=42),fit,allcal,kind,np.arange(x.shape[1]))
    malfit=fit[kind[fit]!=1];malcal=allcal[kind[allcal]!=1]
    fit_model('malware_specialist',LGBMClassifier(n_estimators=400,num_leaves=31,learning_rate=.05,min_child_samples=30,reg_lambda=5,n_jobs=4,verbosity=-1,random_state=42),malfit,malcal,(kind==2).astype(int),np.arange(x.shape[1]))
    # Family winners use validation only. Static mixtures never fit on test data.
    quality=lambda p: measured(y[val],p,tune_threshold(y[val],p,.01))['recall']
    best={family:max([name for name in scores if name.startswith(family)],key=lambda name:quality(scores[name])) for family in ['rf_','xgb_','lgb_','char_']}
    mixtures={name:{name:1.} for name in scores if name!='malware_specialist'}
    for family in ['rf_','xgb_','lgb_']:
        for c in [.25,.5,.75]:mixtures[f'{family}character_{c}']={best[family]:1-c,best['char_']:c}
    mixtures['separate_specialists']={best['xgb_']:1.}
    # Freeze separate operating points for malicious detection on validation
    # containing all three types. Phishing metrics still use phishing thresholds.
    allval=splits['validation']
    all_scores=get_scores(dict(models=models,columns=columns,vectorizer=vectorizer),frame.iloc[allval],x[allval])
    all_rules=np.array([evaluate_rules(dict(zip(FEATURE_NAMES,row[:32])))[0] for row in x[allval]])
    malicious_thresholds={}
    for name,weights in mixtures.items():
        p=sum(w*all_scores[n] for n,w in weights.items())
        if name=='three_class':p=all_scores['three_class_malicious']
        elif name=='separate_specialists':p=np.maximum(p,all_scores['malware_specialist'])
        malicious_thresholds[name]={str(w):tune_threshold((kind[allval]!=0).astype(int),hybrid_score(p,all_rules,w),.01) for w in [1.,.9]}
    rules=np.array([evaluate_rules(dict(zip(FEATURE_NAMES,row[:32])))[0] for row in x[val]])
    thresholds,validation=[],[]
    for name,weights in mixtures.items():
        p=sum(weight*scores[key] for key,weight in weights.items())
        for weight in [1.,.9]:
            index=hybrid_score(p,rules,weight)
            for policy,threshold in policies(y[val],index).items():
                item=dict(model=name,model_weight=weight,policy=policy,**measured(y[val],index,threshold))
                validation.append(item);thresholds.append(dict(model=name,model_weight=weight,policy=policy,threshold=threshold))
    feasible=[r for r in validation if r['policy']=='fpr_1pct']
    winner=max(feasible,key=lambda r:(r['recall'],r['f1'],-len(mixtures[r['model']]),r['model_weight']))
    bundle=dict(models=models,columns=columns,vectorizer=vectorizer,mixtures=mixtures,best=best,thresholds=thresholds,timing=timing,malicious_thresholds=malicious_thresholds)
    joblib.dump(bundle,output/'frozen_bundle.joblib',compress=3)
    protocol=dict(created_at=datetime.now(timezone.utc).isoformat(),feature_version=FEATURE_VERSION,seed=20261101,
        winner=winner,fit_sample_rows=len(fit),family_winners=best,training_seconds=perf_counter()-started,
        code_sha256={name:digest(ROOT/name) for name in CODE},bundle_sha256=digest(output/'frozen_bundle.joblib'),
        dataset_audit_sha256=digest(DATA/'dataset_audit.json'),fresh_sources=json.loads((DATA/'fresh_source_manifest.json').read_text()),
        development_cache_sha256=digest(DATA/'development.joblib'),
        production_artifact_sha256=digest(ROOT/'models/xgboost.joblib'),
        test_status='Fresh feed URLs have not been scored; no threshold or model selection may use final results.',
        threat_intelligence='disabled on feed-derived holdouts to prevent circular evaluation')
    (output/'frozen_protocol.json').write_text(json.dumps(protocol,indent=2))
    pd.DataFrame(validation).to_csv(output/'validation_scores.csv',index=False)
    print('FROZEN_WINNER',json.dumps(winner),flush=True)


def get_scores(bundle,frame,x):
    result={}
    for name,model in bundle['models'].items():
        values=bundle['vectorizer'].transform(frame.text) if name.startswith('char_') else x[:,bundle['columns'][name]]
        p=model.predict_proba(values)
        result[name]=p[:,list(model.classes_).index(1)]
        if name=='three_class':result['three_class_malicious']=1-p[:,0]
    return result


def final(output,combined_path=None):
    marker=output/'final_started.json'
    if marker.exists():raise ValueError('This frozen run has already started final evaluation; do not tune and rerun.')
    protocol=json.loads((output/'frozen_protocol.json').read_text())
    for name,expected in protocol['code_sha256'].items():
        if digest(ROOT/name)!=expected:raise ValueError('Frozen code changed: '+name)
    if digest(output/'frozen_bundle.joblib')!=protocol['bundle_sha256']:raise ValueError('Frozen bundle changed')
    if digest(DATA/'development.joblib')!=protocol['development_cache_sha256']:raise ValueError('Development data changed')
    if digest(ROOT/'models/xgboost.joblib')!=protocol['production_artifact_sha256']:raise ValueError('Production baseline changed')
    for source in protocol['fresh_sources'].values():
        if 'sha256' in source and digest(Path(source['path']))!=source['sha256']:raise ValueError('Reserved feed snapshot changed')
    marker.write_text(json.dumps(dict(protocol_sha256=digest(output/'frozen_protocol.json'))))
    bundle=joblib.load(output/'frozen_bundle.joblib');dev,xdev=joblib.load(DATA/'development.joblib')
    # The complete development corpus is excluded, including its within-source test.
    seen=set(dev.group)
    fresh=[]
    for url in (DATA/'openphish.txt').read_text(encoding='utf-8-sig').splitlines():
        if url.strip():fresh.append(dict(url=url.strip(),kind=1,source='OpenPhish_fresh',collected_at=None))
    tank=pd.read_csv(DATA/'phishtank.csv.gz')
    if not ((tank.verified=='yes')&(tank.online=='yes')).all():raise ValueError('Unverified PhishTank data')
    fresh.extend(dict(url=r.url,kind=1,source='PhishTank_fresh',collected_at=r.verification_time) for r in tank.itertuples(index=False))
    fresh,xfresh,freshinfo=clean(fresh)
    unseen=~fresh.group.isin(seen).to_numpy();freshinfo['excluded_development_domain_rows']=int((~unseen).sum())
    fresh,xfresh=fresh.loc[unseen].reset_index(drop=True),xfresh[unseen]
    testmask=dev.partition.to_numpy()=='test'
    reserved=dev.loc[testmask].reset_index(drop=True);xtest=xdev[testmask]
    frame=pd.concat([reserved,fresh],ignore_index=True);x=np.concatenate([xtest,xfresh])
    kind=frame.kind.to_numpy();pbase=get_scores(bundle,frame,x)
    rules=np.array([evaluate_rules(dict(zip(FEATURE_NAMES,row[:32])))[0] for row in x])
    masks={'reserved_phishing_benign':(np.arange(len(frame))<len(reserved))&(kind!=2),
           'fresh_phishing_with_reserved_benign':(frame.source.str.endswith('_fresh').to_numpy())|((np.arange(len(frame))<len(reserved))&(kind==0)),
           'fresh_phishing_only':frame.source.str.endswith('_fresh').to_numpy(),
           'fresh_openphish':frame.source.to_numpy()=='OpenPhish_fresh',
           'fresh_phishtank':frame.source.to_numpy()=='PhishTank_fresh',
           'recent_phishtank_30d':(frame.source.to_numpy()=='PhishTank_fresh')&(pd.to_datetime(frame.collected_at,format='mixed',errors='coerce',utc=True)>=pd.Timestamp('2026-10-02',tz='UTC')).to_numpy(),
           'reserved_malware_benign':(np.arange(len(frame))<len(reserved))&(kind!=1),
           'reserved_all_types':np.arange(len(frame))<len(reserved),
           'reserved_benign_hard':(kind==0)&((x[:,2]>1)|(x[:,3]>0)|(x[:,4]>0))}
    old=pd.read_csv(combined_path or Path.home()/'Downloads/LinkGuard-Combined-Dataset/combined_phishing_dataset.csv',usecols=['url'])
    old_groups=set()
    for value in old.url:
        host=urlsplit(value).hostname or ''
        if host.startswith('www.'):host=host[4:]
        old_groups.add(SUFFIXES(host).top_domain_under_public_suffix or host)
    old_unseen=~frame.group.isin(old_groups).to_numpy()
    masks['paired_fresh_phishing_reserved_benign']=masks['fresh_phishing_with_reserved_benign']&old_unseen
    masks['paired_recent_phishing_30d']=masks['recent_phishtank_30d']&old_unseen
    artifact=joblib.load(ROOT/'models/xgboost.joblib');legacy=artifact['model'].predict_proba(x[:,:32])[:,1]
    pbase['existing_deployed']=legacy
    mixtures=dict(bundle['mixtures'],existing_deployed={'existing_deployed':1.})
    specs=list(bundle['thresholds'])+[dict(model='existing_deployed',model_weight=artifact.get('model_weight',.8),policy='existing_frozen',threshold=artifact['threshold'])]
    rows=[];selected_predictions={}
    frozen=protocol['winner']
    for spec in specs:
        name=spec['model'];p=sum(w*pbase[key] for key,w in mixtures[name].items())
        score=hybrid_score(p,rules,spec['model_weight'])
        chosen=(name==frozen['model'] and spec['policy']==frozen['policy'] and spec['model_weight']==frozen['model_weight']) or name=='existing_deployed'
        for cohort,mask in masks.items():
            if not mask.any():continue
            # Malware is separately evaluated as malware, not as phishing.
            is_malicious=cohort in ['reserved_malware_benign','reserved_all_types']
            target=(kind!=0).astype(int) if is_malicious else (kind==1).astype(int)
            threshold=spec['threshold']
            if is_malicious:
                if name=='three_class':score_eval=hybrid_score(pbase['three_class_malicious'],rules,spec['model_weight'])
                elif name=='separate_specialists':score_eval=hybrid_score(np.maximum(p,pbase['malware_specialist']),rules,spec['model_weight'])
                else:score_eval=score
                if name!='existing_deployed':threshold=bundle['malicious_thresholds'][name][str(spec['model_weight'])]
            else:score_eval=score
            rows.append(dict(**{k:v for k,v in spec.items() if k!='threshold'},threshold=threshold,
                cohort=cohort,selected_on_validation=chosen,threshold_target='malicious_fpr_1pct' if is_malicious else 'phishing',
                **{k:v for k,v in measured(target[mask],score_eval[mask],threshold).items() if k!='threshold'}))
        if chosen:
            selected_predictions[name]=score
    result=pd.DataFrame(rows);result.to_csv(output/'final_scores.csv',index=False)
    # Record immutable predictions for reporting, not for additional tuning.
    predictions=frame[['url','group','kind','source','collected_at']].copy()
    predictions['paired_cohort']=masks['paired_fresh_phishing_reserved_benign']
    for name,p in selected_predictions.items():predictions[name]=p
    predictions.to_csv(output/'selected_predictions.csv',index=False)
    from research_report import bootstrap
    uncertainty={}
    mask=masks['paired_fresh_phishing_reserved_benign'];target=(kind==1).astype(int)
    operational=[];recall_intervals={}
    for name,p in selected_predictions.items():
        threshold=artifact['threshold'] if name=='existing_deployed' else frozen['threshold']
        uncertainty[name]=bootstrap(target[mask],p[mask]>=threshold,frame.group.to_numpy()[mask])
        review=(p<threshold)&((p>=min(.3,threshold*.6))|(rules>=.4)|(abs(p-threshold)<=.1))
        decisive=mask&~review
        operational.append(dict(model=name,rows=int(mask.sum()),coverage=float(decisive.sum()/mask.sum()),
            needs_review=int((mask&review).sum()),reviewed_phishing=int((mask&review&(kind==1)).sum()),
            reviewed_benign=int((mask&review&(kind==0)).sum()),
            decisive_metrics=_safe_metrics(target[decisive],p[decisive]>=threshold)))
        for cohort in ['fresh_openphish','fresh_phishtank','recent_phishtank_30d','paired_recent_phishing_30d']:
            selected=masks[cohort]
            if not selected.any():continue
            _,inverse=np.unique(frame.group.to_numpy()[selected],return_inverse=True)
            total=np.bincount(inverse);hits=np.bincount(inverse,weights=(p[selected]>=threshold))
            rng=np.random.default_rng(42);values=[]
            for _ in range(1000):
                sampled=rng.integers(len(total),size=len(total));values.append(float(hits[sampled].sum()/total[sampled].sum()))
            recall_intervals[name+' / '+cohort]=np.percentile(values,[2.5,97.5]).tolist()
    summary=dict(fresh_data=freshinfo,cohorts={name:dict(rows=int(mask.sum()),domains=frame.group.loc[mask].nunique(),
        class_counts={str(k):int(v) for k,v in frame.kind.loc[mask].value_counts().items()}) for name,mask in masks.items()},
        confidence_intervals_95=uncertainty,phishing_only_recall_intervals_95=recall_intervals,operational=operational,selected=protocol['winner'],
        limits=['Fresh feed retrieval is not a first-seen timestamp; PhishTank verification dates define the recent slice.',
                'Benign final data are historical reserved domains, not a contemporary independent legitimate sample.',
                'URL/domain disjointness does not establish independent campaigns or templates.',
                'Feed-derived labels were never looked up against the same feeds; full threat intelligence accuracy is not established.'])
    (output/'final_summary.json').write_text(json.dumps(summary,indent=2))
    weights=bundle['mixtures'][frozen['model']]
    candidate=PhishingCandidate({name:bundle['models'][name] for name in weights},
        bundle['columns'],bundle['vectorizer'] if any(n.startswith('char_') for n in weights) else None,weights)
    # Verify the deployable wrapper against frozen batch predictions.
    check=np.linspace(0,len(frame)-1,32,dtype=int)
    expected=sum(w*pbase[n][check] for n,w in weights.items())
    np.testing.assert_allclose(candidate.predict_proba(frame.url.iloc[check])[:,1],expected,rtol=1e-6,atol=1e-7)
    joblib.dump(dict(model=candidate,threshold=frozen['threshold'],model_weight=frozen['model_weight'],
        feature_version=FEATURE_VERSION,protocol_sha256=digest(output/'frozen_protocol.json')),
        output/'candidate_research.joblib',compress=3)
    errors=[]
    for name,p in selected_predictions.items():
        threshold=artifact['threshold'] if name=='existing_deployed' else frozen['threshold']
        for source,part in frame.loc[mask].groupby('source'):
            ix=part.index.to_numpy();truth=kind[ix]==1;pred=p[ix]>=threshold
            errors.append(dict(model=name,source=source,rows=len(ix),false_negative=int((truth&~pred).sum()),
                false_positive=int((~truth&pred).sum()),median_path_length=float(np.median(x[ix,2])),
                median_query_length=float(np.median(x[ix,3]))))
    pd.DataFrame(errors).to_csv(output/'error_analysis.csv',index=False)
    print(result[(result.selected_on_validation)&result.cohort.isin(['paired_fresh_phishing_reserved_benign','fresh_openphish','fresh_phishtank','recent_phishtank_30d'])][['model','policy','cohort','rows','accuracy','precision','recall','f1','false_positive_rate']].to_string(index=False),flush=True)
    plots(output,result)


def runtime(output):
    """Run in a separate process so unused training models do not inflate RSS."""
    import sys
    sys.path.insert(0,str(ROOT/'data/research_v3/deps'))
    import psutil
    before=psutil.Process().memory_info().rss
    tick=perf_counter();artifact=joblib.load(output/'candidate_research.joblib');load_ms=(perf_counter()-tick)*1000
    after=psutil.Process().memory_info().rss
    samples=pd.read_csv(output/'selected_predictions.csv',usecols=['url']).url.iloc[:32].tolist()
    artifact['model'].predict_proba(samples[:1])
    values=[]
    for url in samples:
        tick=perf_counter();artifact['model'].predict_proba([url]);values.append((perf_counter()-tick)*1000)
    result=dict(candidate_file_bytes=(output/'candidate_research.joblib').stat().st_size,
        process_rss_mib=after/2**20,model_load_rss_delta_mib=(after-before)/2**20,load_ms=load_ms,
        single_url_median_ms=float(np.median(values)),single_url_p95_ms=float(np.percentile(values,95)),samples=len(samples))
    (output/'runtime.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))


def baseline(source_directory=None,combined_path=None):
    """Reproduce historical Kaggle results without retraining or API flooding."""
    from research_audit import load_records, _score
    old=source_directory or Path.home()/'Downloads/phishing-url-detector/data'
    frame,metadata=load_records(old/'kaggle-real-world-phishing/phishing_url_dataset_unique.csv','Kaggle historical')
    artifact=joblib.load(ROOT/'models/xgboost.joblib')
    _,score,raw=_score(frame,artifact)
    served=np.array([round(float(value)*100,1) for value in score])>=round(artifact['threshold']*100,1)
    corpus=pd.read_csv(combined_path or Path.home()/'Downloads/LinkGuard-Combined-Dataset/combined_phishing_dataset.csv',usecols=['url'])
    groups=set()
    for url in corpus.url:
        host=urlsplit(url).hostname or ''
        if host.startswith('www.'):host=host[4:]
        groups.add(SUFFIXES(host).top_domain_under_public_suffix or host)
    results={}
    for cohort,mask in [('all',np.ones(len(frame),dtype=bool)),('unseen',~frame.group.isin(groups).to_numpy())]:
        results[cohort]={}
        for policy,pred in [('historical_served_rounding',served),('corrected_full_precision',raw)]:
            values=dict(rows=int(mask.sum()),**_safe_metrics(frame.label.to_numpy()[mask],pred[mask]))
            for source in ['openphish','urlhaus']:
                subset=mask&(frame.source.to_numpy()==source)
                values[source]=dict(rows=int(subset.sum()),detected=int(pred[subset].sum()),recall=float(pred[subset].mean()))
            results[cohort][policy]=values
    result=dict(dataset=metadata,model_version=artifact['trained_at'],model_sha256=digest(ROOT/'models/xgboost.joblib'),
                changed_decisions_from_display_rounding=int((served!=raw).sum()),results=results)
    DATA.mkdir(parents=True,exist_ok=True)
    (DATA/'historical_reproduction.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2),flush=True)


def plots(output,results):
    import sys
    sys.path.insert(0,str(ROOT/'data/research_v3/deps'))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    selected=results[(results.selected_on_validation)&(results.cohort=='fresh_phishing_with_reserved_benign')]
    fig,axes=plt.subplots(1,len(selected),figsize=(6*len(selected),5),squeeze=False)
    for ax,(_,row) in zip(axes[0],selected.iterrows()):
        matrix=np.array(row.confusion_matrix)
        ax.imshow(matrix,cmap='Blues');ax.set_xticks([0,1],['Benign','Phishing']);ax.set_yticks([0,1],['Benign','Phishing'])
        ax.set_xlabel('Predicted');ax.set_ylabel('Actual');ax.set_title(row.model)
        for (i,j),value in np.ndenumerate(matrix):ax.text(j,i,f'{value:,}',ha='center',va='center',color='black')
    fig.suptitle('Fresh phishing + reserved historical benign domains');fig.tight_layout();fig.savefig(output/'confusion_matrices.png',dpi=180);plt.close(fig)
    from sklearn.metrics import roc_curve
    predictions=pd.read_csv(output/'selected_predictions.csv')
    paired=predictions[predictions.paired_cohort]
    fig,axes=plt.subplots(1,2,figsize=(11,4))
    for name in [c for c in paired.columns if c not in ['url','group','kind','source','collected_at','paired_cohort']]:
        y=(paired.kind==1).astype(int);p=paired[name]
        fpr,tpr,_=roc_curve(y,p);precision,recall,_=precision_recall_curve(y,p)
        axes[0].plot(fpr,tpr,label=name);axes[1].plot(recall,precision,label=name)
    axes[0].set(xlabel='False-positive rate',ylabel='Phishing recall',title='ROC, paired unseen domains')
    axes[1].set(xlabel='Phishing recall',ylabel='Precision',title='PR, paired unseen domains')
    for ax in axes:ax.legend(fontsize=8);ax.grid(alpha=.2)
    fig.tight_layout();fig.savefig(output/'roc_pr_curves.png',dpi=180);plt.close(fig)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',choices=['prepare','train','final','runtime','baseline'],required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'training_output/capstone_phishing_2026-11-01')
    parser.add_argument('--source-directory',type=Path,help='Directory with additional-urls.json and kaggle-real-world-phishing/')
    parser.add_argument('--combined',type=Path,help='Original combined CSV, used only for legacy-domain exclusions')
    args=parser.parse_args()
    if args.stage=='prepare':prepare(args.source_directory)
    elif args.stage=='train':train(args.output)
    elif args.stage=='final':final(args.output,args.combined)
    elif args.stage=='baseline':baseline(args.source_directory,args.combined)
    else:runtime(args.output)
