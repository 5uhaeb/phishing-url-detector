"""Fresh, staged, domain-disjoint three-family benchmark. See fresh_protocol.md."""
import argparse
from datetime import datetime, timezone
from concurrent.futures import ProcessPoolExecutor
import gc
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

from detector import FEATURE_NAMES, extract_features
from lexical_features import RichUrlFeatures, LatentUrlFeatures, canonical_text, numeric_features
from metrics import metrics, tune_threshold
from train import make_models, NAMES

SEED = 20261103


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, allow_nan=False), encoding='utf-8')


def parse_batch(task):
    split, rows = task
    records, vectors, invalid = [], [], 0
    for url, label, date, sample_hash in rows:
        try: normalized, features, group = extract_features(url)
        except (ValueError, TypeError): invalid += 1; continue
        parts = urlsplit(normalized)
        authority = parts.netloc
        if (parts.hostname or '').startswith('www.'):
            at = authority.rfind('@') + 1
            authority = authority[:at] + authority[at+4:]
        key = urlunsplit(parts._replace(netloc=authority))
        records.append(dict(url=normalized, key=key, group=group, label=int(label == 'phish'),
                            publisher_split=split, date=date, sample_sha256=sample_hash))
        vectors.append([features[name] for name in FEATURE_NAMES])
    return records, vectors, invalid


def prepare(metadata, output):
    if (output / 'audit.json').exists(): raise ValueError('Prepared output already exists.')
    output.mkdir(parents=True, exist_ok=True)
    records, vectors = [], []
    invalid = {}; raw = {}; www = {}
    for split in ('train', 'test'):
        frame = pd.concat([pd.read_csv(path, keep_default_na=False)
                           for path in sorted(metadata.glob(f'{split}-*.csv'))], ignore_index=True)
        if set(frame.label.unique()) != {'benign', 'phish'}: raise ValueError('Unexpected publisher labels')
        raw[split] = len(frame)
        www[split] = frame.assign(www=frame.url.str.contains(r'://www\.', regex=True)).groupby('label').www.mean().to_dict()
        invalid[split] = 0
        tasks = [(split,list(frame.iloc[start:start+5000][['url','label','date','sha256']]
                             .itertuples(index=False,name=None))) for start in range(0,len(frame),5000)]
        with ProcessPoolExecutor(max_workers=6) as pool:
            for index,(batch_records,batch_vectors,batch_invalid) in enumerate(pool.map(parse_batch,tasks)):
                records.extend(batch_records); vectors.extend(batch_vectors); invalid[split]+=batch_invalid
                if index % 20 == 19: print(f'Parsed {split}: {min(len(frame),(index+1)*5000):,}',flush=True)
    clean = pd.DataFrame(records)
    base = np.asarray(vectors, dtype=np.float32)
    del records, vectors, frame; gc.collect()
    conflicts = clean.groupby('key').label.nunique()
    bad = set(conflicts[conflicts > 1].index)
    conflict_rows = int(clean.key.isin(bad).sum())
    valid = clean[~clean.key.isin(bad)].drop_duplicates('key', keep='first').copy()
    duplicate_rows = len(clean) - conflict_rows - len(valid)
    train_domains = set(valid.loc[valid.publisher_split == 'train', 'group'])
    overlapping = (valid.publisher_split == 'test') & valid.group.isin(train_domains)
    removed_domains = int(overlapping.sum())
    valid = valid[~overlapping].copy()
    base = base[valid.index]
    valid = valid.reset_index(drop=True)
    valid['partition'] = 'test'
    development = np.flatnonzero(valid.publisher_split.eq('train'))
    a, b = next(GroupShuffleSplit(n_splits=1, test_size=.30, random_state=SEED)
                .split(base[development], valid.label.to_numpy()[development], valid.group.to_numpy()[development]))
    fit, rest = development[a], development[b]
    a, b = next(GroupShuffleSplit(n_splits=1, test_size=.5, random_state=SEED+1)
                .split(base[rest], valid.label.to_numpy()[rest], valid.group.to_numpy()[rest]))
    valid.loc[fit, 'partition'] = 'training'
    valid.loc[rest[a], 'partition'] = 'calibration'
    valid.loc[rest[b], 'partition'] = 'validation'
    summary = {}
    group_sets = []
    for name, subset in valid.groupby('partition'):
        if subset.label.nunique() != 2: raise ValueError('A split lacks a class')
        domains = set(subset.group)
        if any(domains & previous for previous in group_sets): raise ValueError('Domain leakage')
        group_sets.append(domains)
        summary[name] = dict(rows=len(subset), domains=len(domains), positives=int(subset.label.sum()),
                             negatives=int((subset.label == 0).sum()),
                             date_min=subset.date.min(), date_max=subset.date.max())
    # Audit www invariance on examples from both labels, never dropping hard rows.
    checked = 0
    for row in valid.groupby('label').head(250).itertuples():
        parts = urlsplit(row.url)
        if ':' in parts.hostname or parts.username is not None: continue
        try: ipaddress.ip_address(parts.hostname)
        except ValueError: pass
        else: continue
        host = parts.hostname.removeprefix('www.')
        suffix = (':' + str(parts.port)) if parts.port is not None else ''
        first = urlunsplit(parts._replace(netloc=host+suffix))
        second = urlunsplit(parts._replace(netloc='www.'+host+suffix))
        if not np.array_equal(numeric_features(first), numeric_features(second)) or canonical_text(first) != canonical_text(second):
            raise ValueError('www feature invariance failed')
        checked += 1
    valid.to_csv(output / 'cohort.csv', index=False)
    np.save(output / 'base.npy', base)
    source = json.loads((metadata / 'source.json').read_text(encoding='utf-8'))
    audit = dict(created_at=datetime.now(timezone.utc).isoformat(), starting_commit='56c2703',
        source_revision=source['revision'], source=source['source'], raw_rows=raw, invalid_rows=invalid,
        contradictory_urls=len(bad), contradictory_rows=conflict_rows, duplicates_removed=duplicate_rows,
        test_rows_removed_for_training_domain_overlap=removed_domains,
        www_fraction_by_class=www, www_invariance_pairs_checked=checked, splits=summary,
        cohort_sha256=hashlib.sha256((output / 'cohort.csv').read_bytes()).hexdigest(),
        positive_class='phishing', seed=SEED, final_test_opened=False)
    write_json(output / 'audit.json', audit)
    print(json.dumps(audit, indent=2), flush=True)


def target_threshold(labels, scores):
    """Maximize the weakest of accuracy/precision/recall/F1 on validation."""
    fpr, recall, thresholds = roc_curve(labels, scores, drop_intermediate=False)
    positives, negatives = int(np.sum(labels)), int(np.sum(1-labels))
    tp, fp = recall*positives, fpr*negatives
    accuracy = (tp + negatives-fp) / len(labels)
    precision = np.divide(tp, tp+fp, out=np.zeros_like(tp), where=(tp+fp)>0)
    f1 = np.divide(2*precision*recall, precision+recall,
                   out=np.zeros_like(tp), where=(precision+recall)>0)
    weakest = np.minimum.reduce([accuracy, precision, recall, f1])
    best = max(range(1, len(thresholds)), key=lambda i: (weakest[i], -fpr[i], accuracy[i]))
    return float(thresholds[best])


def candidate_models(jobs, round_name):
    if round_name == 'latent':
        return {
            'random_forest_latent': RandomForestClassifier(n_estimators=400,max_depth=32,min_samples_leaf=2,
                max_features='sqrt',class_weight='balanced_subsample',n_jobs=jobs,random_state=SEED+2),
            'xgboost_latent': XGBClassifier(n_estimators=1400,max_depth=6,learning_rate=.045,
                min_child_weight=5,subsample=.85,colsample_bytree=.9,reg_lambda=8,
                tree_method='hist',max_bin=128,eval_metric='logloss',n_jobs=jobs,random_state=SEED+2),
            'lightgbm_latent': LGBMClassifier(n_estimators=1600,num_leaves=63,learning_rate=.035,
                min_child_samples=50,subsample=.85,subsample_freq=1,colsample_bytree=.9,
                reg_lambda=5,max_bin=127,n_jobs=jobs,random_state=SEED+2,
                verbosity=-1,deterministic=True,force_col_wise=True),
        }
    if round_name == 'lexical':
        return {
            'random_forest_rich': RandomForestClassifier(n_estimators=360, max_depth=40, min_samples_leaf=1,
                max_features='sqrt', class_weight='balanced_subsample', n_jobs=jobs, random_state=SEED),
            'xgboost_rich': XGBClassifier(n_estimators=1200, max_depth=7, learning_rate=.045,
                min_child_weight=5, subsample=.85, colsample_bytree=.8, reg_lambda=8, reg_alpha=.1,
                tree_method='hist', max_bin=128, eval_metric='logloss', n_jobs=jobs, random_state=SEED),
            'lightgbm_rich': LGBMClassifier(n_estimators=1600, num_leaves=63, learning_rate=.035,
                min_child_samples=50, subsample=.85, subsample_freq=1, colsample_bytree=.8,
                reg_lambda=5, reg_alpha=.1, max_bin=127, n_jobs=jobs, random_state=SEED,
                verbosity=-1, deterministic=True, force_col_wise=True),
        }
    if round_name == 'deep':
        return {
            'random_forest_deep': RandomForestClassifier(n_estimators=480, max_depth=None,
                min_samples_leaf=1, max_features=.08, class_weight='balanced_subsample',
                n_jobs=jobs, random_state=SEED+1),
            'xgboost_deep': XGBClassifier(n_estimators=1600, max_depth=10, learning_rate=.035,
                min_child_weight=8, subsample=.85, colsample_bytree=.75, reg_lambda=12,
                tree_method='hist', max_bin=128, eval_metric='logloss', n_jobs=jobs, random_state=SEED+1),
            'lightgbm_deep': LGBMClassifier(n_estimators=2000, num_leaves=127, learning_rate=.025,
                min_child_samples=70, subsample=.85, subsample_freq=1, colsample_bytree=.8,
                reg_lambda=8, max_bin=127, n_jobs=jobs, random_state=SEED+1,
                verbosity=-1, deterministic=True, force_col_wise=True),
        }
    raise ValueError(round_name)


def matrices(output, frame, rich=False):
    indices = {name: np.flatnonzero(frame.partition.eq(name)) for name in ('training', 'calibration', 'validation')}
    if not rich:
        x = np.load(output / 'base.npy', mmap_mode='r')
        return {name: x[ix] for name, ix in indices.items()}
    feature_file = output / 'rich_features.joblib'
    if not feature_file.exists():
        features = RichUrlFeatures().fit(frame.url.iloc[indices['training']].tolist(),
                                       frame.label.iloc[indices['training']].to_numpy())
        joblib.dump(features, feature_file, compress=3)
    features = joblib.load(feature_file)
    result = {}
    for name, ix in indices.items():
        path = output / f'rich_{name}.npz'
        if not path.exists():
            print(f'Transforming {name} ({len(ix):,} rows)...', flush=True)
            matrix = features.transform(frame.url.iloc[ix].tolist())
            sparse.save_npz(path, matrix, compressed=False)
        result[name] = sparse.load_npz(path)
    return result


def latent_matrices(output,frame):
    raw=matrices(output,frame,rich=True)
    path=output/'latent_features.joblib'
    if not path.exists():
        print('Learning train-only latent text factors...',flush=True)
        features=LatentUrlFeatures().fit_matrix(raw['training'],joblib.load(output/'rich_features.joblib'))
        joblib.dump(features,path,compress=3)
    features=joblib.load(path)
    result={}
    for name,matrix in raw.items():
        cache=output/f'latent_{name}.npy'
        if not cache.exists():np.save(cache,features.transform_matrix(matrix))
        result[name]=np.load(cache,mmap_mode='r')
    return result


def fit_stage(output, jobs, stage):
    if (output / 'frozen.json').exists(): raise ValueError('Selections frozen; no further tuning on this experiment.')
    frame = pd.read_csv(output / 'cohort.csv', keep_default_na=False)
    x = latent_matrices(output,frame) if stage=='latent' else matrices(output, frame, rich=stage != 'baseline')
    ys = {name: frame.loc[frame.partition.eq(name), 'label'].to_numpy() for name in x}
    models = make_models(jobs) if stage == 'baseline' else candidate_models(jobs, stage)
    for identifier, base in models.items():
        family = next(name for name in NAMES if identifier.startswith(name))
        name = f'{identifier}_baseline' if stage == 'baseline' else identifier
        result_path = output / f'{name}.json'
        if result_path.exists():
            print(f'Already measured: {name}', flush=True); continue
        started = time.monotonic()
        print(f'Fitting {name}: {x["training"].shape}...', flush=True)
        artifact_path = output / f'{name}.joblib'
        scores_path = output / f'{name}_validation.npy'
        recovered = artifact_path.exists() and scores_path.exists()
        if recovered:
            model = joblib.load(artifact_path)
            base = model.estimator.estimator
            scores = np.load(scores_path)
        else:
            base.fit(x['training'], ys['training'])
            base.set_params(n_jobs=1)
            model = CalibratedClassifierCV(FrozenEstimator(base), method='sigmoid')
            model.fit(x['calibration'], ys['calibration'])
            scores = model.predict_proba(x['validation'])[:, 1]
        balanced = target_threshold(ys['validation'], scores)
        conservative = tune_threshold(ys['validation'], scores, .008)
        result = dict(identifier=name, family=family, model_name=NAMES[family], stage=stage,
            balanced_threshold=balanced, conservative_threshold=conservative,
            validation=dict(balanced=metrics(ys['validation'], scores >= balanced),
                            conservative=metrics(ys['validation'], scores >= conservative)),
            validation_roc_auc=float(roc_auc_score(ys['validation'], scores)),
            validation_pr_auc=float(average_precision_score(ys['validation'], scores)),
            elapsed_seconds=time.monotonic()-started, recovered_saved_fit=recovered,
            parameters={key: (None if isinstance(value,float) and not np.isfinite(value) else value)
                        for key,value in base.get_params().items()},
            parameter_note='Nonfinite XGBoost missing-value sentinel is represented as null.',
            feature_set=('original_32' if stage=='baseline' else 'www_invariant_latent_url' if stage=='latent'
                         else 'www_invariant_rich_url'),
            trained_at=datetime.now(timezone.utc).isoformat())
        if not recovered:
            joblib.dump(model, artifact_path, compress=3)
            np.save(scores_path, scores)
        write_json(result_path, result)
        print(json.dumps(result, indent=2), flush=True)
        del model; gc.collect()


def freeze(output):
    if (output / 'frozen.json').exists(): raise ValueError('Already frozen')
    # Apply one common operating-point objective to both baseline and improved
    # candidates, so a threshold-policy change cannot masquerade as feature gains.
    frame = pd.read_csv(output / 'cohort.csv',keep_default_na=False)
    validation_labels = frame.loc[frame.partition.eq('validation'),'label'].to_numpy()
    for path in output.glob('*.json'):
        result = json.loads(path.read_text(encoding='utf-8'))
        if 'identifier' not in result: continue
        scores = np.load(output / f'{result["identifier"]}_validation.npy')
        threshold = target_threshold(validation_labels,scores)
        if threshold != result['balanced_threshold']:
            result['initial_validation_f1_threshold'] = result['balanced_threshold']
            result['balanced_threshold'] = threshold
            result['validation']['balanced'] = metrics(validation_labels,scores>=threshold)
        result['balanced_policy'] = 'Maximize minimum of validation accuracy, precision, recall, F1'
        write_json(path,result)
    candidates = [json.loads(p.read_text(encoding='utf-8')) for p in output.glob('*.json')
                  if p.name not in ('audit.json', 'frozen.json', 'final.json') and 'identifier' in json.loads(p.read_text(encoding='utf-8'))]
    selected = []
    for family in NAMES:
        subset = [r for r in candidates if r['family'] == family and r['stage'] != 'baseline']
        if not subset: raise ValueError(f'No improved candidates for {family}')
        balanced = max(subset, key=lambda r: (
            min(r['validation']['balanced'][k] for k in ('accuracy','precision','recall','f1')),
            -r['validation']['balanced']['false_positive_rate'], r['validation_pr_auc']))
        low = max(subset, key=lambda r: (r['validation']['conservative']['recall'],
            r['validation']['conservative']['precision'], r['validation_pr_auc']))
        baseline = next(r for r in candidates if r['family'] == family and r['stage'] == 'baseline')
        for version, result, policy in [('Fresh baseline',baseline,'balanced'),('Fresh baseline',baseline,'conservative'),
                                       ('Retrained',balanced,'balanced'),('Retrained',low,'conservative')]:
            selected.append(dict(version=version, identifier=result['identifier'], family=family, policy=policy,
                threshold=result[f'{policy}_threshold'],
                artifact_sha256=hashlib.sha256((output / f'{result["identifier"]}.joblib').read_bytes()).hexdigest()))
    write_json(output / 'frozen.json', dict(frozen_at=datetime.now(timezone.utc).isoformat(), selected=selected,
        candidate_count=len(candidates), final_test_previously_opened=False,
        balanced_policy='Same weakest-of-four validation objective for fresh baselines and retrained models'))
    print('All baseline/improved families and operating points frozen before test predictions.', flush=True)


def confidence(labels, decisions, groups, resamples=1000):
    _, codes = np.unique(groups, return_inverse=True)
    counts = np.zeros((int(codes.max())+1, 4), dtype=np.int64)
    slot = (labels.astype(int)*2 + decisions.astype(int))
    np.add.at(counts, (codes, slot), 1)
    rng = np.random.default_rng(SEED+2)
    measured = []
    for _ in range(resamples):
        tn, fp, fn, tp = counts[rng.integers(0,len(counts),size=len(counts))].sum(axis=0)
        precision = tp / max(1,tp+fp); recall=tp/max(1,tp+fn)
        measured.append([(tn+tp)/max(1,tn+fp+fn+tp), precision, recall,
                         2*precision*recall/max(1e-15,precision+recall), fp/max(1,tn+fp)])
    intervals = np.quantile(measured,[.025,.975],axis=0)
    return {key: list(map(float,intervals[:,i])) for i,key in enumerate(('accuracy','precision','recall','f1','false_positive_rate'))}


def final(output):
    if (output / 'final.json').exists() or (output / 'test_opened.json').exists():
        raise ValueError('Final evaluation already started/completed. Do not retune or reopen.')
    frozen = json.loads((output / 'frozen.json').read_text(encoding='utf-8'))
    write_json(output / 'test_opened.json', dict(opened_at=datetime.now(timezone.utc).isoformat(),
        frozen_sha256=hashlib.sha256((output / 'frozen.json').read_bytes()).hexdigest()))
    frame = pd.read_csv(output / 'cohort.csv', keep_default_na=False)
    ix = np.flatnonzero(frame.partition.eq('test'))
    test = frame.iloc[ix]
    labels = test.label.to_numpy()
    base = np.load(output / 'base.npy', mmap_mode='r')[ix]
    features = joblib.load(output / 'rich_features.joblib')
    rich = features.transform(test.url.tolist())
    latent=None
    if any(s['identifier'].endswith('_latent') for s in frozen['selected']):
        latent=joblib.load(output/'latent_features.joblib').transform_matrix(rich)
    result, cache = [], {}
    for selection in frozen['selected']:
        identifier = selection['identifier']
        if identifier not in cache:
            if hashlib.sha256((output / f'{identifier}.joblib').read_bytes()).hexdigest() != selection['artifact_sha256']:
                raise ValueError('Model artifact changed after selection')
            model = joblib.load(output / f'{identifier}.joblib')
            matrix=base if identifier.endswith('_baseline') else latent if identifier.endswith('_latent') else rich
            scores = model.predict_proba(matrix)[:,1]
            cache[identifier] = scores
            del model; gc.collect()
        scores = cache[identifier]
        decisions = scores >= selection['threshold']
        measured = metrics(labels, decisions)
        fpr, recall = measured['false_positive_rate'], measured['recall']
        interval = confidence(labels,decisions,test.group.to_numpy())
        row = dict(**selection, model_name=NAMES[selection['family']], test_rows=len(test),
            **measured, roc_auc=float(roc_auc_score(labels,scores)),
            pr_auc=float(average_precision_score(labels,scores)),
            confidence_95=interval, projected_precision_at_1pct=recall*.01/max(1e-15,recall*.01+fpr*.99),
            all_four_at_least_90=all(measured[k]>=.90 for k in ('accuracy','precision','recall','f1')),
            fpr_under_1pct=bool(fpr<.01), release_ci_fpr_under_1pct=bool(interval['false_positive_rate'][1]<.01))
        result.append(row)
        print(json.dumps(row, indent=2),flush=True)
    predictions = dict(labels=labels, groups=test.group.to_numpy(), **cache)
    np.savez_compressed(output / 'test_predictions.npz', **predictions)
    write_json(output / 'final.json', dict(evaluated_at=datetime.now(timezone.utc).isoformat(),
        audit=json.loads((output/'audit.json').read_text(encoding='utf-8')),
        frozen=frozen, models=result, bootstrap_resamples=1000,
        status='Research only; production artifacts unchanged'))
    rows=[]
    for r in result:
        rows.append(dict(model=r['model_name'],version=r['version'],policy=r['policy'],test_rows=r['test_rows'],
            **{k+'_pct':r[k]*100 for k in ('accuracy','precision','recall','f1','false_positive_rate')},
            target_90_pass=r['all_four_at_least_90'],fpr_under_1pct=r['fpr_under_1pct'],
            identifier=r['identifier'],threshold=r['threshold'],
            projected_precision_at_1pct_pct=r['projected_precision_at_1pct']*100,
            tn=r['confusion_matrix'][0][0],fp=r['confusion_matrix'][0][1],
            fn=r['confusion_matrix'][1][0],tp=r['confusion_matrix'][1][1]))
    pd.DataFrame(rows).to_csv(output / 'final_scores.csv',index=False)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=['prepare','features','latent-features','baseline','lexical','latent','deep','freeze','final'])
    parser.add_argument('--metadata',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--jobs',type=int,default=6)
    args=parser.parse_args()
    if args.stage=='prepare': prepare(args.metadata,args.output)
    elif args.stage=='features':
        if (args.output/'frozen.json').exists(): raise ValueError('Selections already frozen')
        matrices(args.output,pd.read_csv(args.output/'cohort.csv',keep_default_na=False),rich=True)
    elif args.stage=='latent-features':
        if (args.output/'frozen.json').exists(): raise ValueError('Selections already frozen')
        latent_matrices(args.output,pd.read_csv(args.output/'cohort.csv',keep_default_na=False))
    elif args.stage=='freeze': freeze(args.output)
    elif args.stage=='final': final(args.output)
    else: fit_stage(args.output,args.jobs,args.stage)
