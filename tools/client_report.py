"""Build the client CSV from frozen evidence, or redraw charts from that CSV.

No training or threshold selection uses test results. Raw URLs stay private.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))

import numpy as np
import pandas as pd

REPORTS = ROOT/'reports'


def prepare(evidence, historical):
    import joblib
    from detector import FEATURE_NAMES, extract_features, evaluate_rules, hybrid_score
    from metrics import metrics
    from sklearn.metrics import roc_auc_score, average_precision_score
    frame = pd.read_csv(evidence/'selected_predictions.csv')
    frame = frame[frame.paired_cohort].reset_index(drop=True)
    y = (frame.kind.to_numpy()==1).astype(int)
    assert len(frame)==48406 and set(frame.kind.unique())=={0,1}
    assert frame.group.nunique()==33285 and int(y.sum())==16117
    fingerprint = hashlib.sha256('\n'.join(f'{u}\t{k}' for u,k in zip(frame.url,y)).encode()).hexdigest()
    vectors=[]
    for url in frame.url:
        _,values,_=extract_features(url)
        vectors.append([values[name] for name in FEATURE_NAMES])
    x=np.asarray(vectors)
    rules=np.array([evaluate_rules(dict(zip(FEATURE_NAMES,row)))[0] for row in x])
    rows=[]
    for family,title in [('random_forest','Random Forest'),('xgboost','XGBoost'),('lightgbm','LightGBM')]:
        path=ROOT/'backend/models'/f'{family}.joblib';a=joblib.load(path)
        p=a['model'].predict_proba(x)[:,list(a['model'].classes_).index(1)]
        score=hybrid_score(p,rules,a.get('model_weight',.8))
        measured=metrics(y,score>=a['threshold'])
        rows.append(dict(benchmark='independent_phishing',model=title,version='Original',model_id=family,
            policy='Frozen original policy',status='Deployed' if family=='xgboost' else 'Preserved baseline',
            positive_class='phishing',test_rows=len(y),domains=frame.group.nunique(),
            threshold=a['threshold'],model_weight=a.get('model_weight',.8),
            model_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cohort_sha256=fingerprint,
            roc_auc=roc_auc_score(y,score),pr_auc=average_precision_score(y,score),**measured))
        if family=='xgboost':
            np.testing.assert_allclose(score,frame.existing_deployed,rtol=1e-6,atol=1e-7)
        print('Measured frozen baseline:',title,flush=True)
    protocol=json.loads((evidence/'frozen_protocol.json').read_text())
    final=pd.read_csv(evidence/'final_scores.csv');val=pd.read_csv(evidence/'validation_scores.csv')
    selected=[('rf_','Random Forest'),('xgb_','XGBoost'),('lgb_','LightGBM'),('char_','Character TF-IDF')]
    for prefix,title in selected:
        name=protocol['family_winners'][prefix]
        policy=val[(val.model==name)&(val.policy=='fpr_1pct')].sort_values(['recall','f1','model_weight'],ascending=False).iloc[0]
        result=final[(final.model==name)&(final.policy=='fpr_1pct')&(final.model_weight==policy.model_weight)&
                     (final.cohort=='paired_fresh_phishing_reserved_benign')].iloc[0]
        rows.append(convert(result,title,'Improved',fingerprint,frame.group.nunique()))
    winner=protocol['winner']
    result=final[(final.model==winner['model'])&(final.policy==winner['policy'])&
                 (final.model_weight==winner['model_weight'])&(final.cohort=='paired_fresh_phishing_reserved_benign')].iloc[0]
    rows.append(convert(result,'XGBoost + character ensemble','Candidate',fingerprint,frame.group.nunique()))
    prior=pd.read_csv(historical)
    prior=prior[(prior.experiment=='ealvaradob_only_retrained')&
                prior.policy.isin(['balanced_validation_f1','raw_validation_fpr_1pct'])]
    assert len(prior)==6
    for record in prior.to_dict('records'):
        rows.append(dict(benchmark='ealvaradob_only',model=record['model'],version='Retrained',
            model_id=record['model'],policy=record['policy'],status='Historical within-source benchmark; not deployed',
            positive_class='publisher malicious label',test_rows=int(record['rows']),domains=71527,
            threshold=record['threshold'],cohort_sha256='Archived same-split domain-disjoint ealvaradob-only test',
            **{k:record[k] for k in ['accuracy','precision','recall','f1','false_positive_rate']},
            confusion_matrix=[[int(record['tn']),int(record['fp'])],[int(record['fn']),int(record['tp'])]]))
    output=[]
    for row in rows:
        tn,fp,fn,tp=np.asarray(row.pop('confusion_matrix')).ravel()
        row.update(tn=int(tn),fp=int(fp),fn=int(fn),tp=int(tp),
            evaluation_date='2026-11-03' if row['benchmark']=='independent_phishing' and row['version']=='Original' else '2026-11-01',
            score_origin='Frozen measured results; no UCI-only test cohort',
            training_change='Data, features and model policy changed together; not a causal single-factor ablation')
        for key in ['accuracy','precision','recall','f1','false_positive_rate']:
            row[key+'_pct']=100*row.pop(key)
        row.pop('missed_phishing_rate',None)
        output.append(row)
    REPORTS.mkdir(exist_ok=True)
    pd.DataFrame(output).to_csv(REPORTS/'model_scores.csv',index=False)
    print(pd.DataFrame(output)[['benchmark','model','version','accuracy_pct','recall_pct','f1_pct','false_positive_rate_pct']].round(2).to_string(index=False),flush=True)


def convert(result,title,version,fingerprint,domains):
    import ast
    return dict(benchmark='independent_phishing',model=title,version=version,model_id=result.model,
        policy=result.policy,status='Research only; not deployed',positive_class='phishing',test_rows=int(result.rows),
        domains=domains,threshold=result.threshold,model_weight=result.model_weight,cohort_sha256=fingerprint,
        **{k:result[k] for k in ['accuracy','precision','recall','f1','false_positive_rate','roc_auc','pr_auc']},
        confusion_matrix=ast.literal_eval(result.confusion_matrix))


def draw():
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
    from matplotlib.ticker import PercentFormatter
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,
                         'axes.spines.right':False,'axes.titleweight':'bold','figure.facecolor':'#f6f8fa'})
    data=pd.read_csv(REPORTS/'model_scores.csv')
    paired=data[data.benchmark=='independent_phishing'];colors=['#8b9baa','#126b59']
    names=['Random Forest','XGBoost','LightGBM']
    with PdfPages(REPORTS/'model_improvements.pdf') as pdf:
        fig=plt.figure(figsize=(14,9));grid=fig.add_gridspec(3,2,height_ratios=[2.4,1.8,.65],hspace=.5)
        fig.suptitle('LINKGUARD  |  Measured model improvements',x=.07,y=.97,ha='left',fontsize=22,color='#182a3b')
        fig.text(.07,.91,'48,406 test URLs · 33,285 domains unseen by both training corpora · 3 November 2026',color='#526575')
        for column,(metric,title) in enumerate([('recall_pct','Phishing recall (%) — higher is better'),
                                              ('false_positive_rate_pct','False positives (%) — lower is better')]):
            ax=fig.add_subplot(grid[0,column]);x=np.arange(3)
            for i,version in enumerate(['Original','Improved']):
                values=[paired[(paired.model==name)&(paired.version==version)].iloc[0][metric] for name in names]
                bars=ax.bar(x+(i-.5)*.32,values,.30,color=colors[i],label=version)
                ax.bar_label(bars,fmt='%.2f',padding=4,fontsize=10)
            ax.set_xticks(x,names);ax.set_title(title,pad=16);ax.set_ylim(0,100 if column==0 else max(paired[metric].max(),1)*1.28)
            if column:ax.axhline(1,color='#b57625',ls='--',lw=1,label='1% release target')
            ax.grid(axis='y',alpha=.15);ax.set_axisbelow(True);ax.legend(fontsize=8,loc='upper center',ncols=3 if column else 2)
        ax=fig.add_subplot(grid[1,:]);ax.axis('off')
        chosen=pd.concat([paired[paired.model==name].sort_values('version',ascending=False) for name in names])
        table_rows=[[r.model,r.version,*[f'{getattr(r,k):.2f}%' for k in ['accuracy_pct','precision_pct','recall_pct','f1_pct','false_positive_rate_pct']]] for r in chosen.itertuples()]
        tab=ax.table(cellText=table_rows,colLabels=['Model','Version','Accuracy','Precision','Phishing recall','F1','False positives'],loc='center',cellLoc='center',bbox=[0,.03,1,.95])
        tab.auto_set_font_size(False);tab.set_fontsize(10)
        for (r,c),cell in tab.get_celld().items():
            cell.set_edgecolor('#dce5e9');cell.set_facecolor('#e8f2ee' if r==0 else '#ffffff')
        ax=fig.add_subplot(grid[2,:]);ax.axis('off');ensemble=paired[paired.version=='Candidate'].iloc[0]
        ax.text(0,.9,f'Research ensemble: {ensemble.recall_pct:.2f}% phishing recall · {ensemble.f1_pct:.2f}% F1 · {ensemble.false_positive_rate_pct:.2f}% false positives',fontsize=13,weight='bold',color='#126b59')
        ax.text(0,.4,'Not deployed: it missed the 1% false-positive gate. The shipped application retains the existing XGBoost model.',fontsize=10)
        fig.text(.07,.035,'Same test cohort and frozen thresholds. Training data/features/policies changed together. No UCI-only shortcut benchmark is used.',fontsize=8.5,color='#526575')
        fig.text(.07,.015,'Test prevalence is 33.3% phishing. Precision changes with real browsing prevalence; these are benchmark results, not universal guarantees.',fontsize=8.5,color='#526575')
        fig.subplots_adjust(left=.07,right=.97,top=.84,bottom=.07);pdf.savefig(fig);fig.savefig(REPORTS/'model_improvements.png',dpi=180);plt.close(fig)
        fig=plt.figure(figsize=(14,9));grid=fig.add_gridspec(2,2,height_ratios=[2,1.6],hspace=.5)
        fig.suptitle('LINKGUARD  |  Single-source validation',x=.07,y=.97,ha='left',fontsize=22,color='#182a3b')
        fig.text(.07,.91,'ealvaradob only · 811,472 cleaned URLs · 178,918 test URLs · 71,527 held-out domains',color='#526575')
        single=data[data.benchmark=='ealvaradob_only']
        for col,(policy,title) in enumerate([('balanced_validation_f1','Balanced threshold: maximum validation F1'),
                                            ('raw_validation_fpr_1pct','Conservative: 1% validation FPR target')]):
            ax=fig.add_subplot(grid[0,col]);part=single[single.policy==policy].set_index('model').loc[names];x=np.arange(3)
            for j,(metric,label,color) in enumerate([('accuracy_pct','Accuracy','#617b91'),('recall_pct','Positive-class recall','#126b59'),('false_positive_rate_pct','False positives','#b57625')]):
                bars=ax.bar(x+(j-1)*.23,part[metric],.21,label=label,color=color);ax.bar_label(bars,fmt='%.1f',padding=3,fontsize=9)
            ax.set_xticks(x,names);ax.set_ylim(0,105);ax.set_title(title,pad=16);ax.legend(fontsize=8,loc='upper center',bbox_to_anchor=(.5,-.11),ncols=2);ax.grid(axis='y',alpha=.15);ax.set_axisbelow(True)
        ax=fig.add_subplot(grid[1,:]);ax.axis('off')
        ax.text(0,.95,'What the client can conclude',fontsize=16,weight='bold',color='#182a3b')
        notes=[
            '• UCI is excluded from this single-source benchmark; the 32-feature extractor ignores the conventional www prefix.',
            '• Balanced accuracy is 88–89%, with 13–15% false positives. High recall does not mean the system is ready for automatic blocking.',
            '• Conservative thresholds reduce false positives below 1%, but recall falls to 45–49%. Thresholds were chosen on validation only.',
            '• Positive-class labels here follow the publisher; they are not asserted to be independently verified phishing-only ground truth.',
            '• No dataset is proven bias-free. The first page uses separately labelled phishing and domain exclusions for a stronger comparison.',
            '• Original models used legacy mixed-source training. Improved research models used typed data, richer features and separate calibration.',
            '• The CSV contains the exact counts, thresholds, cohort fingerprint and deployment status behind these charts.'
        ]
        for i,line in enumerate(notes):ax.text(0,.75-i*.105,line,fontsize=10,color='#344b5c')
        fig.subplots_adjust(left=.07,right=.97,top=.83,bottom=.08);pdf.savefig(fig);plt.close(fig)
    print('Created reports/model_scores.csv, model_improvements.pdf and model_improvements.png',flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepare-evidence',type=Path)
    p.add_argument('--historical-scores',type=Path,help='Archived aggregate score CSV; required only when preparing private evidence')
    args=p.parse_args()
    if args.prepare_evidence:
        if not args.historical_scores:p.error('--prepare-evidence requires --historical-scores from the research archive')
        prepare(args.prepare_evidence,args.historical_scores)
    draw()
