"""Publish measured fresh results without raw URLs or any production model changes."""
import argparse
import json
from pathlib import Path
import shutil

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def generate(experiment, output):
    report=json.loads((experiment/'final.json').read_text(encoding='utf-8'))
    output.mkdir(parents=True,exist_ok=True)
    shutil.copy2(experiment/'final_scores.csv',output/'scores.csv')
    shutil.copy2(experiment/'final.json',output/'evaluation.json')
    candidates=[]
    for path in sorted(experiment.glob('*.json')):
        result=json.loads(path.read_text(encoding='utf-8'))
        if 'identifier' not in result: continue
        for policy,values in result['validation'].items():
            candidates.append(dict(identifier=result['identifier'],family=result['family'],policy=policy,
                **{key+'_pct':values[key]*100 for key in ('accuracy','precision','recall','f1','false_positive_rate')},
                threshold=result[policy+'_threshold'],stage=result['stage']))
    pd.DataFrame(candidates).to_csv(output/'validation_candidates.csv',index=False)
    results=report['models']
    audit=report['audit']
    test=audit['splits']['test']
    balanced_pass=sum(r['all_four_at_least_90'] for r in results if r['version']=='Retrained' and r['policy']=='balanced')
    conservative_pass=sum(r['all_four_at_least_90'] and r['fpr_under_1pct'] for r in results
                          if r['version']=='Retrained' and r['policy']=='conservative')
    lines=['# Fresh LinkGuard experiment — 3 November 2026','',
        '**Research results; the deployed application and client ZIP are unchanged.**','',
        f'**Final verdict: {balanced_pass}/3 retrained families meet all four 90% targets at their '
        f'balanced policies; {conservative_pass}/3 meet all four plus FPR <1% at their conservative policies.**','',
        'These are measured point estimates. Random Forest is borderline: its accuracy and recall '
        '95% confidence intervals extend below 90%. The false-positive release target is unmet; '
        'these results do not justify automatic production promotion.','',
        f"Data: [official PhreshPhish]({audit['source']}), revision `{audit['source_revision']}`.",
        f"Final test: **{test['rows']:,} URLs**, **{test['domains']:,} domains**, "
        f"{test['positives']:,} phishing / {test['negatives']:,} benign. "
        f"Collection dates {test['date_min']} through {test['date_max']}.",
        '', 'Training, calibration, validation and test registrable domains are disjoint. '
        'Publisher test rows on training-corpus domains were excluded before any fitting. '
        'No UCI data, historical scores, pretrained research models, live feeds or reputation labels were used. '
        'All three 32-feature baselines were freshly trained from current GitHub code. '
        'Text vocabularies/selection were learned on fit rows only; thresholds and models were frozen on validation.',
        '', 'Scores apply to URLs accepted by the current product parser (HTTP(S), at most 4,096 characters, '
        'valid host/encoding). Parser rejections are counted in `evaluation.json`, not counted as correct classifications. '
        'Duplicates and label conflicts are removed before fitting. Feature candidates include train-only '
        'character/word counts and train-only TF-IDF/SVD factors; no other classifier supplies predictions as features.',
        '', f"The source contains a www imbalance; every input feature ignores conventional leading www. "
        f"Numeric and text invariance was checked on {audit['www_invariance_pairs_checked']} corpus pairs "
        'plus unit fixtures. This neutralizes that explicit shortcut, without claiming absence of all source bias.',
        '', '| Model | Version | Policy | Accuracy | Precision | Recall | F1 | FPR | All four ≥90% |',
        '|---|---|---|---:|---:|---:|---:|---:|---|']
    for r in results:
        values=' | '.join(f"{r[key]*100:.2f}%" for key in ('accuracy','precision','recall','f1','false_positive_rate'))
        lines.append(f"| {r['model_name']} | {r['version']} | {r['policy']} | {values} | "
                     f"{'PASS' if r['all_four_at_least_90'] else 'FAIL'} |")
    lines.extend(['','The balanced policy maximizes the weakest '
        'of the four requested validation metrics for both baselines and retrained candidates. The conservative policy targets at most '
        '0.8% validation FPR, with margin for the desired <1% test rate. A test target miss is a failed gate, '
        'not a reason to retune on the final test.','',
        '| Retrained model / policy | Recall 95% CI | FPR 95% CI | Projected precision at 1% phishing |',
        '|---|---:|---:|---:|'])
    for r in results:
        if r['version']!='Retrained':continue
        interval=r['confidence_95']
        recall='–'.join(f'{x*100:.2f}%' for x in interval['recall'])
        fpr='–'.join(f'{x*100:.2f}%' for x in interval['false_positive_rate'])
        lines.append(f"| {r['model_name']} / {r['policy']} | {recall} | {fpr} | "
                     f"{r['projected_precision_at_1pct']*100:.2f}% |")
    lines.extend(['','Confidence intervals use 1,000 registrable-domain bootstrap resamples. '
        'The 1% precision is a mathematical projection from measured recall/FPR, not an observed result. '
        'The filtered test has an elevated phishing prevalence, so observed precision must not be '
        'presented as general internet precision. This evaluates URL-only phishing classification; '
        'it cannot establish performance on future campaigns or arbitrary sources.','',
        'Every attempted development candidate is listed in `validation_candidates.csv`. '
        'Exact confusion counts, frozen thresholds, model SHA-256 hashes, and provenance appear '
        'in `evaluation.json` and `scores.csv`. Selected fitted research artifacts and raw metadata '
        'remain outside the minimized production repository.','',
        'Reproduce using `tools/fresh_data.py`, `tools/fresh_benchmark.py` and `tools/fresh_protocol.md`. '
        'Install `backend/requirements.txt`, `tools/requirements-fresh.txt`; install '
        '`tools/requirements.txt` only for charts. Source data attribution: Dalton et al., '
        '[PhreshPhish](https://arxiv.org/abs/2507.10854), CC BY 4.0.'])
    (output/'README.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    names=['Random Forest','XGBoost','LightGBM']
    fig,axes=plt.subplots(1,3,figsize=(16,5.8))
    for i,name in enumerate(names):
        ax=axes[i]
        rows=[next(r for r in results if r['model_name']==name and r['version']==version and r['policy']=='balanced')
              for version in ('Fresh baseline','Retrained')]
        positions=np.arange(4)
        for j,row in enumerate(rows):
            values=[row[key]*100 for key in ('accuracy','precision','recall','f1')]
            bars=ax.bar(positions+(-.18 if j==0 else .18),values,.35,
                        label=row['version'],color=('#94a3b8' if j==0 else '#0891b2'))
            ax.bar_label(bars,fmt='%.1f',fontsize=8,padding=2)
        ax.axhline(90,color='#dc2626',linestyle='--',linewidth=1)
        ax.set_ylim(0,107)
        ax.set_xticks(positions,['Accuracy','Precision','Recall','F1'],fontsize=9)
        ax.set_title(name,weight='bold')
        ax.set_ylabel('Percent')
        ax.grid(axis='y',alpha=.2)
        ax.set_axisbelow(True)
        ax.text(.5,-.15,'Balanced FPR: '+ ' → '.join(f"{r['false_positive_rate']*100:.2f}%" for r in rows),
                transform=ax.transAxes,ha='center',fontsize=10)
    fig.suptitle('LinkGuard · Fresh training and unseen-domain later-period test',fontsize=17,weight='bold',y=.98)
    axes[0].legend(loc='lower left')
    fig.text(.5,.045,f"{test['rows']:,} URLs · {100*test['positives']/test['rows']:.1f}% phishing · "
             f"{test['domains']:,} unseen domains · www-invariant features · "
             'No prior scores used · Research only',ha='center',fontsize=10)
    fig.subplots_adjust(top=.82,bottom=.26,wspace=.25)
    fig.savefig(output/'comparison.png',dpi=180)
    fig.savefig(output/'comparison.pdf')
    plt.close(fig)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    generate(args.experiment,args.output)
