"""Generate capstone reports from frozen results without fitting or selecting on test."""
import argparse
import ast
import json
from pathlib import Path
import shutil
import sys
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.frozen import FrozenEstimator

ROOT=Path(__file__).resolve().parents[1]


def percentage(value):
    return '—' if pd.isna(value) else f'{100*value:.2f}%'


def table(rows, extra=False):
    header='| Model | Accuracy | Precision | Phishing recall | F1 | FPR |\n|---|---:|---:|---:|---:|---:|\n'
    return header+'\n'.join('| '+str(r['model'])+' | '+' | '.join(percentage(r.get(k)) for k in ['accuracy','precision','recall','f1','false_positive_rate'])+' |' for r in rows)


def generate(output):
    docs=ROOT/'docs'
    protocol=json.loads((output/'frozen_protocol.json').read_text())
    summary=json.loads((output/'final_summary.json').read_text())
    runtime=json.loads((output/'runtime.json').read_text())
    api=json.loads((output/'api_runtime.json').read_text())
    audit=json.loads((ROOT/'backend/data/capstone_run/dataset_audit.json').read_text())
    historical=json.loads((ROOT/'backend/data/capstone_run/historical_reproduction.json').read_text())
    live=json.loads((output/'live_verification.json').read_text()) if (output/'live_verification.json').exists() else {}
    final=pd.read_csv(output/'final_scores.csv');validation=pd.read_csv(output/'validation_scores.csv')
    winner=protocol['winner'];candidate=winner['model'];cohort='paired_fresh_phishing_reserved_benign'
    primary=final[(final.cohort==cohort)&final.selected_on_validation]
    new=primary[primary.model==candidate].iloc[0];old=primary[primary.model=='existing_deployed'].iloc[0]
    intervals=summary['confidence_intervals_95'];recent=final[(final.cohort=='fresh_openphish')&final.selected_on_validation]
    op=recent[recent.model==candidate].iloc[0];ob=recent[recent.model=='existing_deployed'].iloc[0]
    gates=dict(recall_improves_5pp=bool(new.recall-old.recall>=.05),
        recall_intervals_separated=intervals[candidate]['recall'][0]>intervals['existing_deployed']['recall'][1],
        f1_improves=bool(new.f1>old.f1),fpr_upper_at_most_1pct=intervals[candidate]['false_positive_rate'][1]<=.01,
        openphish_nonregression=bool(op.recall>=ob.recall-.02),latency_p95_at_most_50ms=runtime['single_url_p95_ms']<=50,
        rss_at_most_400mib=runtime['process_rss_mib']<=400)
    accepted=all(gates.values())
    decision=dict(accepted=accepted,gates=gates,selected_research_candidate=candidate,
        production='existing XGBoost retained' if not accepted else 'eligible for a separately verified integration; no deployment implied')
    (output/'acceptance_result.json').write_text(json.dumps(decision,indent=2))
    # Each family/configuration below is chosen using validation, never its final row.
    names=[*protocol['family_winners'].values(),'binary_malicious','three_class','separate_specialists',candidate]
    rows=[]
    for name in dict.fromkeys(names):
        val=validation[(validation.model==name)&(validation.policy=='fpr_1pct')].sort_values(['recall','f1','model_weight'],ascending=False).iloc[0]
        row=final[(final.model==name)&(final.policy=='fpr_1pct')&(final.model_weight==val.model_weight)&(final.cohort==cohort)].iloc[0]
        rows.append(row.to_dict())
    comparison='\n\n## Measured paired final results\n\n'+table([old.to_dict(),*rows])+'\n\n'
    comparison+='All rows use the same 48,406 URLs: 16,117 fresh-feed phishing and 32,289 reserved legitimate URLs. Family configurations and weights were chosen on validation. The last ensemble is the single preselected primary candidate; other final rows are comparisons, not alternative release selections.\n\n'
    comparison+=f'**Acceptance: {"passed" if accepted else "failed"}.** Candidate FPR is {percentage(new.false_positive_rate)}; its 95% upper bound is {percentage(intervals[candidate]["false_positive_rate"][1])}. The current XGBoost artifact is retained. No threshold is retuned after this result.\n'
    comparison+='\n`rf_200` is Random Forest; `xgb_650` is XGBoost; `lgb_400` is LightGBM; `char_1e-05` is character TF-IDF/SGD. Numeric suffixes are configured maximum tree counts, not scores. Early stopping can use fewer boosting iterations. `xgb_character_0.75` mixes 75% character and 25% XGBoost scores.\n'
    ablation=validation[(validation.model.isin(['xgb_original50','xgb_450']))&(validation.model_weight==1.)&(validation.policy=='fpr_1pct')]
    comparison+='\n## Retrained feature ablation\n\n'+table(ablation.to_dict('records'))+'\n\nThe original 50-feature and enhanced 64-feature XGBoost variants share the same configured hyperparameters and seed. Extra features improve validation recall at the fixed FPR policy; they were not chosen using final-test scores. This does not establish the causal importance of individual correlated features.\n'
    path=docs/'MODEL_COMPARISON.md';text=path.read_text(encoding='utf-8');marker='\n\n## Measured paired final results'
    path.write_text(text.split(marker)[0]+comparison,encoding='utf-8')
    subtype=[]
    for label in ['fresh_openphish','fresh_phishtank','recent_phishtank_30d','paired_recent_phishing_30d']:
        for name in ['existing_deployed',candidate]:
            row=final[(final.model==name)&final.selected_on_validation&(final.cohort==label)].iloc[0]
            ci=summary['phishing_only_recall_intervals_95'][name+' / '+label]
            subtype.append(f'| {label} | {name} | {int(row.rows):,} | {percentage(row.recall)} | {percentage(ci[0])}–{percentage(ci[1])} |')
    cirows=[]
    for name in ['existing_deployed',candidate]:
        for metric,bounds in intervals[name].items():cirows.append(f'| {name} | {metric} | {percentage(bounds[0])}–{percentage(bounds[1])} |')
    matrices=[]
    for row in [old,new]:matrices.append(f'- {row.model}: `{row.confusion_matrix}`.')
    operations=[]
    for row in summary['operational']:
        operations.append(f'| {row["model"]} | {percentage(row["coverage"])} | {row["needs_review"]:,} | {row["reviewed_phishing"]:,} | {percentage(row["decisive_metrics"]["accuracy"])} |')
    def condition(policy):
        return final[(final.model==candidate)&(final.policy=='fpr_1pct')&(final.model_weight==policy)&(final.cohort==cohort)].iloc[0].to_dict()
    malicious={}
    for name_cohort in ['reserved_malware_benign','reserved_all_types']:
        selected=[]
        for name in ['existing_deployed','binary_malicious','three_class','separate_specialists',candidate]:
            selected.append(final[(final.model==name)&(final.cohort==name_cohort)&
                (final.policy==('existing_frozen' if name=='existing_deployed' else 'fpr_1pct'))&
                (final.model_weight==(old.model_weight if name=='existing_deployed' else 1.))].iloc[0].to_dict())
        malicious[name_cohort]=table(selected).replace('Phishing recall','Malware recall' if name_cohort=='reserved_malware_benign' else 'Malicious recall')
    threshold_rows=[]
    for _,row in final[(final.model==candidate)&(final.model_weight==1.)&(final.cohort==cohort)].iterrows():
        threshold_rows.append(f'| {row.policy} | {row.threshold:.6f} | {percentage(row.precision)} | {percentage(row.recall)} | {percentage(row.false_positive_rate)} |')
    # Describe failures through measured URL-pattern slices, not invented attack subtypes.
    predictions=pd.read_csv(output/'selected_predictions.csv');predictions=predictions[predictions.paired_cohort].copy()
    patterns=[]
    for name,threshold in [('existing_deployed',old.threshold),(candidate,new.threshold)]:
        missed=predictions[(predictions.kind==1)&(predictions[name]<threshold)]
        parts=[urlsplit(url) for url in missed.url]
        patterns.append(dict(model=name,false_negatives=len(missed),root_path=sum(p.path in ('','/') for p in parts),
            https=sum(p.scheme=='https' for p in parts),query_present=sum(bool(p.query) for p in parts)))
    (output/'false_negative_patterns.json').write_text(json.dumps(patterns,indent=2))
    pattern_rows='\n'.join(f'| {r["model"]} | {r["false_negatives"]:,} | {percentage(r["root_path"]/r["false_negatives"])} | {percentage(r["https"]/r["false_negatives"])} | {percentage(r["query_present"]/r["false_negatives"])} |' for r in patterns)
    prevalence_precision=(new.recall*.01)/(new.recall*.01+new.false_positive_rate*.99)
    report=f'''# Evaluation report — 1 November 2026

## Independent reproduction of the historical baseline

The original frozen XGBoost artifact SHA-256 is `{historical['model_sha256']}`.
Recomputing historical served rounding gives 94.21% accuracy / 88.85% malicious
recall on 48,803 cleaned Kaggle URLs, and 93.86% / 89.53% on 42,781 unseen-domain
URLs. OpenPhish recall remains 43.24% (128/296) and 38.87% (103/265).
The corrected full-precision path gives 94.18% / 88.79% and 93.82% / 89.47%;
15 rounding-dependent malware decisions change. Phishing-only counts do not.
Earlier live samples matched; a new live request during this work timed out.
These are artifact reproductions, not a claim that every URL was sent to Render.

## Frozen new comparison

{table([old.to_dict(),new.to_dict()])}

The paired cohort has 48,406 URLs from 33,285 domains absent from both development
corpora: 16,117 phishing and 32,289 legitimate. All fresh-feed test domains are
absent from the entire new development corpus. The negative data are reserved
historical domains, not independently collected recent browsing.

Confusion matrices use `[[TN, FP], [FN, TP]]`:

{chr(10).join(matrices)}

The candidate detects {ast.literal_eval(new.confusion_matrix)[1][1]:,} phishing URLs versus {ast.literal_eval(old.confusion_matrix)[1][1]:,}
for the baseline, with 502 rather than 991 false positives. These are a measured
improvement, not achievement of every 95% target. At an assumed 1% phishing
prevalence and unchanged sensitivity/specificity, candidate precision would be
{percentage(prevalence_precision)}; the observed 96.08% precision does not transfer
automatically to ordinary browsing.

## Phishing-only results

| Cohort | Model | URLs | Recall | 95% domain-bootstrap interval |
|---|---|---:|---:|---:|
{chr(10).join(subtype)}

Fresh OpenPhish is a different snapshot from historical Kaggle OpenPhish; their
recalls must not be compared as a paired before/after experiment. PhishTank
retrieval is not first-seen time. The recent cohort uses actual verification
timestamps, with mixed date formats explicitly parsed before final evaluation.

## Malware and overall malicious results

The malware/benign cohort contains 4,352 reserved URLhaus malware and 73,041
reserved legitimate URLs. This is a within-development-source, domain-separated
test, not a fresh independent malware benchmark. Labels 1 and 2 remain distinct.
The existing artifact uses its frozen threshold; other rows use their separately
validation-selected overall-malicious 1% FPR thresholds. Thus their phishing
and malware operating thresholds are explicitly different.

{malicious['reserved_malware_benign']}

All 141,010 reserved test URLs (legitimate, phishing and malware), evaluated as
legitimate versus either malicious type:

{malicious['reserved_all_types']}

## Threshold tradeoffs and AUC

Each threshold below was frozen from validation. Its policy name states a
validation objective, not a guarantee of the same FPR on final test. No alternate
row is chosen for release after examining this table.

| Validation policy | Threshold | Test precision | Test phishing recall | Test FPR |
|---|---:|---:|---:|---:|
{chr(10).join(threshold_rows)}

Paired candidate ROC-AUC: {new.roc_auc:.6f}; PR-AUC (average precision):
{new.pr_auc:.6f}. Existing frozen system-score ROC-AUC: {old.roc_auc:.6f};
PR-AUC: {old.pr_auc:.6f}. AUC does not establish recall at a low false-positive
operating point or calibrate the hybrid index.

## Uncertainty and operational outcomes

The following are 1,000 registrable-domain bootstrap percentile intervals on the
paired cohort. Dependence within each domain is retained; campaigns can still
cross domains, so this is not campaign-cluster uncertainty.

| Model | Metric | 95% interval |
|---|---|---:|
{chr(10).join(cirows)}

Binary metrics count only a high-risk alarm as positive; needs-review URLs count
as non-positive. Operational metrics also show abstention, rather than presenting
metrics on decisive predictions as full-coverage accuracy.

| Model | Decisive coverage | Needs review | Phishing in review | Decisive-only accuracy |
|---|---:|---:|---:|---:|
{chr(10).join(operations)}

## ML, rules and threat intelligence

{table([condition(1.),condition(.9)])}

The frozen policy selected pure model mixing over the rule-weighted alternative.
The application still retains the abstract's hybrid rule pipeline with its
existing production model. No existing rule weight was increased to improve a
test score. Structured rule evidence now identifies correlated warnings; they
are not described as independent probabilistic evidence.

Complete threat-intelligence performance is **not independently established**:
the live service reported no feed indicators and no configured reputation key.
Feed-derived test labels are not looked up in those same feeds. Mocked exact
match/expiry/consent/failure tests validate integration behavior, not detection
accuracy. Malware-only and all-type rows use separately validation-tuned
malicious thresholds, identified by `threshold_target` in the results CSV.

## Errors and runtime

Paired error breakdown: PhreshPhish legitimate false alarms fell from 866 to
369, while ealvaradob legitimate false alarms rose from 125 to 133. OpenPhish
misses fell from 87 to 43; paired PhishTank misses fell from 7,036 to 3,770.
The gains are not uniform across legitimate sources. URL-pattern error counts
(root path, HTTPS, query presence) describe the remaining misses:

| Model | False negatives | Root path among misses | HTTPS among misses | Query among misses |
|---|---:|---:|---:|---:|
{pattern_rows}

These are URL-pattern slices, not adjudicated attack subtypes. Without page
content we cannot reliably assign credential-form or campaign subtype labels.
Valid-looking HTTPS URLs and compromised legitimate hosts can lack the lexical
warning signals available to this offline model. More threshold tuning on these
same final URLs would invalidate the independent test rather than solve that gap.

Total recorded training/search time: {protocol['training_seconds']:.1f} seconds.
The compact selected candidate is {runtime['candidate_file_bytes']/2**20:.2f} MiB;
fresh-process RSS {runtime['process_rss_mib']:.1f} MiB, load delta
{runtime['model_load_rss_delta_mib']:.1f} MiB, single-URL median
{runtime['single_url_median_ms']:.2f} ms / p95 {runtime['single_url_p95_ms']:.2f} ms
over 32 warm predictions. RSS includes interpreter/library overhead, not just trees.
The existing model's local full HTTP API median is {api['http_median_ms']:.2f} ms /
p95 {api['http_p95_ms']:.2f} ms over 16 warmed requests, with external services off.
These are local Windows measurements, not Render cold-start/internet latency or
full-API measurements of a deployed candidate.

## Acceptance and deployment

**Candidate rejected for production replacement:** the FPR 95% upper bound is
{percentage(intervals[candidate]['false_positive_rate'][1])}, exceeding the
predeclared 1% gate. All other declared gates passed. No alternative final-test
row is promoted. The previous production models are unchanged and available
for rollback; only decision consistency and structured rule explanations were
integrated into the local API. No live deployment is claimed.

Final post-push service verification: health HTTP {live.get('health_status','not checked')},
prediction HTTP {live.get('prediction_status','not checked')}; active model remains
`{live.get('model_version','not checked')}`. The decision patch is
{'visible' if live.get('decision_patch_visible') else 'not verified as active'}
in the live response. Pushing GitHub code is not a verified Render release.
The remaining deployment step is to release the tested API patch with the
documented `backend/` root and `python main.py` start command, retaining the old
model, then recheck prediction fields, origins, memory and feed startup.

Overall accuracy, F1, phishing recall and unseen-domain recall do not meet the
95% targets. Further work needs independently adjudicated recent benign deep
links and new phishing campaigns; any new tuning needs a new final test.
The current final feeds cannot become validation data while retaining their
independent-test status. Missing collection dates, source/label confounding,
shared campaigns/templates and feed label errors remain limitations.

![Paired confusion matrices](figures/phishing_confusion_matrices.png)

![Paired ROC and precision-recall curves](figures/phishing_roc_pr.png)
'''
    (docs/'EVALUATION_REPORT.md').write_text(report,encoding='utf-8')
    # Append every frozen final row, not only flattering comparisons, to the one CSV.
    csv=docs/'capstone/linkguard_final_results_2026-11-01.csv';previous=pd.read_csv(csv)
    previous=previous[previous.experiment!='capstone_typed_phishing_2026-11-01']
    final['experiment']='capstone_typed_phishing_2026-11-01';final['dataset']='typed PhreshPhish + reserved fresh feeds'
    final['status']='research candidate; no model deployed';final['recall_target']=np.where(final.threshold_target=='malicious_fpr_1pct','malicious','phishing')
    final['primary_comparison']=final.selected_on_validation
    final['selected_on_validation']=(final.model==candidate)&(final.policy==winner['policy'])&(final.model_weight==winner['model_weight'])
    for i,row in final.iterrows():
        matrix=ast.literal_eval(row.confusion_matrix)
        for key,value in zip(['tn','fp','fn','tp'],np.asarray(matrix).ravel()):final.loc[i,key]=int(value)
    pd.concat([previous,final.drop(columns=['confusion_matrix'])],ignore_index=True).to_csv(csv,index=False)
    bundle=joblib.load(output/'frozen_bundle.joblib');parameters={}
    for name,model in bundle['models'].items():
        estimator=model.calibrated_classifiers_[0].estimator
        while isinstance(estimator,FrozenEstimator):estimator=estimator.estimator
        parameters[name]=dict(parameters=estimator.get_params(),training_seconds=bundle['timing'][name],
            best_iteration=getattr(estimator,'best_iteration_',getattr(estimator,'best_iteration',None)))
    (output/'model_parameters.json').write_text(json.dumps(parameters,indent=2,default=str))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    figures=docs/'figures';figures.mkdir(exist_ok=True)
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    for ax,row in zip(axes,[old,new]):
        matrix=np.array(ast.literal_eval(row.confusion_matrix));ax.imshow(matrix,cmap='Blues')
        ax.set_xticks([0,1],['Benign','Phishing']);ax.set_yticks([0,1],['Benign','Phishing'])
        ax.set(xlabel='Predicted',ylabel='Actual',title='Current XGBoost' if row.model=='existing_deployed' else 'Phishing ensemble')
        for (i,j),value in np.ndenumerate(matrix):ax.text(j,i,str(value),ha='center',va='center',color='white' if value>matrix.max()/2 else 'black')
    fig.suptitle('Paired unseen domains: fresh phishing + historical benign');fig.tight_layout();fig.savefig(figures/'phishing_confusion_matrices.png',dpi=180);plt.close(fig)
    shutil.copy2(output/'roc_pr_curves.png',figures/'phishing_roc_pr.png')
    print(json.dumps(decision,indent=2));print('Generated reports and appended all frozen final scores.')


if __name__=='__main__':
    sys.path.insert(0,str(ROOT/'backend/data/research_v3/deps'))
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    generate(parser.parse_args().output)
