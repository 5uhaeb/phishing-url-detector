"""Audit frozen LinkGuard models on supplied CSVs without tuning on the test data.

This script is intentionally evaluation-only. It does not collect URLs, visit
destinations, use source/label metadata as features, or select a threshold.
"""

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from detector import FEATURE_NAMES, extract_features, hybrid_score, evaluate_rules
from metrics import metrics

FORBIDDEN_FEATURES = {
    "source", "label_name", "label", "target", "row_id", "id", "timestamp",
}
ABLATIONS = {
    "all_features": (),
    "no_hostname_shape": (
        "hostname_length", "subdomains", "dots", "hyphens", "hostname_entropy",
        "hostname_digit_ratio", "known_suffix",
    ),
    "no_path_query": (
        "path_length", "query_length", "path_entropy", "longest_path_segment",
        "opaque_path_token", "encoded_destination", "path_keywords", "path_depth",
        "query_parameters",
    ),
    "no_scheme_ip": ("https", "ip_hostname", "explicit_port"),
    "no_length_counts": (
        "url_length", "digits", "digit_ratio", "ats", "percent_signs",
        "question_marks", "equals", "slashes", "keyword_count",
    ),
}


def _column(frame, *names):
    for name in names:
        if name in frame.columns:
            return name
    raise ValueError(f"CSV must contain one of {names}.")


def _validated_label(value, path, row_number):
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path} row {row_number}: label must be exactly 0 or 1.") from exc
    if not np.isfinite(numeric) or numeric not in (0.0, 1.0):
        raise ValueError(f"{path} row {row_number}: label must be exactly 0 or 1.")
    return int(numeric)


def load_records(path, name):
    frame = pd.read_csv(path)
    url_col = _column(frame, "url", "URL", "text")
    label_col = _column(frame, "label", "target")
    forbidden = sorted(FORBIDDEN_FEATURES.intersection(frame.columns) - {"label"})
    source_col = "source" if "source" in frame.columns else None
    labels = [_validated_label(value, path, row_number)
              for row_number, value in frame[label_col].items()]
    frame = frame.copy()
    frame["_validated_label"] = labels
    rows = []
    invalid = 0
    for row_number, row in frame[[url_col, "_validated_label"] + ([source_col] if source_col else [])].iterrows():
        try:
            normalized, features, group = extract_features(row[url_col])
        except (TypeError, ValueError):
            invalid += 1
            continue
        source = str(row[source_col]) if source_col else name
        positive_type = "legitimate" if row["_validated_label"] == 0 else "positive"
        if source.lower() == "urlhaus":
            positive_type = "malware"
        elif source.lower() == "openphish":
            positive_type = "phishing"
        rows.append({
            "row_number": int(row_number), "url": normalized, "group": group,
            "label": row["_validated_label"], "source": source, "positive_type": positive_type,
            **features,
        })
    clean = pd.DataFrame(rows)
    if clean.empty or set(clean.label.unique()) - {0, 1}:
        raise ValueError(f"{path} has no usable binary records.")
    conflicting = clean.groupby("url").label.nunique()
    conflicting_urls = set(conflicting[conflicting > 1].index)
    clean = clean[~clean.url.isin(conflicting_urls)]
    before_duplicates = len(clean)
    clean = clean.drop_duplicates("url").reset_index(drop=True)
    return clean, {
        "name": name, "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "raw_rows": len(frame), "usable_rows": len(clean), "invalid_rows": invalid,
        "conflicting_urls_removed": len(conflicting_urls),
        "duplicate_rows_removed": before_duplicates - len(clean),
        "forbidden_columns_present": forbidden,
    }


def _style(frame):
    host = frame["url"].str.split("://", n=1).str[-1].str.split("/", n=1).str[0]
    return {
        "www_prefix": int(host.str.lower().str.startswith("www.").sum()),
        "nonroot_path": int(frame["path_depth"].gt(0).sum()),
        "query_string": int(frame["query_parameters"].gt(0).sum()),
        "https": int(frame["https"].sum()),
        "ip_hostname": int(frame["ip_hostname"].sum()),
        "median_url_length": float(frame["url_length"].median()),
    }


def _safe_metrics(labels, predictions):
    labels, predictions = np.asarray(labels), np.asarray(predictions)
    result = metrics(labels, predictions)
    tn = int(((labels == 0) & (predictions == 0)).sum())
    fp = int(((labels == 0) & (predictions == 1)).sum())
    fn = int(((labels == 1) & (predictions == 0)).sum())
    tp = int(((labels == 1) & (predictions == 1)).sum())
    result["accuracy"] = float((tn + tp) / len(labels))
    result["precision"] = float(tp / (tp + fp)) if tp + fp and tn + fp else None
    result["recall"] = float(tp / (tp + fn)) if tp + fn else None
    result["f1"] = (float(2 * result["precision"] * result["recall"] /
                            (result["precision"] + result["recall"]))
                    if result["precision"] is not None and result["recall"] is not None
                    and result["precision"] + result["recall"] else None)
    result["false_positive_rate"] = float(fp / (tn + fp)) if tn + fp else None
    result["missed_phishing_rate"] = float(fn / (tp + fn)) if tp + fn else None
    result["confusion_matrix"] = [[tn, fp], [fn, tp]]
    result["single_class_slice"] = len(np.unique(labels)) == 1
    return result


def _bootstrap(frame, predictions, iterations=1000, seed=42):
    rng = np.random.default_rng(seed)
    labels = frame.label.to_numpy()
    groups = frame.group.to_numpy()
    unique_groups = np.unique(groups)
    group_counts = np.zeros((len(unique_groups), 4), dtype=np.int64)
    for index, group in enumerate(unique_groups):
        selected = groups == group
        group_labels = labels[selected]
        group_predictions = predictions[selected]
        group_counts[index] = (
            ((group_labels == 0) & (group_predictions == 0)).sum(),
            ((group_labels == 0) & (group_predictions == 1)).sum(),
            ((group_labels == 1) & (group_predictions == 0)).sum(),
            ((group_labels == 1) & (group_predictions == 1)).sum(),
        )
    values = []
    for _ in range(iterations):
        sampled = rng.integers(0, len(unique_groups), len(unique_groups))
        tn, fp, fn, tp = group_counts[sampled].sum(axis=0)
        total = tn + fp + fn + tp
        precision = tp / (tp + fp) if tp + fp else np.nan
        recall = tp / (tp + fn) if tp + fn else np.nan
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else np.nan
        value = {
            "accuracy": (tn + tp) / total,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": fp / (tn + fp) if tn + fp else np.nan,
        }
        values.append([value[name] if value[name] is not None else np.nan
                       for name in ("accuracy", "precision", "recall", "f1", "false_positive_rate")])
    intervals = np.percentile(values, [2.5, 97.5], axis=0)
    return {name: [float(intervals[0, index]), float(intervals[1, index])]
            for index, name in enumerate(("accuracy", "precision", "recall", "f1", "false_positive_rate"))}


def _score(frame, artifact, ablated=()):
    values = frame[list(FEATURE_NAMES)].copy()
    for feature in ablated:
        values[feature] = 0.0
    probabilities = artifact["model"].predict_proba(values.to_numpy(dtype=float))
    probability = probabilities[:, list(artifact["model"].classes_).index(1)]
    rules = np.array([
        evaluate_rules(dict(zip(FEATURE_NAMES, row)))[0]
        for row in values.to_numpy(dtype=float)
    ])
    score = hybrid_score(probability, rules, artifact.get("model_weight", 0.8))
    predictions = score >= float(artifact["threshold"])
    return probability, score, predictions


def evaluate_frame(frame, artifact, ablated=(), intervals=True):
    probability, score, predictions = _score(frame, artifact, ablated)
    result = _safe_metrics(frame.label.to_numpy(), predictions)
    result.update(
        rows=len(frame),
        threshold=float(artifact["threshold"]),
        raw_model_roc_auc=float(roc_auc_score(frame.label, probability))
        if frame.label.nunique() == 2 else None,
        raw_model_pr_auc=float(average_precision_score(frame.label, probability))
        if frame.label.nunique() == 2 else None,
        system_score_roc_auc=float(roc_auc_score(frame.label, score))
        if frame.label.nunique() == 2 else None,
        system_score_pr_auc=float(average_precision_score(frame.label, score))
        if frame.label.nunique() == 2 else None,
        bootstrap_95=_bootstrap(frame, predictions) if intervals and frame.label.nunique() == 2 else None,
        predicted_positive=int(predictions.sum()),
        abstention_coverage=1.0,
        score_min=float(score.min()),
        score_max=float(score.max()),
    )
    return result


def main(args):
    combined, combined_meta = load_records(args.combined, "combined")
    external, external_meta = load_records(args.external, "kaggle_external")
    ordered_fingerprint = hashlib.sha256(
        "\n".join(f"{url}\t{label}" for url, label in zip(combined.url, combined.label)).encode()
    ).hexdigest()
    split = np.load(args.combined_split)
    required = {"training", "calibration", "validation", "test"}
    if set(split.files) != required:
        raise ValueError(f"Split manifest must contain exactly {sorted(required)}.")
    if args.combined_fingerprint and ordered_fingerprint != args.combined_fingerprint:
        raise ValueError("Combined CSV does not match the supplied split manifest fingerprint.")
    heldout = combined.iloc[split["test"]].copy()
    training_domains = set(combined.group)
    external = external[~external.group.isin(training_domains)].copy()
    if external.empty:
        raise ValueError("No external records remain after registrable-domain filtering.")
    artifact = joblib.load(args.model)
    if artifact.get("features") != list(FEATURE_NAMES):
        raise ValueError("Artifact feature schema does not match detector.FEATURE_NAMES.")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    datasets = {"combined_heldout": heldout, "kaggle_unseen_domains": external}
    report = {
        "methodology": {
            "model": str(args.model), "threshold_frozen": float(artifact["threshold"]),
            "positive_class": "label=1; Kaggle URLhaus is malware, not phishing",
            "forbidden_features": sorted(FORBIDDEN_FEATURES),
            "no_threshold_or_model_selection_on_evaluation_data": True,
            "confidence_interval": "percentile bootstrap, 1000 resamples, seed 42",
            "confidence_interval_resampling": "registrable-domain clusters, not individual URLs",
            "combined_evaluation_cohort": "held-out test indices from combined_split",
            "external_evaluation_cohort": "Kaggle records whose registrable domains are absent from all combined records",
            "combined_ordered_url_label_sha256": ordered_fingerprint,
            "combined_split": str(args.combined_split),
            "final_test_status": "not established: supplied data have influenced development",
        },
        "datasets": [combined_meta, external_meta],
        "results": {},
        "feature_ablation": {},
    }
    for dataset_name, frame in datasets.items():
        report["results"][dataset_name] = {
            "overall": evaluate_frame(frame, artifact, intervals=True),
            "style_profile": _style(frame),
            "slices": {},
        }
        for value, group in frame.groupby("source", dropna=False):
            report["results"][dataset_name]["slices"][f"source:{value}"] = evaluate_frame(
                group, artifact, intervals=False)
        for value, group in frame.groupby("positive_type", dropna=False):
            report["results"][dataset_name]["slices"][f"type:{value}"] = evaluate_frame(
                group, artifact, intervals=False)
    for name, features in ABLATIONS.items():
        report["feature_ablation"][name] = {
            "removed_features": list(features),
            "combined_heldout": evaluate_frame(heldout, artifact, features, intervals=False),
            "kaggle_unseen_domains": evaluate_frame(external, artifact, features, intervals=False),
            "interpretation": "frozen-model sensitivity; retraining ablations remain required for causal importance",
        }
    (output / "audit_report.json").write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    pd.DataFrame([
        {"dataset": dataset_name, "slice": "overall", **values["overall"]}
        for dataset_name, values in report["results"].items()
    ]).to_csv(output / "audit_summary.csv", index=False)
    print(json.dumps({"output": str(output), "datasets": report["datasets"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--combined", type=Path, required=True)
    parser.add_argument("--external", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--combined-split", type=Path, required=True)
    parser.add_argument("--combined-fingerprint", default="")
    main(parser.parse_args())
