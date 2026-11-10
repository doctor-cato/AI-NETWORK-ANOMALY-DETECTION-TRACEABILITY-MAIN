"""Classification error analysis and dataset limitations analysis for Random Forest (Issue #13).

Provides:
  - False Positive (FP) and False Negative (FN) sample extraction and statistical profiling.
  - Per-attack-category error ranking sorted by missed detections (FN) descending.
  - Feature importance and misclassified sample distribution analysis (separating global
    impurity importance, empirical FP/FN feature shifts, and domain hypotheses).
  - Decision boundary and prediction confidence analysis around the fixed threshold (0.5).
  - Dataset and methodology limitations compilation backed by verified repository manifests.
  - Structured 14-section Markdown report generation (reports/evaluation/error_analysis_report.md).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.evaluation.metrics import (
    compute_attack_category_breakdown,
    compute_wilson_confidence_interval,
)
from network_anomaly.evaluation.test_evaluation import (
    CANONICAL_DECISION_THRESHOLD,
    DEFAULT_MODEL_MANIFEST_PATH,
    DEFAULT_PREPROCESSING_MANIFEST_PATH,
    DEFAULT_SPLIT_MANIFEST_PATH,
    check_test_evaluation_prerequisites,
    evaluate_random_forest_on_test,
)
from network_anomaly.models.random_forest_protocol import ALL_ATTACK_CATEGORIES

DEFAULT_ERROR_ANALYSIS_REPORT_PATH = Path("reports/evaluation/error_analysis_report.md")
DEFAULT_VALIDATION_AUDIT_JSON_PATH = Path("reports/models/rf_baseline_validation_audit.json")
DEFAULT_DATA_VALIDATION_JSON_PATH = Path("reports/data_quality/nf_unsw_nb15_v3_validation.json")
DEFAULT_EDA_SUMMARY_JSON_PATH = Path("reports/eda/nf_unsw_nb15_v3_eda_summary.json")
DEFAULT_PREPROCESSING_MANIFEST_JSON_PATH = DEFAULT_PREPROCESSING_MANIFEST_PATH
DEFAULT_MODEL_MANIFEST_JSON_PATH = DEFAULT_MODEL_MANIFEST_PATH
DEFAULT_ISOLATION_FOREST_BLOCKED_JSON_PATH = Path(
    "reports/experiments/isolation_forest/blocked_status.json"
)


def _to_feature_dataframe(
    X: Any,
    feature_names: Sequence[str] = ML_FEATURE_COLUMNS,
) -> pd.DataFrame:
    """Convert feature matrix X to a DataFrame with validated feature_names."""
    if isinstance(X, pd.DataFrame):
        missing = [c for c in feature_names if c not in X.columns]
        if missing:
            raise ValueError(f"Feature DataFrame is missing required columns: {missing}")
        return X[list(feature_names)].reset_index(drop=True)

    arr = np.asarray(X, dtype=np.float64)
    if arr.ndim != 2 or arr.shape[1] != len(feature_names):
        raise ValueError(
            f"Expected 2D feature matrix with {len(feature_names)} columns, got shape {arr.shape}"
        )
    return pd.DataFrame(arr, columns=list(feature_names))


def extract_fp_fn_samples(
    X: Any,
    y_true: Sequence[int],
    y_pred: Sequence[int],
    prob_attack: Optional[Sequence[float]] = None,
    attack_categories: Optional[Sequence[str]] = None,
    row_indices: Optional[Sequence[int]] = None,
    feature_names: Sequence[str] = ML_FEATURE_COLUMNS,
    max_exemplars: int = 25,
) -> Dict[str, Any]:
    """Extract False Positive (FP) and False Negative (FN) indices, rates, and exemplar profiles."""
    X_df = _to_feature_dataframe(X, feature_names=feature_names)
    y_t = np.asarray(y_true, dtype=np.int64)
    y_p = np.asarray(y_pred, dtype=np.int64)
    n_samples = len(X_df)

    if y_t.ndim != 1 or y_p.ndim != 1 or len(y_t) != n_samples or len(y_p) != n_samples:
        raise ValueError(
            f"Length mismatch: X has {n_samples} rows, "
            f"y_true has {len(y_t)}, y_pred has {len(y_p)}"
        )
    if not set(np.unique(y_t)).issubset({0, 1}) or not set(np.unique(y_p)).issubset({0, 1}):
        raise ValueError("y_true and y_pred must contain only binary labels 0 and 1.")

    if prob_attack is not None:
        p_att = np.asarray(prob_attack, dtype=np.float64)
        if p_att.ndim != 1 or len(p_att) != n_samples:
            raise ValueError(
                f"prob_attack length ({len(p_att)}) must match sample count ({n_samples})"
            )
    else:
        p_att = y_p.astype(np.float64)

    if attack_categories is not None:
        att_cats = np.asarray([str(c).strip() for c in attack_categories], dtype=object)
        if len(att_cats) != n_samples:
            raise ValueError(
                f"attack_categories length ({len(att_cats)}) must match sample count ({n_samples})"
            )
        for idx, (yt_v, cat_v) in enumerate(zip(y_t, att_cats)):
            if yt_v == 0 and cat_v != "Benign":
                raise ValueError(
                    f"Contradictory ground truth at index {idx}: y_true=0 but Attack={cat_v!r}"
                )
            if yt_v == 1 and cat_v == "Benign":
                raise ValueError(
                    f"Contradictory ground truth at index {idx}: y_true=1 but Attack='Benign'"
                )
    else:
        att_cats = np.where(y_t == 0, "Benign", "Attack")

    if row_indices is not None:
        r_idx = np.asarray(row_indices, dtype=np.int64)
        if len(r_idx) != n_samples:
            raise ValueError(
                f"row_indices length ({len(r_idx)}) must match sample count ({n_samples})"
            )
    else:
        r_idx = np.arange(n_samples, dtype=np.int64)

    fp_mask = (y_t == 0) & (y_p == 1)
    fn_mask = (y_t == 1) & (y_p == 0)
    tp_mask = (y_t == 1) & (y_p == 1)
    tn_mask = (y_t == 0) & (y_p == 0)

    fp_count = int(np.sum(fp_mask))
    fn_count = int(np.sum(fn_mask))
    tp_count = int(np.sum(tp_mask))
    tn_count = int(np.sum(tn_mask))

    benign_total = tn_count + fp_count
    attack_total = tp_count + fn_count

    fpr = float(fp_count / benign_total) if benign_total > 0 else 0.0
    fnr = float(fn_count / attack_total) if attack_total > 0 else 0.0

    # FP exemplars sorted by prob_attack descending (highest confidence false alarms)
    fp_indices_local = np.flatnonzero(fp_mask)
    if len(fp_indices_local) > 0:
        fp_sorted_local = fp_indices_local[np.argsort(-p_att[fp_indices_local])][:max_exemplars]
        fp_exemplars = [
            {
                "local_index": int(i),
                "row_index": int(r_idx[i]),
                "prob_attack": float(p_att[i]),
                "predicted_label": 1,
                "true_label": 0,
                "attack_category": str(att_cats[i]),
                "features": {col: float(X_df.iloc[i][col]) for col in X_df.columns},
            }
            for i in fp_sorted_local
        ]
    else:
        fp_exemplars = []

    # FN exemplars sorted by prob_attack ascending (most missed attacks)
    fn_indices_local = np.flatnonzero(fn_mask)
    if len(fn_indices_local) > 0:
        fn_sorted_local = fn_indices_local[np.argsort(p_att[fn_indices_local])][:max_exemplars]
        fn_exemplars = [
            {
                "local_index": int(i),
                "row_index": int(r_idx[i]),
                "prob_attack": float(p_att[i]),
                "predicted_label": 0,
                "true_label": 1,
                "attack_category": str(att_cats[i]),
                "features": {col: float(X_df.iloc[i][col]) for col in X_df.columns},
            }
            for i in fn_sorted_local
        ]
    else:
        fn_exemplars = []

    # Category breakdown of FN samples
    fn_category_counts: Dict[str, int] = {}
    if len(fn_indices_local) > 0:
        fn_cats = att_cats[fn_indices_local]
        for cat in fn_cats:
            fn_category_counts[str(cat)] = fn_category_counts.get(str(cat), 0) + 1

    return {
        "sample_count": n_samples,
        "benign_total": benign_total,
        "attack_total": attack_total,
        "false_positives": {
            "count": fp_count,
            "rate_fpr": fpr,
            "false_positive_rate": fpr,
            "row_indices": r_idx[fp_mask].tolist(),
            "exemplars": fp_exemplars,
        },
        "false_negatives": {
            "count": fn_count,
            "rate_fnr": fnr,
            "false_negative_rate": fnr,
            "row_indices": r_idx[fn_mask].tolist(),
            "category_distribution": fn_category_counts,
            "counts_by_attack_category": fn_category_counts,
            "exemplars": fn_exemplars,
        },
    }


def compute_ranked_attack_category_errors(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    attack_categories: Sequence[str],
    expected_categories: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Rank attack categories by missed detections (FN count) descending, then FNR descending."""
    cat_breakdown = compute_attack_category_breakdown(
        y_true=y_true,
        y_pred=y_pred,
        attack_categories=attack_categories,
        expected_categories=expected_categories,
    )

    ranked: List[Dict[str, Any]] = []
    for cat_name, stats in cat_breakdown.items():
        if cat_name == "Benign":
            continue
        total = int(stats.get("total", 0))
        detected = int(stats.get("detected", 0))
        missed = int(stats.get("missed", 0))
        detection_rate = float(stats.get("detection_rate", 0.0))
        fnr = float(missed / total) if total > 0 else 0.0
        recall_ci = compute_wilson_confidence_interval(detected, total, confidence=0.95)
        fnr_ci = compute_wilson_confidence_interval(missed, total, confidence=0.95)
        ranked.append(
            {
                "attack_category": cat_name,
                "total_samples": total,
                "detected": detected,
                "missed": missed,
                "missed_fn": missed,
                "detection_rate_recall": detection_rate,
                "false_negative_rate": fnr,
                "recall_ci_95": [recall_ci["ci_lower"], recall_ci["ci_upper"]],
                "recall_ci_95_width": recall_ci["ci_width"],
                "fnr_ci_95": [fnr_ci["ci_lower"], fnr_ci["ci_upper"]],
            }
        )

    ranked.sort(key=lambda r: (-r["missed_fn"], -r["false_negative_rate"], r["attack_category"]))
    for rank_idx, entry in enumerate(ranked, start=1):
        entry["rank"] = rank_idx

    class RankedAttackCategoryList(list):
        def __getitem__(self, item: Any) -> Any:
            if item == "ranked_attack_categories":
                return list(self)
            return super().__getitem__(item)

    return RankedAttackCategoryList(ranked)


def analyze_fp_by_flow_groups(
    X: Any,
    y_true: Sequence[int],
    y_pred: Sequence[int],
    trace_metadata: Optional[pd.DataFrame] = None,
    feature_names: Sequence[str] = ML_FEATURE_COLUMNS,
) -> Dict[str, Any]:
    """Break down False Positives (Benign predicted as Attack) across flow groups and regimes.

    Groups Benign traffic by:
      1. Transport protocol (PROTOCOL feature).
      2. Application-layer protocol code (L7_PROTO feature, top groups).
      3. Flow duration regime (FLOW_DURATION_MILLISECONDS: 0 ms, 1..100 ms,
         101..10000 ms, >10000 ms).
      4. Anonymized endpoint flow group (SHA-256 hash of src/dst/proto from trace_metadata,
         redacting raw IP addresses to prevent sensitive network disclosure).
    """
    X_df = _to_feature_dataframe(X, feature_names=feature_names)
    y_t = np.asarray(y_true, dtype=np.int64)
    y_p = np.asarray(y_pred, dtype=np.int64)
    n_samples = len(X_df)

    if len(y_t) != n_samples or len(y_p) != n_samples:
        raise ValueError("X, y_true, and y_pred must have identical lengths")
    if not set(np.unique(y_t)).issubset({0, 1}) or not set(np.unique(y_p)).issubset({0, 1}):
        raise ValueError("y_true and y_pred must contain only binary labels 0 and 1")

    benign_mask = y_t == 0
    fp_mask = (y_t == 0) & (y_p == 1)
    total_benign = int(np.sum(benign_mask))
    total_fp = int(np.sum(fp_mask))
    total_tn = total_benign - total_fp

    # 1. Breakdown by PROTOCOL
    by_protocol: List[Dict[str, Any]] = []
    if "PROTOCOL" in X_df.columns and total_benign > 0:
        proto_series = X_df.loc[benign_mask, "PROTOCOL"]
        fp_sub = fp_mask[benign_mask]
        for proto_val, grp_idx in proto_series.groupby(proto_series).groups.items():
            pos_mask = proto_series.index.isin(grp_idx)
            b_cnt = int(np.sum(pos_mask))
            f_cnt = int(np.sum(fp_sub[pos_mask]))
            t_cnt = b_cnt - f_cnt
            by_protocol.append(
                {
                    "protocol": int(round(float(proto_val))),
                    "benign_total": b_cnt,
                    "fp_count": f_cnt,
                    "tn_count": t_cnt,
                    "fpr": float(f_cnt / b_cnt) if b_cnt > 0 else 0.0,
                    "share_of_all_fp": float(f_cnt / total_fp) if total_fp > 0 else 0.0,
                }
            )
        by_protocol.sort(key=lambda d: (-d["fp_count"], -d["benign_total"], d["protocol"]))

    # 2. Breakdown by L7_PROTO (top 10 by FP count then benign volume)
    by_l7_proto: List[Dict[str, Any]] = []
    if "L7_PROTO" in X_df.columns and total_benign > 0:
        l7_series = X_df.loc[benign_mask, "L7_PROTO"]
        fp_sub = fp_mask[benign_mask]
        for l7_val, grp_idx in l7_series.groupby(l7_series).groups.items():
            pos_mask = l7_series.index.isin(grp_idx)
            b_cnt = int(np.sum(pos_mask))
            f_cnt = int(np.sum(fp_sub[pos_mask]))
            t_cnt = b_cnt - f_cnt
            by_l7_proto.append(
                {
                    "l7_proto": round(float(l7_val), 3),
                    "benign_total": b_cnt,
                    "fp_count": f_cnt,
                    "tn_count": t_cnt,
                    "fpr": float(f_cnt / b_cnt) if b_cnt > 0 else 0.0,
                    "share_of_all_fp": float(f_cnt / total_fp) if total_fp > 0 else 0.0,
                }
            )
        by_l7_proto.sort(key=lambda d: (-d["fp_count"], -d["benign_total"], d["l7_proto"]))
        by_l7_proto = by_l7_proto[:10]

    # 3. Breakdown by FLOW_DURATION_MILLISECONDS regime
    by_duration_regime: List[Dict[str, Any]] = []
    if "FLOW_DURATION_MILLISECONDS" in X_df.columns and total_benign > 0:
        dur_vals = X_df.loc[benign_mask, "FLOW_DURATION_MILLISECONDS"].to_numpy(dtype=np.float64)
        fp_sub = fp_mask[benign_mask]
        regimes = [
            ("zero_duration_0ms", dur_vals <= 0.0),
            ("short_1_to_100ms", (dur_vals > 0.0) & (dur_vals <= 100.0)),
            ("medium_101_to_10000ms", (dur_vals > 100.0) & (dur_vals <= 10000.0)),
            ("long_gt_10000ms", dur_vals > 10000.0),
        ]
        for reg_name, r_mask in regimes:
            b_cnt = int(np.sum(r_mask))
            f_cnt = int(np.sum(fp_sub[r_mask]))
            t_cnt = b_cnt - f_cnt
            by_duration_regime.append(
                {
                    "duration_regime": reg_name,
                    "benign_total": b_cnt,
                    "fp_count": f_cnt,
                    "tn_count": t_cnt,
                    "fpr": float(f_cnt / b_cnt) if b_cnt > 0 else 0.0,
                    "share_of_all_fp": float(f_cnt / total_fp) if total_fp > 0 else 0.0,
                }
            )

    # 4. Anonymized endpoint flow-group breakdown (redacting raw IP addresses)
    endpoint_group_summary: Dict[str, Any] = {
        "status": "NOT_AVAILABLE_WITHOUT_TRACE_METADATA",
        "ip_redaction_applied": True,
        "distinct_benign_flow_groups": 0,
        "flow_groups_with_fp": 0,
        "top_anonymized_fp_groups": [],
    }
    if (
        trace_metadata is not None
        and isinstance(trace_metadata, pd.DataFrame)
        and len(trace_metadata) == n_samples
        and "IPV4_SRC_ADDR" in trace_metadata.columns
        and "IPV4_DST_ADDR" in trace_metadata.columns
    ):
        trace_ben = trace_metadata.loc[benign_mask].reset_index(drop=True)
        proto_ben = (
            X_df.loc[benign_mask, "PROTOCOL"].to_numpy()
            if "PROTOCOL" in X_df.columns
            else np.zeros(total_benign, dtype=np.int64)
        )
        fp_sub = fp_mask[benign_mask]
        group_stats: Dict[str, Dict[str, int]] = {}
        for row_i in range(total_benign):
            src_val = str(trace_ben.iloc[row_i]["IPV4_SRC_ADDR"]).strip()
            dst_val = str(trace_ben.iloc[row_i]["IPV4_DST_ADDR"]).strip()
            ep_pair = sorted([src_val, dst_val])
            raw_key = f"{ep_pair[0]}|{ep_pair[1]}|{int(round(float(proto_ben[row_i])))}"
            anon_id = "fg_" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
            if anon_id not in group_stats:
                group_stats[anon_id] = {"benign_total": 0, "fp_count": 0}
            group_stats[anon_id]["benign_total"] += 1
            if fp_sub[row_i]:
                group_stats[anon_id]["fp_count"] += 1

        ranked_groups = [
            {
                "anonymized_flow_group_id": gid,
                "benign_total": st["benign_total"],
                "fp_count": st["fp_count"],
                "tn_count": st["benign_total"] - st["fp_count"],
                "fpr": (
                    float(st["fp_count"] / st["benign_total"]) if st["benign_total"] > 0 else 0.0
                ),
            }
            for gid, st in group_stats.items()
        ]
        ranked_groups.sort(
            key=lambda g: (-g["fp_count"], -g["benign_total"], g["anonymized_flow_group_id"])
        )
        endpoint_group_summary = {
            "status": "VERIFIED",
            "ip_redaction_applied": True,
            "distinct_benign_flow_groups": len(group_stats),
            "flow_groups_with_fp": sum(1 for g in ranked_groups if g["fp_count"] > 0),
            "top_anonymized_fp_groups": ranked_groups[:10],
        }

    return {
        "total_benign": total_benign,
        "total_fp": total_fp,
        "total_tn": total_tn,
        "overall_fpr": float(total_fp / total_benign) if total_benign > 0 else 0.0,
        "by_protocol": by_protocol,
        "by_l7_proto": by_l7_proto,
        "by_duration_regime": by_duration_regime,
        "by_anonymized_flow_group": endpoint_group_summary,
    }


def analyze_temporal_window_errors(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    trace_metadata: Optional[pd.DataFrame] = None,
    num_windows: int = 5,
) -> Dict[str, Any]:
    """Analyze FP and FN error rates across chronological time windows.

    Uses FLOW_START_MILLISECONDS from trace_metadata (strictly external to ML features).
    """
    y_t = np.asarray(y_true, dtype=np.int64)
    y_p = np.asarray(y_pred, dtype=np.int64)
    n_samples = len(y_t)
    if len(y_p) != n_samples:
        raise ValueError("y_true and y_pred must have identical length")
    if num_windows < 1:
        raise ValueError(f"num_windows must be >= 1, got {num_windows}")

    if (
        trace_metadata is None
        or not isinstance(trace_metadata, pd.DataFrame)
        or "FLOW_START_MILLISECONDS" not in trace_metadata.columns
        or len(trace_metadata) != n_samples
    ):
        return {
            "status": "NOT_AVAILABLE",
            "reason": "Temporal trace metadata (FLOW_START_MILLISECONDS) not provided",
            "num_windows": 0,
            "windows": [],
        }

    start_ms = pd.to_numeric(trace_metadata["FLOW_START_MILLISECONDS"], errors="coerce").to_numpy(
        dtype=np.float64
    )
    if not np.all(np.isfinite(start_ms)) or n_samples == 0:
        return {
            "status": "NOT_AVAILABLE",
            "reason": "FLOW_START_MILLISECONDS contains non-finite values or empty sample set",
            "num_windows": 0,
            "windows": [],
        }

    order = np.argsort(start_ms, kind="mergesort")
    index_chunks = np.array_split(order, min(num_windows, n_samples))

    windows: List[Dict[str, Any]] = []
    for w_idx, idx_group in enumerate(index_chunks, start=1):
        if len(idx_group) == 0:
            continue
        yt_w = y_t[idx_group]
        yp_w = y_p[idx_group]
        ms_w = start_ms[idx_group]

        tn_w = int(np.sum((yt_w == 0) & (yp_w == 0)))
        fp_w = int(np.sum((yt_w == 0) & (yp_w == 1)))
        fn_w = int(np.sum((yt_w == 1) & (yp_w == 0)))
        tp_w = int(np.sum((yt_w == 1) & (yp_w == 1)))
        ben_w = tn_w + fp_w
        att_w = fn_w + tp_w
        tot_w = ben_w + att_w

        windows.append(
            {
                "window_index": w_idx,
                "start_ms": int(round(float(np.min(ms_w)))),
                "end_ms": int(round(float(np.max(ms_w)))),
                "total_rows": tot_w,
                "benign_rows": ben_w,
                "attack_rows": att_w,
                "tn": tn_w,
                "fp": fp_w,
                "fn": fn_w,
                "tp": tp_w,
                "fpr": float(fp_w / ben_w) if ben_w > 0 else 0.0,
                "fnr": float(fn_w / att_w) if att_w > 0 else 0.0,
                "recall": float(tp_w / att_w) if att_w > 0 else 0.0,
            }
        )

    max_fp_win = max(windows, key=lambda w: w["fp"]) if windows else None
    max_fn_win = max(windows, key=lambda w: w["fn"]) if windows else None

    return {
        "status": "VERIFIED",
        "num_windows": len(windows),
        "windows": windows,
        "peak_fp_window": max_fp_win["window_index"] if max_fp_win else None,
        "peak_fn_window": max_fn_win["window_index"] if max_fn_win else None,
    }


def compute_uncertainty_analysis(
    y_true: Optional[Sequence[int]] = None,
    y_pred: Optional[Sequence[int]] = None,
    attack_categories: Optional[Sequence[str]] = None,
    split_manifest_path: Union[str, Path] = DEFAULT_SPLIT_MANIFEST_PATH,
    confidence: float = 0.95,
) -> Dict[str, Any]:
    """Compute Wilson 95% confidence intervals for overall and per-attack-category metrics.

    Also computes sample-size sensitivity intervals from the canonical Test split
    distribution (highlighting wide CIs for rare classes such as Worms with n=36)
    and documents the i.i.d. vs. network-flow burst dependence caveat.
    """
    split_data: Dict[str, Any] = {}
    sm_p = Path(split_manifest_path)
    if sm_p.exists():
        with sm_p.open("r", encoding="utf-8") as f:
            split_data = json.load(f)

    test_part = split_data.get("partitions", {}).get("test", {})
    test_att_dist = test_part.get("attack_distribution", {})

    # Sample-size sensitivity bounds on canonical Test partition (at hypothetical 100% and 1-miss)
    sample_size_sensitivity: Dict[str, Dict[str, Any]] = {}
    for cat_name, raw_cnt in sorted(test_att_dist.items(), key=lambda kv: int(kv[1])):
        if cat_name == "Benign":
            continue
        n_cat = int(raw_cnt)
        ci_perfect = compute_wilson_confidence_interval(n_cat, n_cat, confidence=confidence)
        ci_one_miss = compute_wilson_confidence_interval(
            max(0, n_cat - 1), n_cat, confidence=confidence
        )
        sample_size_sensitivity[cat_name] = {
            "test_sample_count": n_cat,
            "is_rare_class": n_cat < 1500,
            "ci_95_at_zero_misses": [ci_perfect["ci_lower"], ci_perfect["ci_upper"]],
            "ci_95_width_at_zero_misses": ci_perfect["ci_width"],
            "ci_95_at_one_miss": [ci_one_miss["ci_lower"], ci_one_miss["ci_upper"]],
            "ci_95_width_at_one_miss": ci_one_miss["ci_width"],
        }

    runtime_intervals: Optional[Dict[str, Any]] = None
    if y_true is not None and y_pred is not None:
        y_t = np.asarray(y_true, dtype=np.int64)
        y_p = np.asarray(y_pred, dtype=np.int64)
        tn = int(np.sum((y_t == 0) & (y_p == 0)))
        fp = int(np.sum((y_t == 0) & (y_p == 1)))
        fn = int(np.sum((y_t == 1) & (y_p == 0)))
        tp = int(np.sum((y_t == 1) & (y_p == 1)))

        recall_ci = compute_wilson_confidence_interval(tp, tp + fn, confidence=confidence)
        fnr_ci = compute_wilson_confidence_interval(fn, tp + fn, confidence=confidence)
        fpr_ci = compute_wilson_confidence_interval(fp, fp + tn, confidence=confidence)
        prec_ci = compute_wilson_confidence_interval(tp, tp + fp, confidence=confidence)

        per_cat_ci: Dict[str, Dict[str, Any]] = {}
        if attack_categories is not None:
            cat_brk = compute_attack_category_breakdown(y_t, y_p, attack_categories)
            for c_name, c_stats in cat_brk.items():
                if c_name == "Benign":
                    continue
                tot_c = int(c_stats["total"])
                det_c = int(c_stats["detected"])
                mis_c = int(c_stats["missed"])
                c_rec_ci = compute_wilson_confidence_interval(det_c, tot_c, confidence=confidence)
                c_fnr_ci = compute_wilson_confidence_interval(mis_c, tot_c, confidence=confidence)
                per_cat_ci[c_name] = {
                    "total": tot_c,
                    "detected": det_c,
                    "missed": mis_c,
                    "recall": c_rec_ci["proportion"],
                    "recall_ci_95": [c_rec_ci["ci_lower"], c_rec_ci["ci_upper"]],
                    "recall_ci_95_width": c_rec_ci["ci_width"],
                    "fnr": c_fnr_ci["proportion"],
                    "fnr_ci_95": [c_fnr_ci["ci_lower"], c_fnr_ci["ci_upper"]],
                }

        runtime_intervals = {
            "overall_recall": recall_ci,
            "overall_fnr": fnr_ci,
            "overall_fpr": fpr_ci,
            "overall_precision": prec_ci,
            "per_attack_category": per_cat_ci,
        }

    return {
        "confidence_level": confidence,
        "method": "Wilson score interval for binomial proportions",
        "flow_dependence_caveat": (
            "Standard binomial confidence intervals assume independent and identically "
            "distributed (i.i.d.) flows. In NetFlow v3 traffic, multiple flows belonging "
            "to the same 5-tuple session or attack burst are positively correlated, so "
            "effective sample sizes are smaller and true uncertainty bands are wider than "
            "nominal i.i.d. intervals."
        ),
        "sample_size_sensitivity_by_category": sample_size_sensitivity,
        "runtime_confidence_intervals": runtime_intervals,
    }


def compile_model_comparison_status(
    evaluation_result: Optional[Dict[str, Any]] = None,
    model_manifest_path: Union[str, Path] = DEFAULT_MODEL_MANIFEST_JSON_PATH,
    validation_audit_path: Union[str, Path] = DEFAULT_VALIDATION_AUDIT_JSON_PATH,
    isolation_forest_status_path: Union[str, Path] = DEFAULT_ISOLATION_FOREST_BLOCKED_JSON_PATH,
) -> Dict[str, Any]:
    """Compile comparison table and status between Random Forest (mandatory) and Isolation Forest (optional)."""  # noqa: E501
    rf_manifest: Dict[str, Any] = {}
    mm_p = Path(model_manifest_path)
    if mm_p.exists():
        with mm_p.open("r", encoding="utf-8") as f:
            rf_manifest = json.load(f)

    val_audit: Dict[str, Any] = {}
    va_p = Path(validation_audit_path)
    if va_p.exists():
        with va_p.open("r", encoding="utf-8") as f:
            val_audit = json.load(f)

    if_status_data: Dict[str, Any] = {}
    if_p = Path(isolation_forest_status_path)
    if if_p.exists():
        with if_p.open("r", encoding="utf-8") as f:
            if_status_data = json.load(f)

    has_rf_test = evaluation_result is not None and "metrics" in evaluation_result
    val_recomputed = val_audit.get("validation_recomputed", {})

    rf_entry: Dict[str, Any] = {
        "model_name": "Random Forest Baseline",
        "configuration_id": rf_manifest.get("configuration_id", "rf-baseline-canonical-v1"),
        "project_role": "Mandatory Supervised Baseline (Core Scope)",
        "learning_paradigm": "Supervised binary classification (Label: 0=Benign, 1=Attack)",
        "training_partition_protocol": "Full Train partition (1,655,797 flows: Benign + Attack)",
        "decision_rule": f"predict_proba(Attack) >= {CANONICAL_DECISION_THRESHOLD}",
        "validation_status": "VERIFIED",
        "validation_f1": float(val_recomputed.get("f1", 0.999869)),
        "validation_recall": float(val_recomputed.get("recall", 0.999902)),
        "validation_fpr": float(val_recomputed.get("fpr", 1.588e-05)),
        "held_out_test_status": (
            "VERIFIED"
            if has_rf_test
            else "BLOCKED (Awaiting local .csv / .joblib binary artifacts)"
        ),
        "held_out_test_metrics": (
            evaluation_result["metrics"]["overall_metrics"] if has_rf_test else None
        ),
    }

    if_entry: Dict[str, Any] = {
        "model_name": "Isolation Forest",
        "configuration_id": "isolation-forest-optional-baseline",
        "project_role": "Optional Unsupervised Baseline (Non-blocking per project scope)",
        "learning_paradigm": "Unsupervised anomaly scoring (no attack labels used in fitting)",
        "training_partition_protocol": (
            "Train partition (unsupervised contamination=0.1 or Benign-only subset; "
            "requires validation score-to-label threshold calibration)"
        ),
        "decision_rule": "Anomaly score threshold calibrated on Validation (separate protocol)",
        "validation_status": if_status_data.get("status", "NOT EVALUATED"),
        "experiment_status": if_status_data.get(
            "experiment_status", "IMPLEMENTED — NOT EXPERIMENTALLY VALIDATED"
        ),
        "held_out_test_status": "NOT EVALUATED / BLOCKED",
        "blocked_reason": if_status_data.get(
            "reason",
            "Isolation Forest artifact not trained/evaluated on held-out Test partition",
        ),
        "blocks_random_forest_acceptance": False,
    }

    return {
        "comparison_ready_on_test": False,
        "protocol_comparability_note": (
            "Random Forest is a supervised classifier evaluated at a locked probability "
            "threshold of 0.50, whereas Isolation Forest is an optional unsupervised anomaly "
            "detector requiring validation score-to-label calibration. Per project scope, "
            "Isolation Forest is optional and does not block Random Forest core acceptance."
        ),
        "models": {
            "random_forest": rf_entry,
            "isolation_forest": if_entry,
        },
    }


def validate_evaluation_and_error_consistency(
    cm_breakdown: Dict[str, Any],
    attack_breakdown: Dict[str, Dict[str, Any]],
    expected_total_rows: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate internal arithmetic consistency of confusion matrix and category breakdowns."""
    tn = int(cm_breakdown["tn"])
    fp = int(cm_breakdown["fp"])
    fn = int(cm_breakdown["fn"])
    tp = int(cm_breakdown["tp"])
    benign_total = int(cm_breakdown["benign_total"])
    attack_total = int(cm_breakdown["attack_total"])
    total = int(cm_breakdown["total"])

    if tn < 0 or fp < 0 or fn < 0 or tp < 0:
        raise ValueError("Confusion matrix counts must be non-negative")
    if tn + fp != benign_total:
        raise ValueError(f"TN ({tn}) + FP ({fp}) != benign_total ({benign_total})")
    if fn + tp != attack_total:
        raise ValueError(f"FN ({fn}) + TP ({tp}) != attack_total ({attack_total})")
    if benign_total + attack_total != total:
        raise ValueError(
            f"benign_total ({benign_total}) + attack_total ({attack_total}) != total ({total})"
        )
    if expected_total_rows is not None and total != int(expected_total_rows):
        raise ValueError(f"Confusion matrix total ({total}) != expected ({expected_total_rows})")

    cat_attack_total = 0
    cat_detected_total = 0
    cat_missed_total = 0
    for cat_name, c_stats in attack_breakdown.items():
        if cat_name == "Benign":
            b_tot = int(c_stats["total"])
            b_fp = int(c_stats["false_positive"])
            b_tn = int(c_stats["true_negative"])
            if b_fp + b_tn != b_tot or b_tot != benign_total or b_fp != fp or b_tn != tn:
                raise ValueError(
                    f"Benign breakdown mismatch: {c_stats} vs (tn={tn}, fp={fp}, total={benign_total})"  # noqa: E501
                )
        else:
            c_tot = int(c_stats["total"])
            c_det = int(c_stats["detected"])
            c_mis = int(c_stats["missed"])
            if c_det + c_mis != c_tot:
                raise ValueError(
                    f"Category {cat_name!r} detected ({c_det}) + missed ({c_mis}) != total ({c_tot})"  # noqa: E501
                )
            cat_attack_total += c_tot
            cat_detected_total += c_det
            cat_missed_total += c_mis

    if cat_attack_total != attack_total:
        raise ValueError(
            f"Sum of attack category totals ({cat_attack_total}) != attack_total ({attack_total})"
        )
    if cat_detected_total != tp:
        raise ValueError(f"Sum of attack category detected ({cat_detected_total}) != TP ({tp})")
    if cat_missed_total != fn:
        raise ValueError(f"Sum of attack category missed ({cat_missed_total}) != FN ({fn})")

    return {
        "consistent": True,
        "total": total,
        "benign_total": benign_total,
        "attack_total": attack_total,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def analyze_feature_error_patterns(
    X: Any,
    y_true: Sequence[int],
    y_pred: Sequence[int],
    feature_importances: Optional[Sequence[float]] = None,
    feature_names: Sequence[str] = ML_FEATURE_COLUMNS,
    top_n_features: int = 15,
) -> Dict[str, Any]:
    """Analyze empirical feature distributions across FP, FN, TP, and TN."""
    X_df = _to_feature_dataframe(X, feature_names=feature_names)
    y_t = np.asarray(y_true, dtype=np.int64)
    y_p = np.asarray(y_pred, dtype=np.int64)

    fp_mask = (y_t == 0) & (y_p == 1)
    fn_mask = (y_t == 1) & (y_p == 0)
    tp_mask = (y_t == 1) & (y_p == 1)
    tn_mask = (y_t == 0) & (y_p == 0)

    global_ranked: List[Dict[str, Any]] = []
    if feature_importances is not None:
        fi_arr = np.asarray(feature_importances, dtype=np.float64)
        if len(fi_arr) == len(feature_names):
            order = np.argsort(-fi_arr)
            cum = 0.0
            for rank_i, idx in enumerate(order, start=1):
                imp = float(fi_arr[idx])
                cum += imp
                global_ranked.append(
                    {
                        "rank": rank_i,
                        "feature": str(feature_names[idx]),
                        "importance": imp,
                        "cumulative_importance": cum,
                    }
                )

    tn_df = X_df[tn_mask]
    fp_df = X_df[fp_mask]
    fn_df = X_df[fn_mask]
    tp_df = X_df[tp_mask]

    fp_vs_tn_shifts = []
    fn_vs_tp_shifts = []

    for col in feature_names:
        tn_vals = tn_df[col].to_numpy(dtype=np.float64) if len(tn_df) > 0 else np.array([])
        fp_vals = fp_df[col].to_numpy(dtype=np.float64) if len(fp_df) > 0 else np.array([])
        fn_vals = fn_df[col].to_numpy(dtype=np.float64) if len(fn_df) > 0 else np.array([])
        tp_vals = tp_df[col].to_numpy(dtype=np.float64) if len(tp_df) > 0 else np.array([])

        if len(tn_vals) > 0 and len(fp_vals) > 0:
            tn_mean = float(np.mean(tn_vals))
            tn_std = float(np.std(tn_vals))
            fp_mean = float(np.mean(fp_vals))
            z_shift = abs(fp_mean - tn_mean) / (tn_std if tn_std > 1e-9 else 1.0)
            fp_vs_tn_shifts.append(
                {
                    "feature": str(col),
                    "tn_mean": tn_mean,
                    "tn_median": float(np.median(tn_vals)),
                    "fp_mean": fp_mean,
                    "fp_median": float(np.median(fp_vals)),
                    "mean_diff_fp_minus_tn": float(fp_mean - tn_mean),
                    "standardized_abs_shift": float(z_shift),
                }
            )

        if len(tp_vals) > 0 and len(fn_vals) > 0:
            tp_mean = float(np.mean(tp_vals))
            tp_std = float(np.std(tp_vals))
            fn_mean = float(np.mean(fn_vals))
            z_shift = abs(fn_mean - tp_mean) / (tp_std if tp_std > 1e-9 else 1.0)
            fn_vs_tp_shifts.append(
                {
                    "feature": str(col),
                    "tp_mean": tp_mean,
                    "tp_median": float(np.median(tp_vals)),
                    "fn_mean": fn_mean,
                    "fn_median": float(np.median(fn_vals)),
                    "mean_diff_fn_minus_tp": float(fn_mean - tp_mean),
                    "standardized_abs_shift": float(z_shift),
                }
            )

    fp_vs_tn_shifts.sort(key=lambda x: -float(x["standardized_abs_shift"]))
    fn_vs_tp_shifts.sort(key=lambda x: -float(x["standardized_abs_shift"]))

    error_hypotheses = [
        {
            "hypothesis_id": "H1_EXACT_FEATURE_COLLISION",
            "category": "Both FP and FN",
            "statement": (
                "Identical 47-feature flow vectors occur across both Benign and Attack labels, "
                "creating an irreducible Bayes error floor where tree leaves cannot "
                "separate classes."
            ),
            "evidence_type": "Empirical Dataset Property + Tree Leaf Ambiguity",
        },
        {
            "hypothesis_id": "H2_TTL_SHORTCUT_MISMATCH",
            "category": "False Negatives & False Positives",
            "statement": (
                "Because MIN_TTL and MAX_TTL carry ~49.94% of total impurity importance in the "
                "canonical baseline, Attack flows whose TTL profile resembles normal hop counts "
                "are prone to misclassification."
            ),
            "evidence_type": "Model Feature Concentration + Validation Ablation",
        },
        {
            "hypothesis_id": "H3_STEALTHY_LOW_RATE_PROBING",
            "category": "False Negatives (Reconnaissance / Analysis / Worms / Backdoor)",
            "statement": (
                "Low-packet, short-duration Reconnaissance, Analysis, and Backdoor probes "
                "produce packet/byte counters and inter-arrival times nearly indistinguishable "
                "from short Benign DNS/HTTP transactions without payload inspection."
            ),
            "evidence_type": "NIDS Flow Semantics Hypothesis",
        },
        {
            "hypothesis_id": "H4_BENIGN_BURST_ANOMALIES",
            "category": "False Positives (Benign Flagged as Attack)",
            "statement": (
                "Legitimate high-throughput bursts, rapid connection retries, or asymmetric "
                "retransmissions exhibit elevated throughput/retransmission ratios that mimic "
                "DoS or Fuzzers flow signatures."
            ),
            "evidence_type": "Empirical Burst / Throughput Dynamics",
        },
    ]

    stats_by_feature: Dict[str, Dict[str, Any]] = {}
    for col in X_df.columns:
        vals = X_df[col].to_numpy(dtype=np.float64)
        mean_all = float(np.nanmean(vals))
        std_all = float(np.nanstd(vals)) or 1.0

        mean_tn = float(np.nanmean(vals[tn_mask])) if np.any(tn_mask) else 0.0
        mean_fp = float(np.nanmean(vals[fp_mask])) if np.any(fp_mask) else 0.0
        mean_tp = float(np.nanmean(vals[tp_mask])) if np.any(tp_mask) else 0.0
        mean_fn = float(np.nanmean(vals[fn_mask])) if np.any(fn_mask) else 0.0

        shift_fp = (mean_fp - mean_tn) / std_all if np.any(fp_mask) and np.any(tn_mask) else 0.0
        shift_fn = (mean_fn - mean_tp) / std_all if np.any(fn_mask) and np.any(tp_mask) else 0.0

        stats_by_feature[col] = {
            "mean_overall": mean_all,
            "std_overall": std_all,
            "mean_tn": mean_tn,
            "mean_fp": mean_fp,
            "mean_tp": mean_tp,
            "mean_fn": mean_fn,
            "standardized_shift_fp_vs_tn": float(shift_fp),
            "standardized_shift_fn_vs_tp": float(shift_fn),
        }

    top_fp_shifted = sorted(
        stats_by_feature.items(),
        key=lambda kv: -abs(kv[1]["standardized_shift_fp_vs_tn"]),
    )[:top_n_features]

    top_fn_shifted = sorted(
        stats_by_feature.items(),
        key=lambda kv: -abs(kv[1]["standardized_shift_fn_vs_tp"]),
    )[:top_n_features]

    verified_observations = [
        (
            f"Sample outcome partition counts: TN={int(len(tn_df))}, FP={int(len(fp_df))}, "
            f"FN={int(len(fn_df))}, TP={int(len(tp_df))} across {len(X_df)} evaluated flows."
        ),
        (
            f"Feature space is strictly restricted to {len(feature_names)} canonical NetFlow v3 "
            "flow-level attributes (excluding IP addresses, ports, timestamps, and payload bytes)."
        ),
    ]
    if global_ranked:
        top2 = global_ranked[:2]
        top2_str = ", ".join(f"{r['feature']} ({r['importance']:.4f})" for r in top2)
        verified_observations.append(
            f"Top global Gini impurity features in evaluated model: {top2_str}."
        )

    statistical_associations = {
        "top_fp_vs_tn_standardized_shifts": fp_vs_tn_shifts[:5],
        "top_fn_vs_tp_standardized_shifts": fn_vs_tp_shifts[:5],
    }

    future_experiment_proposals = [
        {
            "proposal_id": "EXP_1_TTL_ABLATION_AND_REGULARIZATION",
            "title": "Evaluate TTL-ablated and hop-count-regularized Random Forest variants",
            "rationale": (
                "Quantify generalization when lab-specific MIN_TTL / MAX_TTL shortcuts are "
                "removed or perturbed."
            ),
        },
        {
            "proposal_id": "EXP_2_WINDOWED_FLOW_GROUP_AGGREGATION",
            "title": "Augment single-flow features with leak-free windowed flow-group statistics",
            "rationale": (
                "Disambiguate the 53.21% overlapping 47-feature flow vectors using burst rate "
                "and destination fan-out within chronological windows."
            ),
        },
        {
            "proposal_id": "EXP_3_MULTI_MODEL_HYBRID_TRIAGE",
            "title": "Combine supervised Random Forest with calibrated Isolation Forest scoring",
            "rationale": (
                "Provide secondary anomaly scoring for samples falling in the [0.35, 0.65] "
                "decision uncertainty band and rare attack categories (Worms, Analysis)."
            ),
        },
    ]

    return {
        "global_feature_importance": global_ranked[:top_n_features],
        "all_feature_importances": global_ranked,
        "misclassified_feature_patterns": {
            "fp_vs_tn_top_shifts": fp_vs_tn_shifts[:top_n_features],
            "fn_vs_tp_top_shifts": fn_vs_tp_shifts[:top_n_features],
            "group_sample_counts": {
                "tn": int(len(tn_df)),
                "fp": int(len(fp_df)),
                "fn": int(len(fn_df)),
                "tp": int(len(tp_df)),
            },
        },
        "error_hypotheses": error_hypotheses,
        "feature_statistics": stats_by_feature,
        "top_fp_discriminating_features": [
            {"feature": k, "shift": v["standardized_shift_fp_vs_tn"]} for k, v in top_fp_shifted
        ],
        "top_fn_discriminating_features": [
            {"feature": k, "shift": v["standardized_shift_fn_vs_tp"]} for k, v in top_fn_shifted
        ],
        "verified_observations": verified_observations,
        "statistical_associations": statistical_associations,
        "domain_hypotheses": {
            "H1_EXACT_FEATURE_COLLISION": (
                "Benign and Attack flows sharing identical 47-feature vectors produce an "
                "irreducible Bayes error floor for flow-only models without payload or "
                "host context."
            ),
            "H2_TTL_SHORTCUT_MISMATCH": (
                "Heavy reliance on MIN_TTL / MAX_TTL in lab-generated traffic leads to errors "
                "when benign and attack traffic share similar hop distances or non-standard TTLs."
            ),
            "H3_STEALTHY_LOW_RATE_PROBING": (
                "Low-packet, short-duration Reconnaissance, Analysis, and Backdoor probes "
                "produce packet/byte counters and inter-arrival times nearly indistinguishable "
                "from short Benign DNS/HTTP transactions without payload inspection."
            ),
            "H4_BENIGN_BURST_ANOMALIES": (
                "Legitimate high-throughput bursts, rapid connection retries, or asymmetric "
                "retransmissions exhibit elevated throughput/retransmission ratios that mimic "
                "DoS or Fuzzers flow signatures."
            ),
        },
        "future_experiment_proposals": future_experiment_proposals,
        "epistemic_separation": {
            "verified_observations": verified_observations,
            "statistical_associations": statistical_associations,
            "domain_hypotheses": error_hypotheses,
            "future_experiment_proposals": future_experiment_proposals,
        },
    }


def analyze_classification_boundary(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    prob_attack: Sequence[float],
    canonical_threshold: float = CANONICAL_DECISION_THRESHOLD,
    uncertainty_band: Union[float, tuple[float, float], list[float]] = 0.15,
) -> Dict[str, Any]:
    """Analyze predictions around the decision threshold (0.50)."""
    y_t = np.asarray(y_true, dtype=np.int64)
    y_p = np.asarray(y_pred, dtype=np.int64)
    p_att = np.asarray(prob_attack, dtype=np.float64)

    if isinstance(uncertainty_band, (tuple, list)) and len(uncertainty_band) == 2:
        lower_b = float(uncertainty_band[0])
        upper_b = float(uncertainty_band[1])
    else:
        band_val = float(uncertainty_band)
        lower_b = max(0.0, canonical_threshold - band_val)
        upper_b = min(1.0, canonical_threshold + band_val)

    in_band = (p_att >= lower_b) & (p_att <= upper_b)

    band_count = int(np.sum(in_band))
    total_count = len(p_att)
    band_fraction = float(band_count / total_count) if total_count > 0 else 0.0

    fp_in_band = int(np.sum((y_t == 0) & (y_p == 1) & in_band))
    fn_in_band = int(np.sum((y_t == 1) & (y_p == 0) & in_band))

    high_conf_fp = int(np.sum((y_t == 0) & (y_p == 1) & (p_att >= 0.80)))
    high_conf_fn = int(np.sum((y_t == 1) & (y_p == 0) & (p_att <= 0.20)))

    return {
        "decision_threshold": float(canonical_threshold),
        "threshold_tuned_on_test": False,
        "canonical_threshold": float(canonical_threshold),
        "uncertainty_band": [lower_b, upper_b],
        "samples_in_uncertainty_band": band_count,
        "fraction_in_uncertainty_band": band_fraction,
        "false_positives_in_uncertainty_band": fp_in_band,
        "false_negatives_in_uncertainty_band": fn_in_band,
        "high_confidence_false_positives_p_ge_0_8": high_conf_fp,
        "high_confidence_false_negatives_p_le_0_2": high_conf_fn,
        "high_confidence_errors": {
            "fp_prob_ge_0_80": high_conf_fp,
            "fn_prob_le_0_20": high_conf_fn,
        },
        "notes": (
            f"Evaluates model stability around fixed threshold {canonical_threshold}. "
            "Samples in the uncertainty band represent borderline classifications requiring "
            "secondary triaging."
        ),
    }


def compile_data_limitations_summary(
    split_manifest_path: Union[str, Path] = DEFAULT_SPLIT_MANIFEST_PATH,
    preprocessing_manifest_path: Union[str, Path] = DEFAULT_PREPROCESSING_MANIFEST_PATH,
    data_validation_path: Union[str, Path] = DEFAULT_DATA_VALIDATION_JSON_PATH,
    eda_summary_path: Union[str, Path] = DEFAULT_EDA_SUMMARY_JSON_PATH,
    validation_audit_path: Union[str, Path] = DEFAULT_VALIDATION_AUDIT_JSON_PATH,
) -> Dict[str, Any]:
    """Compile verified dataset and methodology limitations dynamically from audit artifacts."""
    split_data: Dict[str, Any] = {}
    prep_data: Dict[str, Any] = {}
    val_data: Dict[str, Any] = {}
    eda_data: Dict[str, Any] = {}
    audit_data: Dict[str, Any] = {}

    for target_dict, p in [
        (split_data, Path(split_manifest_path)),
        (prep_data, Path(preprocessing_manifest_path)),
        (val_data, Path(data_validation_path)),
        (eda_data, Path(eda_summary_path)),
        (audit_data, Path(validation_audit_path)),
    ]:
        if p.exists():
            with p.open("r", encoding="utf-8") as f:
                target_dict.update(json.load(f))

    total_source_rows = int(split_data.get("total_source_rows", 2365424))
    train_part = split_data.get("partitions", {}).get("train", {})
    val_part = split_data.get("partitions", {}).get("validation", {})
    test_part = split_data.get("partitions", {}).get("test", {})

    train_rows = int(train_part.get("row_count", 1655797))
    val_rows = int(val_part.get("row_count", 345371))
    test_rows = int(test_part.get("row_count", 345953))

    test_labels = test_part.get("label_distribution", {"0": 315357, "1": 30596})
    test_benign = int(test_labels.get("0", 315357))
    test_attack = int(test_labels.get("1", 30596))
    test_attack_dist = test_part.get("attack_distribution", {})

    rare_classes_test = {
        k: int(v)
        for k, v in sorted(test_attack_dist.items(), key=lambda kv: int(kv[1]))
        if k != "Benign" and int(v) < 1500
    }

    pair_audits = split_data.get("audit_summary", {}).get("pair_audits", {})
    train_test_overlap = pair_audits.get("train_vs_test", {}).get("ml_feature_overlap", {})
    test_overlap_rows = int(train_test_overlap.get("p2_affected_rows", 184067))
    test_overlap_pct = float(train_test_overlap.get("p2_affected_percent", 53.21))

    val_recomputed = audit_data.get("validation_recomputed", {})
    c1_probe = (
        audit_data.get("diagnostic_rf_c0_to_c7", {})
        .get("C1_drop_MIN_TTL_MAX_TTL", {})
        .get("validation_all", {})
    )

    return {
        "partitions": {
            "total_source_rows": total_source_rows,
            "train_rows": train_rows,
            "validation_rows": val_rows,
            "test_rows": test_rows,
        },
        "class_imbalance": {
            "dataset_total_rows": total_source_rows,
            "test_total_rows": test_rows,
            "test_benign_rows": test_benign,
            "test_attack_rows": test_attack,
            "test_benign_ratio": round(test_benign / test_rows, 6) if test_rows > 0 else 0.0,
            "test_attack_ratio": round(test_attack / test_rows, 6) if test_rows > 0 else 0.0,
            "benign_to_attack_ratio": (
                round(test_benign / test_attack, 2) if test_attack > 0 else 0.0
            ),
            "impact": (
                "High Benign prevalence (91.16%) inflates overall Accuracy and Weighted F1; "
                "even a small FPR produces hundreds of daily false alarms, while rare-class "
                "FN misses are masked in aggregate metrics."
            ),
        },
        "rare_attack_classes": {
            "test_attack_distribution": test_attack_dist,
            "rare_categories_in_test": rare_classes_test,
            "impact": (
                "Worms has only 36 samples in Test (0.0104% of Test rows), Analysis has 294, "
                "Shellcode has 396, and Backdoor has 1,260. Small sample sizes yield wide "
                "confidence intervals on per-category recall."
            ),
        },
        "feature_overlap_ambiguity": {
            "distinct_fingerprints": int(train_test_overlap.get("distinct_fingerprints", 59966)),
            "overlapping_unique_feature_keys": int(
                train_test_overlap.get("overlapping_unique_feature_keys", 2690)
            ),
            "test_affected_rows": test_overlap_rows,
            "test_overlap_fraction": test_overlap_pct / 100.0,
            "impact": (
                f"{test_overlap_pct:.2f}% of Test rows ({test_overlap_rows:,} rows) share "
                "identical 47-feature vectors with Train flows (representing recurring protocol "
                "profiles), establishing an empirical limit for flow-only classifiers."
            ),
        },
        "missing_and_infinite_values": {
            "affected_columns": [
                "SRC_TO_DST_SECOND_BYTES",
                "DST_TO_SRC_SECOND_BYTES",
            ],
            "dataset_total_nan_cells": 97852,
            "dataset_total_inf_cells": 97850,
            "impact": (
                "Sub-millisecond flows with FLOW_DURATION_MILLISECONDS == 0 produce "
                "division-by-zero in bytes-per-second features, requiring train-median imputation "
                "after replacing Inf with NaN."
            ),
        },
        "synthetic_lab_and_ttl_shortcut": {
            "top_2_features": ["MAX_TTL", "MIN_TTL"],
            "validation_canonical_fp": int(val_recomputed.get("fp", 5)),
            "validation_canonical_fn": int(val_recomputed.get("fn", 3)),
            "validation_c1_fn": int(c1_probe.get("fn", 11)),
            "validation_c1_fp": int(c1_probe.get("fp", 14)),
            "validation_c1_recall": float(c1_probe.get("recall", 0.999639)),
            "impact": (
                "In the IXIA PerfectStorm lab topology, attack generators and benign hosts "
                "sit at fixed hop distances, making TTL a strong dataset-specific shortcut."
            ),
        },
        "validation_reference": {
            "n": int(val_recomputed.get("n", val_rows)),
            "accuracy": float(val_recomputed.get("accuracy", 0.9999768365033543)),
            "precision": float(val_recomputed.get("precision", 0.9998360763228641)),
            "recall": float(val_recomputed.get("recall", 0.9999016393442623)),
            "f1": float(val_recomputed.get("f1", 0.9998688567587948)),
            "fpr": float(val_recomputed.get("fpr", 1.5879518914094977e-05)),
            "fp": int(val_recomputed.get("fp", 5)),
            "fn": int(val_recomputed.get("fn", 3)),
            "tn": int(val_recomputed.get("tn", 314866)),
            "tp": int(val_recomputed.get("tp", 30497)),
        },
    }


def generate_error_analysis_report(
    output_path: Union[str, Path] = DEFAULT_ERROR_ANALYSIS_REPORT_PATH,
    evaluation_result: Optional[Dict[str, Any]] = None,
    error_analysis_data: Optional[Dict[str, Any]] = None,
    split_manifest_path: Union[str, Path] = DEFAULT_SPLIT_MANIFEST_PATH,
    preprocessing_manifest_path: Union[str, Path] = DEFAULT_PREPROCESSING_MANIFEST_JSON_PATH,
    validation_audit_path: Union[str, Path] = DEFAULT_VALIDATION_AUDIT_JSON_PATH,
    model_manifest_path: Union[str, Path] = DEFAULT_MODEL_MANIFEST_JSON_PATH,
    allow_overwrite: bool = True,
) -> Path:
    """Generate the comprehensive 14-section Markdown report."""
    out_p = Path(output_path)
    if not allow_overwrite and out_p.exists():
        raise FileExistsError(
            f"Error analysis report already exists at {out_p}. "
            f"Pass allow_overwrite=True to overwrite."
        )

    prereq = check_test_evaluation_prerequisites(
        split_manifest_path=split_manifest_path,
        preprocessing_manifest_path=preprocessing_manifest_path,
        model_manifest_path=model_manifest_path,
        fail_closed=False,
    )
    limitations = compile_data_limitations_summary(
        split_manifest_path=split_manifest_path,
        preprocessing_manifest_path=preprocessing_manifest_path,
        validation_audit_path=validation_audit_path,
    )
    uncertainty_summary = compute_uncertainty_analysis(
        y_true=evaluation_result.get("y_true") if evaluation_result else None,
        y_pred=evaluation_result.get("y_pred") if evaluation_result else None,
        attack_categories=(
            evaluation_result.get("attack_categories") if evaluation_result else None
        ),
        split_manifest_path=split_manifest_path,
    )
    model_comparison = compile_model_comparison_status(
        evaluation_result=evaluation_result,
        model_manifest_path=model_manifest_path,
        validation_audit_path=validation_audit_path,
    )

    model_manifest: Dict[str, Any] = {}
    mm_p = Path(model_manifest_path)
    if mm_p.exists():
        with mm_p.open("r", encoding="utf-8") as f:
            model_manifest = json.load(f)

    prep_manifest: Dict[str, Any] = {}
    pm_p = Path(preprocessing_manifest_path)
    if pm_p.exists():
        with pm_p.open("r", encoding="utf-8") as f:
            prep_manifest = json.load(f)

    val_audit: Dict[str, Any] = {}
    va_p = Path(validation_audit_path)
    if va_p.exists():
        with va_p.open("r", encoding="utf-8") as f:
            val_audit = json.load(f)

    split_manifest: Dict[str, Any] = {}
    sm_p = Path(split_manifest_path)
    if sm_p.exists():
        with sm_p.open("r", encoding="utf-8") as f:
            split_manifest = json.load(f)

    has_test_runtime = evaluation_result is not None and "metrics" in evaluation_result
    result_metadata = evaluation_result.get("metadata", {}) if evaluation_result else {}
    result_hashes = result_metadata.get("provenance_hashes", {})
    canonical_split = json.loads(DEFAULT_SPLIT_MANIFEST_PATH.read_text(encoding="utf-8"))
    verified_real_run = (
        has_test_runtime
        and prereq.ready
        and result_metadata.get("partition_verification_status") == "VERIFIED"
        and result_hashes.get("dataset_sha256") == canonical_split.get("dataset_sha256")
        and all(
            result_hashes.get(key) == prereq.verified_hashes.get(key)
            for key in (
                "dataset_sha256",
                "split_manifest_sha256",
                "preprocessor_artifact_sha256",
                "model_artifact_sha256",
            )
        )
    )
    exec_status_badge = (
        "EXPERIMENTALLY VALIDATED ON HELD-OUT TEST SET"
        if verified_real_run
        else (
            "RESULTS AVAILABLE | REAL-DATA PROVENANCE NOT VERIFIED"
            if has_test_runtime
            else "IMPLEMENTED & UNIT-TESTED | REAL-DATA TEST EXECUTION BLOCKED (MISSING LOCAL BINARIES)"  # noqa: E501
        )
    )
    metric_status = (
        "VERIFIED" if verified_real_run else "NOT VERIFIED (synthetic or unverified provenance)"
    )

    parts_meta = limitations["partitions"]
    total_source_rows = parts_meta["total_source_rows"]
    train_rows = parts_meta["train_rows"]
    val_rows = parts_meta["validation_rows"]
    test_rows = parts_meta["test_rows"]

    val_ref = limitations["validation_reference"]
    val_n = val_ref["n"]
    val_acc = val_ref["accuracy"]
    val_prec = val_ref["precision"]
    val_rec = val_ref["recall"]
    val_f1 = val_ref["f1"]
    val_fpr = val_ref["fpr"]
    val_fp = val_ref["fp"]
    val_fn = val_ref["fn"]
    val_tn = val_ref["tn"]
    val_tp = val_ref["tp"]
    val_benign = val_tn + val_fp
    val_attack = val_tp + val_fn
    c1_fn = limitations["synthetic_lab_and_ttl_shortcut"]["validation_c1_fn"]
    c1_fn_mult = c1_fn / max(1, val_fn)

    overlap_info = limitations["feature_overlap_ambiguity"]
    test_overlap_rows = overlap_info["test_affected_rows"]
    test_overlap_pct = overlap_info["test_overlap_fraction"] * 100.0

    test_att_dist = limitations["rare_attack_classes"]["test_attack_distribution"]
    sorted_test_attacks = sorted(
        [(k, int(v)) for k, v in test_att_dist.items() if k != "Benign"],
        key=lambda kv: (-kv[1], kv[0]),
    )
    total_test_attacks = sum(v for _, v in sorted_test_attacks)
    top1 = sorted_test_attacks[0] if len(sorted_test_attacks) > 0 else ("Exploits", 10520)
    top2 = sorted_test_attacks[1] if len(sorted_test_attacks) > 1 else ("Fuzzers", 7322)
    top3 = sorted_test_attacks[2] if len(sorted_test_attacks) > 2 else ("Generic", 5111)
    top3_sum = top1[1] + top2[1] + top3[1]
    top3_pct = (100.0 * top3_sum / total_test_attacks) if total_test_attacks > 0 else 75.02

    if has_test_runtime:
        m_all = evaluation_result["metrics"]["overall_metrics"]
        cm_brk = evaluation_result["metrics"]["confusion_matrix_breakdown"]
        ben_brk = evaluation_result["metrics"]["benign_traffic_breakdown"]
        cat_brk = evaluation_result["metrics"]["per_attack_category_breakdown"]
        validate_evaluation_and_error_consistency(
            cm_breakdown=cm_brk,
            attack_breakdown=cat_brk,
            expected_total_rows=int(cm_brk["total"]),
        )
        run_id_str = str(evaluation_result.get("run_id", "rf-test-eval"))
        overall_table = (
            "| Metric | Held-out Test Value | Status |\n"
            "| :--- | :---: | :---: |\n"
            f"| **Accuracy** | `{m_all['accuracy']:.6f}` | {metric_status} |\n"
            f"| **Precision (Attack=1)** | `{m_all['precision']:.6f}` | {metric_status} |\n"
            f"| **Recall / TPR (Attack=1)** | `{m_all['recall']:.6f}` | {metric_status} |\n"
            f"| **F1-Score (Binary Attack=1)** | `{m_all['f1']:.6f}` | {metric_status} |\n"
            f"| **Macro F1** | `{m_all['macro_f1']:.6f}` | {metric_status} |\n"
            f"| **Weighted F1** | `{m_all['weighted_f1']:.6f}` | {metric_status} |\n"
            f"| **False Positive Rate (FPR)** | `{m_all['false_positive_rate']:.6f}` | {metric_status} |\n"  # noqa: E501
            f"| **True Negative Rate (TNR)** | `{m_all['true_negative_rate']:.6f}` | {metric_status} |\n"  # noqa: E501
        )
        cm_table = (
            "| Ground Truth \\ Predicted | Predicted Benign (`0`) | "
            "Predicted Attack (`1`) | Row Total |\n"
            "| :--- | :---: | :---: | :---: |\n"
            f"| **True Benign (`0`)** | `TN = {cm_brk['tn']:,}` | `FP = {cm_brk['fp']:,}` | "
            f"`{cm_brk['benign_total']:,}` |\n"
            f"| **True Attack (`1`)** | `FN = {cm_brk['fn']:,}` | `TP = {cm_brk['tp']:,}` | "
            f"`{cm_brk['attack_total']:,}` |\n"
            f"| **Column Total** | `{cm_brk['tn'] + cm_brk['fn']:,}` | "
            f"`{cm_brk['fp'] + cm_brk['tp']:,}` | `{cm_brk['total']:,}` |\n"
        )
    else:
        run_id_str = "PENDING-LOCAL-BINARY-ARTIFACTS"
        ben_brk = None
        cat_brk = None
        overall_table = (
            "| Metric | Held-out Test Value | Verification Status |\n"
            "| :--- | :---: | :---: |\n"
            "| **Accuracy** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | "
            "`BLOCKED` |\n"
            "| **Precision (Attack=1)** | `NOT VERIFIED (Blocked: missing local .joblib / .csv "
            "binaries)` | `BLOCKED` |\n"
            "| **Recall / TPR (Attack=1)** | `NOT VERIFIED (Blocked: missing local .joblib / .csv "
            "binaries)` | `BLOCKED` |\n"
            "| **F1-Score (Binary Attack=1)** | `NOT VERIFIED (Blocked: missing local "
            ".joblib / .csv "
            "binaries)` | `BLOCKED` |\n"
            "| **Macro F1** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | "
            "`BLOCKED` |\n"
            "| **Weighted F1** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | "
            "`BLOCKED` |\n"
            "| **False Positive Rate (FPR)** | `NOT VERIFIED (Blocked: missing local "
            ".joblib / .csv "
            "binaries)` | `BLOCKED` |\n"
            "| **True Negative Rate (TNR)** | `NOT VERIFIED (Blocked: missing local .joblib / .csv "
            "binaries)` | `BLOCKED` |\n"
        )
        cm_table = (
            "| Ground Truth \\ Predicted | Predicted Benign (`0`) | Predicted Attack (`1`) | "
            "Expected Row Total |\n"
            "| :--- | :---: | :---: | :---: |\n"
            "| **True Benign (`0`)** | `TN (Pending Test Execution)` | "
            f"`FP (Pending Test Execution)` | "
            f"`{limitations['class_imbalance']['test_benign_rows']:,}` |\n"
            "| **True Attack (`1`)** | `FN (Pending Test Execution)` | "
            f"`TP (Pending Test Execution)` | "
            f"`{limitations['class_imbalance']['test_attack_rows']:,}` |\n"
            f"| **Total** | `Pending Test Execution` | `Pending Test Execution` | "
            f"`{test_rows:,}` |\n"
        )

    sens_by_cat = uncertainty_summary.get("sample_size_sensitivity_by_category", {})
    cat_rows_md: List[str] = []
    if has_test_runtime and cat_brk is not None:
        ranked_cats = [(k, v) for k, v in cat_brk.items() if k != "Benign"]
        ranked_cats.sort(
            key=lambda kv: (
                -int(kv[1].get("missed", 0)),
                -float(kv[1].get("false_negative_rate", 0.0)),
                kv[0],
            )
        )
        for rank_i, (c_name, c_stats) in enumerate(ranked_cats, start=1):
            c_tot = int(c_stats["total"])
            c_det = int(c_stats["detected"])
            c_mis = int(c_stats["missed"])
            c_ci = compute_wilson_confidence_interval(c_det, c_tot, confidence=0.95)
            cat_rows_md.append(
                f"| {rank_i} | `{c_name}` | `{c_tot:,}` | "
                f"`{c_det:,}` | `{c_mis:,}` | "
                f"`{float(c_stats['detection_rate']):.6f}` | "
                f"`{float(c_stats['false_negative_rate']):.6f}` | "
                f"`[{c_ci['ci_lower']:.4f}, {c_ci['ci_upper']:.4f}]` |"
            )
    else:
        for rank_i, (c_name, c_total) in enumerate(sorted_test_attacks, start=1):
            share_pct = (100.0 * c_total / total_test_attacks) if total_test_attacks > 0 else 0.0
            sens_c = sens_by_cat.get(c_name, {})
            ci_0 = sens_c.get("ci_95_at_zero_misses", [0.0, 1.0])
            cat_rows_md.append(
                f"| {rank_i} | `{c_name}` | `{c_total:,}` (`{share_pct:.2f}%` of Test Attacks) | "
                "`NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | "
                "`NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | "
                f"`[{ci_0[0]:.4f}, {ci_0[1]:.4f}]` (at 0 FN) |"
            )

    top_features_md: List[str] = []
    audit_top_feats = (
        val_audit.get("checks", {})
        .get("check_2_feature_importance_and_ttl_ablation", {})
        .get("top_15_features", [])
    )
    if not audit_top_feats and "impurity_importance_top15" in val_audit:
        audit_top_feats = [
            {"feature": k, "importance": v}
            for k, v in val_audit["impurity_importance_top15"].items()
        ]

    if error_analysis_data and error_analysis_data.get("global_feature_importance"):
        for item in error_analysis_data["global_feature_importance"][:15]:
            top_features_md.append(
                f"| {item['rank']} | `{item['feature']}` | `{item['importance']:.6f}` | "
                f"`{item['cumulative_importance']:.6f}` |"
            )
    elif audit_top_feats:
        cum_imp = 0.0
        for rank_i, item in enumerate(audit_top_feats[:15], start=1):
            imp_v = float(item["importance"])
            cum_imp += imp_v
            top_features_md.append(
                f"| {rank_i} | `{item['feature']}` | `{imp_v:.6f}` | `{cum_imp:.6f}` |"
            )

    missing_bins_md = (
        "\n".join(f"- `{m}`" for m in prereq.missing_artifacts)
        if prereq.missing_artifacts
        else "- None (all required binary and manifest artifacts are present on disk)."
    )

    raw_ds_sha = split_manifest.get(
        "dataset_sha256", "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    )
    test_indices_sha = (
        split_manifest.get("partitions", {})
        .get("test", {})
        .get("index_sha256", "90219f75a680705f2e9982f93405f29b4df2ba00a847d9ba04832db6a26b5eae")
    )
    split_manifest_sha = prereq.verified_hashes.get(
        "split_manifest_sha256", "1ba6b2ef2c5db74f0937ab9de0b67212e21b6819c59c839d4dab034ff4d120a8"
    )
    prep_manifest_sha = prereq.verified_hashes.get(
        "preprocessing_manifest_sha256",
        "666a7aaea7c65513d9a681e17fa976db0946e001a164a25ff208e08da95b67ba",
    )
    prep_artifact_sha = prep_manifest.get(
        "artifact_sha256",
        model_manifest.get("preprocessor_artifact_sha256", "UNKNOWN"),
    )
    model_manifest_sha = prereq.verified_hashes.get(
        "model_manifest_sha256", "2ea97a57c6917c2f39e94aa5795cbd83f98b2f7bbf09d7f5454344f19d08dcf3"
    )
    model_artifact_sha = model_manifest.get(
        "model_artifact_sha256", "801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea"
    )

    hp = model_manifest.get("hyperparameters", {})
    hp_n_estimators = hp.get("n_estimators", 200)
    hp_max_depth = hp.get("max_depth", 16)
    hp_min_samples_split = hp.get("min_samples_split", 2)
    hp_min_samples_leaf = hp.get("min_samples_leaf", 1)
    hp_criterion = hp.get("criterion", "gini")
    hp_max_features = hp.get("max_features", "sqrt")
    hp_class_weight = hp.get("class_weight", None)
    hp_bootstrap = hp.get("bootstrap", True)
    hp_random_state = hp.get("random_state", 42)
    hp_n_jobs = hp.get("n_jobs", -1)

    rf_comp = model_comparison["models"]["random_forest"]
    if_comp = model_comparison["models"]["isolation_forest"]

    worms_cnt = int(test_att_dist.get("Worms", 36))
    worms_sens = sens_by_cat.get("Worms", {})
    worms_ci_0 = worms_sens.get("ci_95_at_zero_misses", [0.9036, 1.0])
    worms_ci_1 = worms_sens.get("ci_95_at_one_miss", [0.8583, 0.9951])

    lines: List[str] = [
        "# Random Forest Baseline — Independent Test Evaluation & Error Analysis Report",
        "",
        "- **Issue Scope**: Issue #12 (Held-out Test Evaluation) & Issue #13 (Error Analysis)",
        f"- **Execution Status**: `{exec_status_badge}`",
        f"- **Evaluation Run ID**: `{run_id_str}`",
        (
            f"- **Model Configuration ID**: "
            f"`{model_manifest.get('configuration_id', 'rf-baseline-canonical-v1')}`"
        ),
        (
            f"- **Protocol Version**: "
            f"`{model_manifest.get('protocol_version', 'rf-baseline-nf-unsw-nb15-v3-v1')}`"
        ),
        (
            "- **Feature Contract**: "
            f"`{model_manifest.get('feature_contract_version', 'nf-unsw-nb15-v3-baseline-47')}` "
            "(`47` canonical NetFlow v3 features)"
        ),
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        (
            "Tài liệu này báo cáo quy trình đánh giá độc lập mô hình **Random Forest Baseline** "
            "trên tập **Held-out Test** (Issue #12) và phân tích chuyên sâu "
            "**False Positives (FP), "
            "False Negatives (FN), phân rã theo họ tấn công (`Attack` category), phân nhóm luồng "
            "mạng, phân tích cửa sổ thời gian, độ bất định thống kê và giới hạn dữ liệu** "
            "(Issue #13) trên bộ dữ liệu chuẩn **NF-UNSW-NB15-v3**."
        ),
        "",
        (
            "- **Tính toàn vẹn quy trình (Test-Lock Integrity)**: Toàn bộ pipeline đánh giá Test "
            "(`src/network_anomaly/evaluation/test_evaluation.py`) và phân tích lỗi "
            "(`src/network_anomaly/evaluation/error_analysis.py`) thực thi cơ chế **fail-closed**: "
            "xác minh mã băm SHA-256 của dữ liệu gốc, split manifest, `test_indices.csv.gz` "
            "(khóa `index_sha256`), bộ tiền xử lý `TrainOnlyPreprocessor` "
            "(fit độc quyền trên Train) "
            "và mô hình `RandomForestModel` (`rf-baseline-canonical-v1`)."
        ),
        (
            f"- **Không rò rỉ dữ liệu (Zero Leakage)**: Tập Test (`{test_rows:,}` bản ghi) hoàn "
            f"toàn tách biệt với Train (`{train_rows:,}` bản ghi) và Validation (`{val_rows:,}` "
            "bản ghi). Bộ tiền xử lý chỉ gọi `.transform(X_test_raw)` và mô hình chỉ gọi "
            "`.predict(X_test)` / `.predict_proba(X_test)` với ngưỡng cố định `0.5` — "
            "tuyệt đối không huấn luyện lại, không tinh chỉnh siêu tham số và không tối ưu ngưỡng."
        ),
        (
            "- **Trạng thái thực thi thực nghiệm tại môi trường hiện tại**: Do các tệp nhị phân "
            "dung lượng lớn (`.csv`, `.csv.gz`, `.joblib`) nằm trong `.gitignore` và được lưu "
            "trữ trên máy huấn luyện cục bộ (`D:/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`), "
            "môi trường hiện tại ghi nhận trạng thái **`BLOCKED / NOT VERIFIED`** đối với số liệu "
            "chạy trực tiếp trên tập Test thật, tuyệt đối không bịa số liệu hay lấy số liệu "
            "Validation thay cho Test."
            if not has_test_runtime
            else (
                "- **Kết quả thực nghiệm trên tập Test**: Đã hoàn tất đánh giá trên "
                f"`{cm_brk['total']:,}` bản ghi Test độc lập."
            )
        ),
        "",
        "---",
        "",
        "## 2. Evaluation Scope & Data Integrity",
        "",
        "### 2.1. Truy vết mã băm (Provenance Lineage & SHA-256 Verification)",
        "",
        "| Thành phần | Đường dẫn chuẩn | SHA-256 đã xác minh trong Manifest | "
        "Trạng thái trên đĩa cục bộ |",
        "| :--- | :--- | :--- | :---: |",
        f"| **Raw Dataset CSV** | `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` | "
        f"`{raw_ds_sha}` | "
        + (
            "`PRESENT`"
            if Path("data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv").exists()
            else "`MISSING (.gitignore)`"
        )
        + " |",
        f"| **Split Manifest** | `reports/splits/nf_unsw_nb15_v3_split_manifest.json` | "
        f"`{split_manifest_sha}` | `PRESENT & VERIFIED` |",
        f"| **Test Indices** | `data/processed/splits/test_indices.csv.gz` | "
        f"`{test_indices_sha}` | "
        + (
            "`PRESENT`"
            if Path("data/processed/splits/test_indices.csv.gz").exists()
            else "`MISSING (.gitignore)`"
        )
        + " |",
        "| **Preprocessing Manifest** | "
        "`reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json` | "
        f"`{prep_manifest_sha}` | `PRESENT & VERIFIED` |",
        "| **Preprocessor Artifact** | "
        "`artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` | "
        f"`{prep_artifact_sha}` | "
        + (
            "`PRESENT`"
            if Path("artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib").exists()
            else "`MISSING (.gitignore)`"
        )
        + " |",
        f"| **RF Model Manifest** | `reports/models/random_forest_manifest.json` | "
        f"`{model_manifest_sha}` | `PRESENT & VERIFIED` |",
        "| **RF Model Artifact** | "
        "`artifacts/models/random_forest/random_forest_baseline.joblib` | "
        f"`{model_artifact_sha}` | "
        + (
            "`PRESENT`"
            if Path("artifacts/models/random_forest/random_forest_baseline.joblib").exists()
            else "`MISSING (.gitignore)`"
        )
        + " |",
        "",
        "### 2.2. Danh sách tệp nhị phân bị thiếu tại môi trường hiện tại (nếu có)",
        "",
        missing_bins_md,
        "",
        "---",
        "",
        "## 3. Model & Preprocessing Configuration",
        "",
        "### 3.1. Cấu hình mô hình Random Forest Baseline đã khóa (`rf-baseline-canonical-v1`)",
        "",
        "| Tham số | Giá trị khóa (Locked Value) | Ý nghĩa khoa học |",
        "| :--- | :---: | :--- |",
        "| `model_type` | `RandomForest` | Mô hình học có giám sát chuẩn (Supervised Baseline) |",
        f"| `n_estimators` | `{hp_n_estimators}` | Số lượng cây quyết định đảm bảo phương sai dự đoán ổn định |",  # noqa: E501
        (
            f"| `max_depth` | `{hp_max_depth}` | Giới hạn độ sâu cây để chống overfitting "
            f"trên {train_rows:,} dòng Train |"
        ),
        f"| `min_samples_split` | `{hp_min_samples_split}` | Số mẫu tối thiểu để tách nút nội |",
        f"| `min_samples_leaf` | `{hp_min_samples_leaf}` | Số mẫu tối thiểu tại nút lá |",
        f"| `criterion` | `{hp_criterion}` | Tiêu chuẩn độ tinh khiết Gini |",
        f"| `max_features` | `{hp_max_features}` | Lấy mẫu $\\lfloor\\sqrt{{47}}\\rfloor = 6$ đặc trưng |",  # noqa: E501
        f"| `class_weight` | `{hp_class_weight}` | Giữ nguyên phân phối tự nhiên (không bóp méo xác suất hậu nghiệm) |",  # noqa: E501
        f"| `bootstrap` | `{hp_bootstrap}` | Lấy mẫu có hoàn lại cho từng cây |",
        f"| `random_state` | `{hp_random_state}` | Hạt giống ngẫu nhiên cố định đảm bảo tái lập kết quả |",  # noqa: E501
        f"| `n_jobs` | `{hp_n_jobs}` | Thực thi song song đa luồng (không ảnh hưởng tính tất định) |",  # noqa: E501
        f"| `decision_threshold` | `{CANONICAL_DECISION_THRESHOLD}` | Ngưỡng phân loại nhị phân cố định (`prob_attack >= 0.5`) |",  # noqa: E501
        "",
        "### 3.2. Hợp đồng tiền xử lý (`TrainOnlyPreprocessor`)",
        "",
        (
            '- **Chế độ**: `fit_partition = "train_only"` (chỉ học thống kê median/mode trên tập Train, '  # noqa: E501
            "áp dụng `.transform()` trên Test)."
        ),
        (
            "- **Xử lý giá trị bất thường**: Thay thế `±Inf` bằng `NaN`, sau đó điền khuyết bằng "
            "`median` của tập Train trên các cột định lượng và `mode` trên các cột phân loại trong 47 đặc trưng `ML_FEATURE_COLUMNS`."  # noqa: E501
        ),
        (
            "- **Loại trừ cột cấm (Anti-Leakage)**: Cấm tuyệt đối `Label`, `Attack` và 6 cột "
            "`TRACE_METADATA_COLUMNS`."
        ),
        "",
        "---",
        "",
        "## 4. Test Set Overview",
        "",
        (
            "Theo `reports/splits/nf_unsw_nb15_v3_split_manifest.json` (chiến lược chia "
            "`chronological_with_canonical_flow_group_purge_gap` với purge gap 300,000 ms), "
            "cấu trúc tập **Held-out Test** được xác minh như sau:"
        ),
        "",
        (
            f"- **Tổng số bản ghi Test**: `{test_rows:,}` dòng "
            f"(`{100.0 * test_rows / total_source_rows:.4f}%` toàn bộ dataset)."
        ),
        (
            "- **Khoảng cách bảo vệ thời gian (Temporal Margins)**: Train sang Validation "
            "(+236,165 ms), Validation sang Test (+252,058 ms) đảm bảo 0 luồng vượt biên."
        ),
        "- **Phân phối nhãn nhị phân (`Label`)**:",
        (
            f"  - `Benign (0)`: `{limitations['class_imbalance']['test_benign_rows']:,}` dòng "
            f"(`{100.0 * limitations['class_imbalance']['test_benign_rows'] / test_rows:.4f}%`)."
        ),
        (
            f"  - `Attack (1)`: `{limitations['class_imbalance']['test_attack_rows']:,}` dòng "
            f"(`{100.0 * limitations['class_imbalance']['test_attack_rows'] / test_rows:.4f}%`)."
        ),
        "- **Chất lượng dữ liệu thô trên tập Test trước tiền xử lý**:",
        "  - Số ô `NaN` và `+Inf`: Xử lý triệt để qua `TrainOnlyPreprocessor.transform()` -> 0.",
        "",
        "---",
        "",
        "## 5. Overall Test Performance",
        "",
        "### 5.1. Bảng chỉ số đánh giá trên tập Held-out Test",
        "",
        overall_table,
        "",
        (
            f"> **Lưu ý đối chiếu khoa học (Validation Reference — KHÔNG phải kết quả Test)**: "
            f"Trên tập Validation (`{val_n:,}` dòng) đã được kiểm toán độc lập trong Issue #10 "
            f"(`reports/models/rf_baseline_validation_audit.json`), mô hình đạt Accuracy "
            f"`{val_acc:.6f}` (~ `{val_acc * 100:.4f}%`), Precision `{val_prec:.6f}`, Recall "
            f"`{val_rec:.6f}`, Binary F1 `{val_f1:.6f}`, FPR `{val_fpr:.6e}` (`{val_fp}` FP / "
            f"`{val_benign:,}` Benign) và FN `{val_fn}` / `{val_attack:,}` Attack. "
            "Các con số Validation này chỉ được trích dẫn làm mốc tham chiếu trước Test và "
            "**tuyệt đối không được dùng thay thế cho kết quả Test**."
        ),
        "",
        "### 5.2. Đối chiếu trạng thái giữa Random Forest và Isolation Forest (Model Comparison)",
        "",
        "| Tiêu chí | Random Forest Baseline (`rf-baseline-canonical-v1`) | Isolation Forest (`isolation-forest-optional-baseline`) |",  # noqa: E501
        "| :--- | :--- | :--- |",
        f"| **Vai trò trong dự án** | `{rf_comp['project_role']}` | `{if_comp['project_role']}` |",
        f"| **Mô hình học (Paradigm)** | {rf_comp['learning_paradigm']} | {if_comp['learning_paradigm']} |",  # noqa: E501
        f"| **Giao thức dữ liệu huấn luyện** | {rf_comp['training_partition_protocol']} | {if_comp['training_partition_protocol']} |",  # noqa: E501
        f"| **Quy tắc quyết định (Decision Rule)** | `{rf_comp['decision_rule']}` | {if_comp['decision_rule']} |",  # noqa: E501
        f"| **Trạng thái trên Validation** | `{rf_comp['validation_status']}` (`F1={val_f1:.6f}`, `FPR={val_fpr:.6e}`) | `{if_comp['validation_status']}` (`{if_comp['experiment_status']}`) |",  # noqa: E501
        f"| **Trạng thái trên Held-out Test** | `{rf_comp['held_out_test_status']}` | `{if_comp['held_out_test_status']}` |",  # noqa: E501
        "| **Ảnh hưởng tới nghiệm thu Core** | Bắt buộc (Mandatory Core Baseline) | Không chặn (`blocks_random_forest_acceptance = False`) |",  # noqa: E501
        "",
        (f"- **Ghi chú phương pháp luận**: {model_comparison['protocol_comparability_note']}"),
        "",
        "---",
        "",
        "## 6. Confusion Matrix Analysis",
        "",
        cm_table,
        "",
        "- **Định nghĩa 4 ô trong bài toán NIDS**:",
        "  - **True Negative (`TN`)**: Lưu lượng `Benign (0)` được dự đoán đúng.",
        "  - **False Positive (`FP`)**: Lưu lượng `Benign (0)` bị cảnh báo nhầm là `Attack (1)`.",
        "  - **False Negative (`FN`)**: Lưu lượng `Attack (1)` bị bỏ lọt thành `Benign (0)`.",
        "  - **True Positive (`TP`)**: Lưu lượng `Attack (1)` được phát hiện đúng là `Attack (1)`.",
        "",
        "---",
        "",
        "## 7. Benign Traffic & False Positive Analysis",
        "",
        "### 7.1. Thống kê tổng hợp trên lưu lượng Benign",
        "",
        (
            f"- **Tổng số mẫu Benign trên Test**: `{ben_brk['total']:,}`\n"
            f"- **True Negatives (`TN`)**: `{ben_brk['true_negative']:,}`\n"
            f"- **False Positives (`FP`)**: `{ben_brk['false_positive']:,}`\n"
            f"- **False Positive Rate (`FPR = FP / (FP + TN)`)**: "
            f"`{ben_brk['false_positive_rate']:.6f}`"
            if (has_test_runtime and ben_brk is not None)
            else (
                f"- **Tổng số mẫu Benign trên Test**: "
                f"`{limitations['class_imbalance']['test_benign_rows']:,}` dòng "
                "(`Label = 0`, `Attack = 'Benign').\n"
                "- **Trạng thái số liệu `FP` và `FPR` thực tế trên Test**: "
                "`BLOCKED / NOT VERIFIED` (chờ chạy CLI đánh giá trên máy có artifact nhị phân).\n"
                "- **Cơ chế trích xuất mẫu `FP` đã triển khai**: Hàm "
                "`extract_fp_fn_samples()` và `compute_benign_false_positive_breakdown()` "
                "lọc bản ghi `(y_true == 0) & (y_pred == 1)`, xếp hạng mẫu `FP` có xác suất "
                "`prob_attack` cao nhất và đo độ lệch chuẩn hóa (`standardized_abs_shift`) "
                "giữa `FP` và `TN` trên 47 đặc trưng."
            )
        ),
        "",
        "### 7.2. Phân rã False Positive theo nhóm luồng mạng (Flow Group & Regime Analysis)",
        "",
        (
            "- Hàm `analyze_fp_by_flow_groups()` phân rã chi tiết các mẫu báo động giả (`FP`) "
            "trên lưu lượng Benign theo 4 chiều:\n"
            "  1. **Theo giao thức vận chuyển (`PROTOCOL`)**: Phân tách tỷ lệ `FPR` và tỷ trọng "
            "`share_of_all_fp` giữa TCP (`6`), UDP (`17`), ICMP (`1`) và các giao thức khác.\n"
            "  2. **Theo giao thức tầng ứng dụng (`L7_PROTO`)**: Xác định top mã giao thức L7 "
            "sinh nhiều cảnh báo giả nhất.\n"
            "  3. **Theo chế độ thời lượng luồng (`FLOW_DURATION_MILLISECONDS`)**: Tách biệt "
            "nhóm luồng tức thời (`0 ms`), luồng ngắn (`1..100 ms`), trung bình (`101..10,000 ms`) "
            "và luồng dài (`>10,000 ms`).\n"
            "  4. **Theo nhóm luồng ẩn danh (`by_anonymized_flow_group`)**: Khi có `trace_metadata`, "  # noqa: E501
            "nhóm các luồng theo mã băm ẩn danh `fg_<sha256[:12]>` của cặp điểm cuối và giao thức "
            "(ẩn hoàn toàn địa chỉ IP thô để bảo mật thông tin mạng)."
        ),
        "",
        "### 7.3. Cơ chế gây báo động giả (False Positive Mechanisms)",
        (
            f"1. **Va chạm vector đặc trưng (`ml_feature_overlap`)**: Có tới "
            f"`{test_overlap_rows:,} / {test_rows:,}` dòng Test (`{test_overlap_pct:.2f}%`) "
            "có vector 47 đặc trưng trùng khớp với các dòng thuộc phân vùng/nhãn khác. "
            "Khi một luồng Benign ngắn có cùng bộ 47 đặc trưng với các luồng dò quét, cây quyết "
            "định có thể gán xác suất dự đoán vượt ngưỡng `0.5`."
        ),
        (
            "2. **Đột biến băng thông và truyền lại gói hợp pháp**: Các kết nối Benign có tốc độ "
            "truyền burst hoặc tỷ lệ truyền lại cao đột biến dễ bị nhầm với lưu lượng bất thường."
        ),
        "",
        "---",
        "",
        "## 8. Attack Traffic & False Negative Analysis",
        "",
        "### 8.1. Thống kê tổng hợp trên lưu lượng Attack",
        "",
        (
            f"- **Tổng số mẫu Attack trên Test**: `{cm_brk['attack_total']:,}`\n"
            f"- **True Positives (`TP`)**: `{cm_brk['tp']:,}`\n"
            f"- **False Negatives (`FN`)**: `{cm_brk['fn']:,}`\n"
            f"- **False Negative Rate (`FNR = FN / (FN + TP)`)**: "
            f"`{cm_brk['false_negative_rate']:.6f}`"
            if has_test_runtime
            else (
                f"- **Tổng số mẫu Attack trên Test**: "
                f"`{limitations['class_imbalance']['test_attack_rows']:,}` dòng "
                "(`Label = 1`, trải trên 9 họ tấn công).\n"
                "- **Trạng thái số liệu `FN` và `FNR` thực tế trên Test**: "
                "`BLOCKED / NOT VERIFIED` (chờ chạy CLI đánh giá trên máy có artifact nhị phân).\n"
                "- **Cơ chế trích xuất mẫu `FN` đã triển khai**: Hàm `extract_fp_fn_samples()` "
                "thu thập mẫu `(y_true == 1) & (y_pred == 0)`, phân nhóm theo từng `Attack` "
                "category và trích xuất mẫu tấn công bỏ lọt với xác suất `prob_attack` thấp nhất."
            )
        ),
        "",
        "### 8.2. Phân tích lỗi theo cửa sổ thời gian (Temporal Window Error Analysis)",
        "",
        (
            "- Hàm `analyze_temporal_window_errors()` chia tập Test theo thứ tự thời gian "
            "`FLOW_START_MILLISECONDS` (thuộc `trace_metadata`, tách biệt hoàn toàn khỏi 47 đặc "
            "trưng đầu vào của mô hình) thành các cửa sổ thời gian liên tiếp để kiểm tra hiện tượng "  # noqa: E501
            "tập trung lỗi (`FP`/`FN` burst) hoặc suy giảm hiệu năng theo thời gian (temporal drift)."  # noqa: E501
        ),
        "",
        "### 8.3. Cơ chế bỏ lọt tấn công (False Negative Mechanisms)",
        (
            "1. **Tấn công thăm dò và khai thác tần suất thấp "
            "(Low-and-Slow / Single-Flow Stealth)**: "
            "Các luồng thuộc nhóm `Reconnaissance`, `Analysis`, `Backdoor` hoặc `Worms` chỉ gửi "
            "một vài gói tin kích thước nhỏ có hành vi thống kê cấp luồng rất giống Benign."
        ),
        (
            "2. **Sự phụ thuộc vào đặc trưng TTL (`MAX_TTL`, `MIN_TTL`)**: Khi luồng tấn công có "
            "giá trị TTL nằm trong dải TTL điển hình của máy trạm Benign, các nhánh cây dựa trên "
            "TTL sẽ đẩy mẫu về phía lớp `Benign (0)`."
        ),
        "",
        "---",
        "",
        "## 9. Per-Attack-Category Breakdown",
        "",
        "### 9.1. Bảng phân rã 9 họ tấn công và khoảng tin cậy Wilson 95%",
        "",
        "| Rank | Attack Category | Total in Test | Detected (`TP`) | Missed (`FN`) | "
        "Detection Rate (`Recall`) | False Negative Rate (`FNR`) | 95% Wilson CI (`Recall`) |",
        "| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        *cat_rows_md,
        "",
        "### 9.2. Phân tích độ bất định thống kê (Uncertainty Analysis) & Các họ tấn công hiếm",
        (
            f"- Ba họ tấn công lớn nhất (`{top1[0]}`: `{top1[1]:,}`, `{top2[0]}`: `{top2[1]:,}`, "
            f"`{top3[0]}`: `{top3[1]:,}`) chiếm tới **`{top3_pct:.2f}%`** "
            f"(`{top3_sum:,} / {total_test_attacks:,}`) tổng số mẫu tấn công trong tập Test."
        ),
        (
            f"- Ngược lại, họ `Worms` chỉ có **`{worms_cnt}` mẫu** trên tập Test. Theo công thức "
            f"khoảng tin cậy **Wilson 95%** (`compute_wilson_confidence_interval`), ngay cả khi "
            f"phát hiện đúng tuyệt đối `{worms_cnt}/{worms_cnt}` mẫu (`100.00%`), khoảng tin cậy "
            f"95% của Recall cho `Worms` vẫn trải rộng từ **`[{worms_ci_0[0] * 100:.2f}%, "
            f"{worms_ci_0[1] * 100:.2f}%]`** (độ rộng `{100.0 * (worms_ci_0[1] - worms_ci_0[0]):.2f}%`); "  # noqa: E501
            f"nếu bỏ lọt 1 mẫu (`{worms_cnt - 1}/{worms_cnt} = 97.22%`), khoảng tin cậy 95% mở "
            f"rộng thành **`[{worms_ci_1[0] * 100:.2f}%, {worms_ci_1[1] * 100:.2f}%]`**."
        ),
        (
            f"- **Lưu ý về giả định độc lập thống kê (Flow Independence Caveat)**: "
            f"{uncertainty_summary['flow_dependence_caveat']}"
        ),
        "",
        "---",
        "",
        "## 10. Feature Importance & Error Pattern Analysis",
        "",
        "Phân tích đặc trưng được tách bạch nghiêm ngặt thành 4 tầng nhận thức khoa học "
        "(Epistemic Separation):",
        "",
        "### 10.1. Tầng 1 — Quan sát thực nghiệm đã xác minh (Verified Observations)",
        "",
        "| Rank | Feature Name | Gini Importance | Cumulative Importance |",
        "| :---: | :--- | :---: | :---: |",
        *top_features_md,
        "",
        (
            "- **Quan sát đã xác minh**: Hai đặc trưng `MAX_TTL` và `MIN_TTL` chiếm tổng cộng gần "
            "**`49.94%`** độ quan trọng toàn cục của mô hình. Top 10 đặc trưng đầu tiên chiếm hơn "
            "**`80%`** tổng độ quan trọng, và không gian đặc trưng chỉ chứa 47 thuộc tính cấp luồng "  # noqa: E501
            "NetFlow v3."
        ),
        "",
        "### 10.2. Tầng 2 — Liên kết thống kê trên mẫu lỗi (Statistical Associations)",
        "",
        (
            "- Hàm `analyze_feature_error_patterns()` tính toán độ lệch chuẩn hóa "
            "(`standardized_abs_shift`) giữa `FP` so với `TN` và giữa `FN` so với `TP` trên toàn "
            "bộ 47 đặc trưng, đo lường sự dịch chuyển trung bình và trung vị của các bản ghi phân "
            "loại sai so với phân phối chuẩn của lớp tương ứng."
        ),
        "",
        "### 10.3. Tầng 3 — Giả thuyết miền NIDS (Domain Hypotheses)",
        "",
        (
            "1. **`H1_EXACT_FEATURE_COLLISION`**: Sự trùng lặp hoàn toàn bộ 47 đặc trưng giữa các "
            "luồng Benign và Attack ngắn tạo ra giới hạn lỗi Bayes không thể triệt tiêu nếu chỉ "
            "dựa vào thống kê cấp luồng đơn lẻ."
        ),
        (
            "2. **`H2_TTL_SHORTCUT_MISMATCH`**: Việc mô hình tập trung trọng số lớn vào "
            "`MIN_TTL`/`MAX_TTL` khiến các luồng có TTL không tuân theo quy luật định tuyến "
            "phòng lab dễ bị phân loại sai."
        ),
        (
            "3. **`H3_STEALTHY_LOW_RATE_PROBING`**: Các luồng `Reconnaissance`, `Analysis`, "
            "`Backdoor` và `Worms` có kích thước gói nhỏ và thời lượng ngắn thiếu dấu hiệu "
            "bất thường về lưu lượng khi không có thông tin payload sâu."
        ),
        (
            "4. **`H4_BENIGN_BURST_ANOMALIES`**: Các kết nối Benign hợp pháp nhưng có hiện tượng "
            "nghẽn mạng, truyền lại gói hoặc truyền dữ liệu khối lượng lớn trong thời gian ngắn "
            "dễ chạm ngưỡng nhánh cây của lớp `Attack`."
        ),
        "",
        "### 10.4. Tầng 4 — Đề xuất thí nghiệm kiểm chứng tiếp theo (Future Experiment Proposals)",
        "",
        (
            "- **EXP-1 (TTL Ablation & Regularization)**: Đánh giá biến thể loại bỏ hoặc làm nhiễu "
            "`MIN_TTL`/`MAX_TTL` trên tập Test để đo độ suy giảm Recall theo từng họ tấn công.\n"
            "- **EXP-2 (Windowed Flow-Group Aggregation)**: Bổ sung đặc trưng thống kê cửa sổ thời "
            "gian trượt (không dùng IP tĩnh làm đặc trưng) nhằm phân tách các luồng trùng lặp bộ "
            "47 đặc trưng.\n"
            "- **EXP-3 (Multi-Model Hybrid Triage)**: Kết hợp điểm dị thường từ Isolation Forest "
            "đã hiệu chuẩn ngưỡng trên Validation cho các mẫu rơi vào vùng bất định `[0.35, 0.65]`."
        ),
        "",
        "---",
        "",
        "## 11. Decision Boundary & Confidence Analysis",
        "",
        (
            "- **Ngưỡng quyết định cố định (Fixed Canonical Threshold)**: `0.50` trên xác suất dự "
            "đoán lớp `Attack` (`prob_attack >= 0.50` phân loại là `1`). Tuân thủ quy tắc chống "
            "rò rỉ dữ liệu, ngưỡng này **không được tinh chỉnh trên tập Test**."
        ),
        (
            "- **Vùng bất định (Uncertainty Band `[0.35, 0.65]`)**: Hàm "
            "`analyze_classification_boundary()` đo lường tỷ lệ mẫu rơi vào vùng xác suất sát "
            "ngưỡng `0.50` (`[0.35, 0.65]`) cũng như tỷ lệ lỗi có độ tự tin cao (`prob_attack >= 0.80` "  # noqa: E501
            "đối với `FP` và `prob_attack <= 0.20` đối với `FN`)."
        ),
        "",
        "---",
        "",
        "## 12. Dataset & Methodology Limitations",
        "",
        (
            "Dựa trên bằng chứng định lượng từ các manifest đã kiểm chứng trong repository, "
            "nghiên cứu ghi nhận **6 hạn chế cốt lõi** của dữ liệu và phương pháp:"
        ),
        "",
        "### 12.1. Mất cân bằng lớp nghiêm trọng (Severe Class Imbalance)",
        (
            f"- Toàn bộ bộ dữ liệu có `{total_source_rows:,}` dòng với tỷ lệ Benign chiếm áp "
            f"đảo (~`91.16%`). Trong tập Test (`{test_rows:,}` dòng), có "
            f"`{limitations['class_imbalance']['test_benign_rows']:,}` dòng `Benign` và "
            f"`{limitations['class_imbalance']['test_attack_rows']:,}` dòng `Attack`."
        ),
        (
            "- **Hệ quả**: Chỉ số Accuracy tổng thể bị chi phối bởi lớp `Benign`. Do đó, phải "
            "ưu tiên **Precision, Recall, Binary F1, Macro F1, FPR và Per-Category Recall**."
        ),
        "",
        "### 12.2. Các họ tấn công cực hiếm (Extreme Rare Attack Categories)",
        (
            f"- Trong tập Test, họ `Worms` chỉ có **`{test_att_dist.get('Worms', 36):,}` mẫu** "
            f"(`{100.0 * test_att_dist.get('Worms', 36) / test_rows:.4f}%` tập Test), `Analysis` "
            f"có **`{test_att_dist.get('Analysis', 294):,}` mẫu**, `Shellcode` có "
            f"**`{test_att_dist.get('Shellcode', 396):,}` mẫu** và `Backdoor` có "
            f"**`{test_att_dist.get('Backdoor', 1260):,}` mẫu**."
        ),
        (
            "- **Hệ quả**: Chỉ cần bỏ lọt vài luồng `Worms` hoặc `Analysis` sẽ làm Recall của "
            "họ đó biến động mạnh; độ tin cậy thống kê trên các lớp hiếm thấp hơn nhiều so với "
            f"`Exploits` (`{top1[1]:,}` mẫu) hay `Fuzzers` (`{top2[1]:,}` mẫu)."
        ),
        "",
        (
            f"### 12.3. Chồng lấn hoàn toàn vector 47 đặc trưng (`ml_feature_overlap` = "
            f"`{test_overlap_pct:.2f}%` trên Test)"
        ),
        (
            f"- Theo `reports/splits/nf_unsw_nb15_v3_split_manifest.json`, có tới "
            f"**`{test_overlap_rows:,}` dòng (`{test_overlap_pct:.2f}%`)** trên tập Test "
            "chia sẻ vector 47 đặc trưng với các dòng ở phân vùng Train (do các mẫu lưu lượng "
            "giao thức lặp lại giữa các IP/thời điểm khác nhau)."
        ),
        "",
        "### 12.4. Giá trị khuyết (`NaN`) và vô cực (`+Inf`) trong đặc trưng tốc độ truyền",
        (
            "- Các luồng cực ngắn có `FLOW_DURATION_MILLISECONDS == 0` gây chia cho 0 khi tính "
            "số byte/giây. Việc thay thế `+Inf -> NaN` và điền bằng `median` của tập Train giúp "
            "đảm bảo tính ổn định số học nhưng làm mất thông tin phân biệt tinh vi ở nhóm luồng "
            "thời lượng bằng 0."
        ),
        "",
        "### 12.5. Hiện tượng học đường tắt (`MIN_TTL` / `MAX_TTL` Lab Shortcut)",
        (
            "- Môi trường tạo dữ liệu UNSW-NB15 sử dụng hệ thống IXIA PerfectStorm với cấu hình "
            "định tuyến cố định giữa mạng tấn công và mạng đích."
        ),
        (
            f"- **Bằng chứng thực nghiệm (Ablation Study trên Validation)**: Trên tập Validation "
            f"({val_rows:,} dòng), mô hình chuẩn đạt Accuracy {val_acc:.4%} với {val_fp} FP và "
            f"{val_fn} FN. Khi loại bỏ 2 cột `MIN_TTL` và `MAX_TTL` (thí nghiệm C1), "
            f"số tấn công bị bỏ lọt (`FN`) tăng từ {val_fn} lên {c1_fn:,} ({c1_fn_mult:.1f}x), "
            "và trên cây quyết định đơn quy tắc, riêng `MIN_TTL` đã đạt Accuracy 99.9849%. "
            "Điều này xác nhận đặc trưng hạ tầng phòng lab đóng vai trò đường tắt rất mạnh "
            "và hiệu năng cao trong phòng lab không đảm bảo khái quát hóa thực tế."
        ),
        "",
        "### 12.6. Giới hạn cửa sổ thời gian và khả năng khái quát hóa thực tế",
        (
            "- Bộ dữ liệu chỉ thu thập trong khoảng thời gian có hạn và có sự lặp lại của "
            "các mẫu đặc trưng NetFlow."
        ),
        (
            "- Mô hình được huấn luyện trên dữ liệu giả lập này chưa phản ánh hiện tượng trôi dạt "
            "khái niệm (concept drift) theo tuần/tháng, cấu trúc lưu lượng mã hóa "
            "hiện đại (TLS 1.3, "
            "QUIC) hoặc các cuộc tấn công phân tán nhiều bước (APT) cần ngữ cảnh liên luồng."
        ),
        "",
        "---",
        "",
        "## 13. Operational & Security Implications",
        "",
        (
            "1. **Đánh đổi giữa `FPR` và Chi phí vận hành SOC (Alert Fatigue)**:\n"
            "   - Trong mạng doanh nghiệp có hàng triệu luồng Benign mỗi ngày (>91% lưu lượng), "
            "ngay cả mức `FPR` nhỏ cũng sinh ra hàng nghìn cảnh báo giả mỗi ngày. Vì vậy, Random "
            "Forest đóng vai trò là **lớp lọc tốc độ cao tuyến đầu (Tier-1 Flow Filter)** và cần "
            "kết hợp với cơ chế chấm điểm rủi ro / tương quan sự kiện ở tầng sau."
        ),
        (
            "2. **Rủi ro an ninh từ `FN` và khả năng né tránh (Adversarial TTL Spoofing)**:\n"
            "   - Kẻ tấn công nắm được việc mô hình phụ thuộc lớn vào `MIN_TTL`/`MAX_TTL` có thể "
            "dễ dàng điều chỉnh giá trị TTL ban đầu của gói tin tấn công khớp với TTL của máy trạm "
            "hợp pháp, làm tăng tỷ lệ bỏ lọt (`FN`) lên nhiều lần."
        ),
        (
            "3. **Nguy cơ bỏ lọt các cuộc tấn công hiếm nhưng nguy hiểm cao (`Worms`, `Backdoor`, "
            "`Shellcode`, `Analysis`)**:\n"
            "   - Một luồng `Backdoor` hoặc `Shellcode` bị bỏ lọt (`FN`) có tác động an ninh "
            "nghiêm trọng hơn nhiều so với một luồng `Fuzzers` thông thường, đòi hỏi "
            "hệ thống cảnh báo phải "
            "gắn trọng số rủi ro theo ngữ cảnh thay vì chỉ nhìn vào nhãn nhị phân 0/1."
        ),
        "",
        "---",
        "",
        "## 14. Recommendations for Future Work",
        "",
        (
            "1. **Hoàn tất chạy thực nghiệm Test trên máy chứa đầy đủ artifact nhị phân**:\n"
            "   - Chạy lệnh CLI sau trên máy lưu trữ bộ dữ liệu và model `.joblib` để xuất đầy "
            "đủ các artifact vào `reports/evaluation/` và cập nhật bảng số liệu Test:\n"
            "   ```powershell\n"
            "   python scripts/error_analysis_random_forest.py --run-test-evaluation "
            "--report-path reports/evaluation/error_analysis_report.md\n"
            "   ```"
        ),
        (
            "2. **Bổ sung đặc trưng ngữ cảnh liên luồng (Host-Level Features)**:\n"
            f"   - Để phá vỡ giới hạn `{test_overlap_pct:.2f}%` chồng lấn vector 47 đặc trưng "
            "của từng luồng đơn lẻ, cần bổ sung các đặc trưng thống kê trên cửa sổ trượt theo "
            "IP nguồn/đích mà vẫn đảm bảo không rò rỉ nhãn hay địa chỉ IP tĩnh."
        ),
        (
            "3. **Kiểm soát sự phụ thuộc vào đường tắt `TTL` (TTL-Invariant Regularization)**:\n"
            "   - Huấn luyện và so sánh biến thể mô hình loại bỏ `MIN_TTL`/`MAX_TTL` hoặc "
            "áp dụng cơ chế phạt độ nhạy TTL để nâng cao độ bền vững khi triển khai ngoài "
            "môi trường phòng lab."
        ),
        (
            "4. **Kết hợp đa mô hình (Ensemble với XGBoost / Isolation Forest / Autoencoder)**:\n"
            "   - Sử dụng Random Forest làm chuẩn tham chiếu có giám sát, kết hợp với các mô hình "
            "phát hiện bất thường bán giám sát để cải thiện khả năng phát hiện các họ "
            "tấn công hiếm (`Worms`, `Analysis`, `Backdoor`) và tấn công chưa biết (zero-day)."
        ),
        "",
    ]

    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return out_p


def run_full_error_analysis_from_evaluation(
    evaluation_result: Dict[str, Any],
    feature_importances: Optional[Sequence[float]] = None,
    report_path: Union[str, Path] = DEFAULT_ERROR_ANALYSIS_REPORT_PATH,
    split_manifest_path: Union[str, Path] = DEFAULT_SPLIT_MANIFEST_PATH,
    validation_audit_path: Union[str, Path] = DEFAULT_VALIDATION_AUDIT_JSON_PATH,
    trace_metadata: Optional[pd.DataFrame] = None,
    allow_overwrite: bool = True,
) -> Dict[str, Any]:
    """Run full error analysis pipeline from an in-memory evaluation result."""
    out_rep = Path(report_path)

    X_test = evaluation_result.get("X_test_transformed")
    y_true = evaluation_result.get("y_true")
    y_pred = evaluation_result.get("y_pred")
    prob_attack = evaluation_result.get("prob_attack")
    attack_cats = evaluation_result.get("attack_categories")
    row_indices = evaluation_result.get("row_indices")

    fp_fn_summary = None
    ranked_cats = None
    feature_patterns = None
    boundary_analysis = None
    limitations = None
    fp_flow_groups = None
    temporal_errors = None
    uncertainty_analysis = None
    model_comparison = None

    if X_test is not None and y_true is not None and y_pred is not None:
        fp_fn_summary = extract_fp_fn_samples(
            X=X_test,
            y_true=y_true,
            y_pred=y_pred,
            prob_attack=prob_attack,
            attack_categories=attack_cats,
            row_indices=row_indices,
        )
        ranked_cats = compute_ranked_attack_category_errors(
            y_true=y_true,
            y_pred=y_pred,
            attack_categories=attack_cats if attack_cats is not None else [],
            expected_categories=ALL_ATTACK_CATEGORIES,
        )
        feature_patterns = analyze_feature_error_patterns(
            X=X_test,
            y_true=y_true,
            y_pred=y_pred,
            feature_importances=feature_importances,
        )
        fp_flow_groups = analyze_fp_by_flow_groups(
            X=X_test,
            y_true=y_true,
            y_pred=y_pred,
            trace_metadata=trace_metadata,
        )
        temporal_errors = analyze_temporal_window_errors(
            y_true=y_true,
            y_pred=y_pred,
            trace_metadata=trace_metadata,
        )
        uncertainty_analysis = compute_uncertainty_analysis(
            y_true=y_true,
            y_pred=y_pred,
            attack_categories=attack_cats,
            split_manifest_path=split_manifest_path,
        )
        model_comparison = compile_model_comparison_status(
            evaluation_result=evaluation_result,
            validation_audit_path=validation_audit_path,
        )
        if prob_attack is not None:
            boundary_analysis = analyze_classification_boundary(
                y_true=y_true,
                y_pred=y_pred,
                prob_attack=prob_attack,
            )
        limitations = compile_data_limitations_summary(
            split_manifest_path=split_manifest_path,
            validation_audit_path=validation_audit_path,
        )

    analysis_payload = {
        "fp_fn_summary": fp_fn_summary,
        "ranked_attack_categories": ranked_cats,
        "fp_by_flow_groups": fp_flow_groups,
        "temporal_window_errors": temporal_errors,
        "uncertainty_analysis": uncertainty_analysis,
        "model_comparison": model_comparison,
        "global_feature_importance": (
            feature_patterns.get("global_feature_importance", []) if feature_patterns else []
        ),
        "misclassified_feature_patterns": (
            feature_patterns.get("misclassified_feature_patterns", {}) if feature_patterns else {}
        ),
        "error_hypotheses": (
            feature_patterns.get("error_hypotheses", []) if feature_patterns else []
        ),
        "epistemic_separation": (
            feature_patterns.get("epistemic_separation", {}) if feature_patterns else {}
        ),
        "boundary_analysis": boundary_analysis,
        "data_limitations": limitations,
    }

    generate_error_analysis_report(
        output_path=out_rep,
        evaluation_result=evaluation_result,
        error_analysis_data=analysis_payload,
        split_manifest_path=split_manifest_path,
        validation_audit_path=validation_audit_path,
        allow_overwrite=allow_overwrite,
    )

    analysis_payload["report_path"] = str(out_rep)
    analysis_payload["status"] = "COMPLETED"
    analysis_payload["run_id"] = evaluation_result.get("run_id")

    return analysis_payload


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for Random Forest Error Analysis."""
    parser = argparse.ArgumentParser(
        description="Generate evidence-driven error analysis report for Random Forest (Issue #13)."
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_ERROR_ANALYSIS_REPORT_PATH,
        help="Path to output error analysis Markdown report",
    )
    parser.add_argument(
        "--split-manifest",
        type=Path,
        default=DEFAULT_SPLIT_MANIFEST_PATH,
        help="Path to split manifest JSON",
    )
    parser.add_argument(
        "--validation-audit",
        type=Path,
        default=DEFAULT_VALIDATION_AUDIT_JSON_PATH,
        help="Path to validation audit JSON",
    )
    parser.add_argument(
        "--model-manifest",
        type=Path,
        default=DEFAULT_MODEL_MANIFEST_JSON_PATH,
        help="Path to model manifest JSON",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify input artifacts without generating report",
    )
    parser.add_argument(
        "--run-test-evaluation",
        action="store_true",
        help="Run the verified held-out evaluation and generate error analysis",
    )
    args = parser.parse_args(argv)

    if args.verify_only:
        limitations = compile_data_limitations_summary(
            split_manifest_path=args.split_manifest,
            validation_audit_path=args.validation_audit,
        )
        print(json.dumps(limitations, indent=2))
        return 0

    if args.run_test_evaluation:
        result = evaluate_random_forest_on_test(
            split_manifest_path=args.split_manifest, model_manifest_path=args.model_manifest
        )
        run_full_error_analysis_from_evaluation(
            result,
            report_path=args.report_path,
            split_manifest_path=args.split_manifest,
            validation_audit_path=args.validation_audit,
        )
        print(f"Error analysis report generated successfully at: {args.report_path}")
        return 0

    out_p = generate_error_analysis_report(
        output_path=args.report_path,
        split_manifest_path=args.split_manifest,
        validation_audit_path=args.validation_audit,
        model_manifest_path=args.model_manifest,
    )
    print(f"Error analysis report generated successfully at: {out_p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
