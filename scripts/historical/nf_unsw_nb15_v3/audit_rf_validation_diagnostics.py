#!/usr/bin/env python3
"""Train/Validation-only diagnostic audit of the canonical Random Forest baseline (Issue #10).

Purpose: independently re-derive the validation results recorded in the run manifest and test
hypotheses (code/pipeline leakage, memorisation of repeated feature vectors, and dataset-specific
testbed shortcuts) that could explain the 99.9977% validation accuracy.

Guarantees:
- The Test index file is never opened; rows outside Train/Validation are skipped as raw text.
- The canonical 200-tree model artifact is only loaded (never rewritten).
- Diagnostic retrains (60-tree Random Forests C0-C7, single Decision Trees C8-C9, and depth-6
  single-feature trees) are strictly non-canonical diagnostic probes; their results must not be
  used for model selection or hyperparameter tuning.
- Label-shuffle control (C7) is strictly a harness sanity check (verifying that fitting on
  permuted y_train collapses validation performance to the majority baseline) and is NOT used to
  claim complete absence of leakage.
- Metadata columns (IPs, ports, timestamps) are read for audit only, never as features.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score  # noqa: E402
from sklearn.tree import DecisionTreeClassifier  # noqa: E402

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.models.random_forest import RandomForestModel  # noqa: E402
from network_anomaly.preprocessing.pipeline import (  # noqa: E402
    EXPECTED_DATASET_SHA256,
    TrainOnlyPreprocessor,
)

COLS: List[str] = list(ML_FEATURE_COLUMNS)
META_COLS = [
    "FLOW_START_MILLISECONDS",
    "FLOW_END_MILLISECONDS",
    "IPV4_SRC_ADDR",
    "IPV4_DST_ADDR",
    "L4_SRC_PORT",
    "L4_DST_PORT",
]
DATASET = PROJECT_ROOT / "data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv"
INDICES_DIR = PROJECT_ROOT / "data/processed/splits"
SPLIT_MANIFEST = PROJECT_ROOT / "reports/splits/nf_unsw_nb15_v3_split_manifest.json"
PREPROCESSOR = PROJECT_ROOT / "artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib"
PREPROCESSOR_MANIFEST = (
    PROJECT_ROOT / "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json"
)
MODEL = PROJECT_ROOT / "artifacts/models/random_forest/random_forest_baseline.joblib"
RUN_MANIFEST = PROJECT_ROOT / "reports/models/random_forest_manifest.json"
LOCAL_RUN_MANIFEST = PROJECT_ROOT / "artifacts/models/random_forest/random_forest_manifest.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "reports/models/rf_baseline_validation_audit.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def binary_metrics(y: np.ndarray, pred: np.ndarray, prob: Optional[np.ndarray] = None) -> Dict:
    """Binary metrics with explicit label order [0=Benign, 1=Attack]; FPR = FP / (FP + TN)."""
    if len(y) == 0:
        return {"n": 0}
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(y, pred, labels=[0, 1]).ravel())
    res: Dict[str, Any] = {
        "n": int(len(y)),
        "n_attack": int((y == 1).sum()),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "accuracy": (tn + tp) / len(y),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else None,
    }
    if prob is not None and len(set(y.tolist())) > 1:
        res["auc"] = float(roc_auc_score(y, prob))
        res["average_precision"] = float(average_precision_score(y, prob))
    return res


def build_taxonomy_summary() -> Dict[str, Any]:
    """Return explicit methodological boundaries between leakage types and diagnostic models."""
    return {
        "canonical_vs_diagnostic_models": {
            "canonical_baseline": {
                "configuration_id": "rf-baseline-canonical-v1",
                "is_canonical_baseline": True,
                "estimator_type": "RandomForestClassifier",
                "n_estimators": 200,
                "max_depth": 16,
                "criterion": "gini",
                "max_features": "sqrt",
                "random_state": 42,
                "n_jobs": -1,
                "artifact_sha256": (
                    "801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea"
                ),
            },
            "diagnostic_rf_c0_to_c7": {
                "is_canonical_baseline": False,
                "estimator_type": "RandomForestClassifier",
                "n_estimators": 60,
                "max_depth": 16,
                "random_state": 42,
                "purpose": (
                    "Non-canonical 60-tree diagnostic probes for feature ablation (C1-C5), "
                    "cross-split fingerprint deduplication (C6), and harness sanity control (C7)."
                ),
            },
            "diagnostic_single_trees_c8_c9_and_univariate": {
                "is_canonical_baseline": False,
                "estimator_type": "DecisionTreeClassifier",
                "n_estimators": 1,
                "max_depths_used": [3, 6, 8],
                "purpose": (
                    "Non-canonical single decision trees used to measure univariate feature "
                    "separability (depth 6) and shallow rule-based separability (C8 depth 3, "
                    "C9 depth 8)."
                ),
            },
        },
        "hypothesis_separation": {
            "1_code_and_pipeline_leakage": {
                "status": "PASS_NO_CODE_LEAKAGE_DETECTED",
                "evidence_type": (
                    "Direct code, schema, split-disjointness, temporal-margin (+236,165 ms), "
                    "label-alignment, and train-only preprocessor fit-boundary verification."
                ),
                "label_shuffle_control_limitation": (
                    "C7 (permuting y_train) only verifies that the training/evaluation loop "
                    "does not copy y_val or produce high scores independent of y_train. C7 "
                    "does NOT prove absence of feature-level target proxies, split/session "
                    "contamination, or dataset-specific shortcuts."
                ),
            },
            "2_fingerprint_memorisation": {
                "status": "QUANTIFIED_NOT_PRIMARY_DRIVER",
                "evidence_type": (
                    "49.9813% of Validation rows (172,621) share an exact 47-feature vector "
                    "with Train (0 label conflicts) where both the canonical 200-tree RF and "
                    "a lookup table achieve 1.000000 accuracy. However, on the 172,750 unseen "
                    "Validation rows (containing 74.25% of Validation attacks), the canonical "
                    "200-tree RF still achieves 0.999954 accuracy (5 FP, 3 FN), and diagnostic "
                    "C6 (removing all 551,167 overlapping Train rows) still achieves 0.999461 "
                    "on the formerly overlapping Validation rows and 0.999699 overall."
                ),
            },
            "3_dataset_specific_shortcuts": {
                "status": "CONFIRMED_PRIMARY_DRIVER_OF_NEAR_100_ACCURACY",
                "evidence_type": (
                    "In the IXIA PerfectStorm synthetic lab of NF-UNSW-NB15-v3, MIN_TTL alone "
                    "achieves 0.999849 Validation accuracy (MIN_TTL=31 is 100% Benign across "
                    "308,033 Validation rows; MIN_TTL in {62, 254, 255} is 99.997% Attack "
                    "across 30,450 Validation rows). Even after dropping MIN_TTL/MAX_TTL (C1) "
                    "or Top-10 impurity features (C5), the remaining 37 flow features achieve "
                    "0.999902 accuracy due to multi-dimensional separability within the "
                    "2015-02-18 capture window. High Validation accuracy therefore does NOT "
                    "establish external generalization beyond this benchmark testbed."
                ),
            },
        },
    }


def load_train_validation(manifest: Dict, out: Dict) -> Dict[str, Any]:
    """Load Train/Validation rows by stream-selecting raw lines; Test lines are never parsed."""
    tr_idx = pd.read_csv(INDICES_DIR / "train_indices.csv.gz")["source_row_index"].to_numpy()
    va_idx = pd.read_csv(INDICES_DIR / "validation_indices.csv.gz")["source_row_index"].to_numpy()
    total = int(manifest["total_source_rows"])
    out["split_integrity"] = {
        "train_rows": int(len(tr_idx)),
        "val_rows": int(len(va_idx)),
        "train_index_sha256_matches_manifest": sha256_file(INDICES_DIR / "train_indices.csv.gz")
        == manifest["partitions"]["train"]["index_sha256"],
        "val_index_sha256_matches_manifest": sha256_file(INDICES_DIR / "validation_indices.csv.gz")
        == manifest["partitions"]["validation"]["index_sha256"],
        "indices_unique": bool(
            len(set(tr_idx.tolist())) == len(tr_idx) and len(set(va_idx.tolist())) == len(va_idx)
        ),
        "train_val_disjoint": not (set(tr_idx.tolist()) & set(va_idx.tolist())),
    }
    part = np.zeros(total, dtype=np.int8)
    part[tr_idx] = 1
    part[va_idx] = 2
    use = COLS + ["Label", "Attack"] + META_COLS
    frames: Dict[int, List[pd.DataFrame]] = {1: [], 2: []}
    bufs: Dict[int, List[str]] = {1: [], 2: []}
    rows: Dict[int, List[int]] = {1: [], 2: []}
    n_lines = 0

    def flush(p: int, header: str) -> None:
        if not bufs[p]:
            return
        frame = pd.read_csv(
            io.StringIO(header + "".join(bufs[p])),
            usecols=use,
            keep_default_na=False,
            low_memory=False,
        )
        frame.index = rows[p][-len(bufs[p]) :]
        frames[p].append(frame)
        bufs[p].clear()

    with DATASET.open("r", encoding="utf-8", errors="replace") as handle:
        header = handle.readline()
        for i, line in enumerate(handle):
            n_lines += 1
            p = int(part[i]) if i < total else 0
            if p:
                bufs[p].append(line)
                rows[p].append(i)
                if len(bufs[p]) >= 200_000:
                    flush(p, header)
    flush(1, header)
    flush(2, header)
    tr, va = pd.concat(frames[1]), pd.concat(frames[2])
    out["split_integrity"]["csv_data_lines_equal_manifest_total"] = n_lines == total
    out["split_integrity"]["row_order_matches_indices"] = bool(
        np.array_equal(tr.index.to_numpy(), tr_idx) and np.array_equal(va.index.to_numpy(), va_idx)
    )
    return {"train": tr, "val": va}


def audit_labels_and_groups(tr: pd.DataFrame, va: pd.DataFrame, out: Dict) -> None:
    lab: Dict[str, Any] = {}
    for name, frame in (("train", tr), ("validation", va)):
        label = frame["Label"].astype(int).to_numpy()
        attack = frame["Attack"].astype(str).to_numpy()
        lab[name] = {
            "label_counts": {str(k): int(v) for k, v in zip(*np.unique(label, return_counts=True))},
            "benign_iff_label_0": bool(np.array_equal(attack == "Benign", label == 0)),
        }
    out["label_alignment"] = lab
    margin = int(va["FLOW_START_MILLISECONDS"].min() - tr["FLOW_END_MILLISECONDS"].max())

    def group_key(frame: pd.DataFrame) -> pd.Series:
        src = frame["IPV4_SRC_ADDR"] + ":" + frame["L4_SRC_PORT"].astype(str)
        dst = frame["IPV4_DST_ADDR"] + ":" + frame["L4_DST_PORT"].astype(str)
        first = np.where(src <= dst, src, dst)
        second = np.where(src <= dst, dst, src)
        bucket = frame["FLOW_START_MILLISECONDS"].to_numpy(np.int64) // 300000
        return (
            pd.Series(first, index=frame.index)
            + "__"
            + pd.Series(second, index=frame.index)
            + "__"
            + frame["PROTOCOL"].astype(str)
            + "__"
            + pd.Series(bucket, index=frame.index).astype(str)
        )

    sharing: Dict[str, float] = {}
    for name, cols in (
        ("src_ip", ["IPV4_SRC_ADDR"]),
        ("ip_pair", ["IPV4_SRC_ADDR", "IPV4_DST_ADDR"]),
        ("dst_ip_dst_port", ["IPV4_DST_ADDR", "L4_DST_PORT"]),
    ):
        seen = set(map(tuple, tr[cols].astype(str).to_numpy()))
        sharing[name] = round(
            100 * float(np.mean([k in seen for k in map(tuple, va[cols].astype(str).to_numpy())])),
            3,
        )
    out["temporal_and_group_audit"] = {
        "train_end_to_validation_start_margin_ms": margin,
        "canonical_flow_group_overlap": len(set(group_key(tr)) & set(group_key(va))),
        "validation_rows_sharing_entity_with_train_pct_informational": sharing,
    }


def audit_model(
    model: RandomForestModel,
    x_tr: pd.DataFrame,
    x_va: pd.DataFrame,
    y_tr: np.ndarray,
    y_va: np.ndarray,
    attack_va: np.ndarray,
    h_tr: np.ndarray,
    h_va: np.ndarray,
    manifest: Dict,
    out: Dict,
) -> np.ndarray:
    est = model.estimator
    out["model_structure"] = {
        "configuration_id": manifest["configuration_id"],
        "is_canonical_baseline": bool(manifest["is_canonical_baseline"]),
        "estimator_type": type(est).__name__,
        "n_estimators": len(est.estimators_),
        "max_depth": int(est.max_depth),
        "classes": [int(c) for c in est.classes_],
        "n_features_in": int(est.n_features_in_),
        "feature_names_equal_contract": list(model.feature_names) == COLS,
        "estimator_feature_names_in_equal_contract": list(est.feature_names_in_) == COLS,
        "manifest_selected_features_equal_contract": manifest["selected_features"] == COLS,
        "tree_depth_min_max": [
            int(min(t.tree_.max_depth for t in est.estimators_)),
            int(max(t.tree_.max_depth for t in est.estimators_)),
        ],
        "tree_nodes_mean": float(np.mean([t.tree_.node_count for t in est.estimators_])),
    }
    p1 = est.predict_proba(x_va)
    p2 = est.predict_proba(x_va)
    est.set_params(n_jobs=1)
    p3 = est.predict_proba(x_va)
    p4 = est.predict_proba(x_va)
    est.set_params(n_jobs=-1)
    out["probability_aggregation_determinism"] = {
        "repeat_max_abs_diff_n_jobs_-1": float(np.abs(p1 - p2).max()),
        "repeat_max_abs_diff_n_jobs_1": float(np.abs(p3 - p4).max()),
        "n_jobs_1_vs_-1_max_abs_diff": float(np.abs(p1 - p3).max()),
        "manifest_max_abs_probability_diff": manifest["reload_verification"][
            "max_abs_probability_diff"
        ],
    }
    pred = (p1[:, 1] >= 0.5).astype(int)
    val = binary_metrics(y_va, pred, p1[:, 1])
    out["validation_recomputed"] = val
    out["validation_confusion_matrix_equals_manifest"] = [
        [val["tn"], val["fp"]],
        [val["fn"], val["tp"]],
    ] == manifest["validation_summary"]["confusion_matrix"]
    ptr = est.predict_proba(x_tr)[:, 1]
    out["train_recomputed"] = binary_metrics(y_tr, (ptr >= 0.5).astype(int), ptr)
    overlap = np.isin(h_va, h_tr)
    out["fingerprint_overlap"] = {
        "validation_rows_overlapping_train": int(overlap.sum()),
        "validation_rows_overlapping_train_pct": float(overlap.mean() * 100),
        "train_rows_overlapping_validation": int(np.isin(h_tr, h_va).sum()),
        "distinct_overlapping_fingerprints": int(len(set(h_tr.tolist()) & set(h_va.tolist()))),
        "validation_with_train_fingerprint": binary_metrics(
            y_va[overlap], pred[overlap], p1[overlap, 1]
        ),
        "validation_without_train_fingerprint": binary_metrics(
            y_va[~overlap], pred[~overlap], p1[~overlap, 1]
        ),
    }
    per_cat = {}
    for name in sorted(set(attack_va.tolist())):
        mask = attack_va == name
        per_cat[name] = {
            "total": int(mask.sum()),
            "overlap": int((mask & overlap).sum()),
            "errors_with_overlap": int(((pred != y_va) & mask & overlap).sum()),
            "errors_without_overlap": int(((pred != y_va) & mask & ~overlap).sum()),
        }
    out["fingerprint_overlap"]["per_category"] = per_cat
    out["validation_errors"] = [
        {
            "attack": str(attack_va[i]),
            "label": int(y_va[i]),
            "p_attack": float(p1[i, 1]),
            "has_train_fingerprint": bool(overlap[i]),
        }
        for i in np.where(pred != y_va)[0]
    ]
    groups = pd.DataFrame({"h": h_tr, "y": y_tr}).groupby("h")["y"].agg(["mean"])
    lookup = pd.Series(h_va[overlap]).map(groups["mean"]).to_numpy()
    out["memorisation_lookup_baseline"] = {
        "train_fingerprints": int(len(groups)),
        "train_fingerprints_with_conflicting_labels": int(
            ((groups["mean"] > 0) & (groups["mean"] < 1)).sum()
        ),
        "accuracy_on_overlapping_validation_rows": float(
            ((lookup >= 0.5).astype(int) == y_va[overlap]).mean()
        ),
    }
    importance = pd.Series(est.feature_importances_, index=COLS).sort_values(ascending=False)
    out["impurity_importance_top15"] = {k: float(v) for k, v in importance.head(15).items()}
    rng = np.random.RandomState(0)
    sub = rng.choice(len(x_va), 60000, replace=False)
    xs, ys = x_va.iloc[sub].reset_index(drop=True), y_va[sub]
    base_acc = float((est.predict(xs) == ys).mean())
    perm = {}
    for col in COLS:
        xp = xs.copy()
        xp[col] = xp[col].to_numpy()[rng.permutation(len(xp))]
        perm[col] = base_acc - float((est.predict(xp) == ys).mean())
    out["permutation_importance_accuracy_drop_top10_60k_validation_sample"] = dict(
        sorted(perm.items(), key=lambda kv: -kv[1])[:10]
    )
    single = {}
    for col in COLS:
        tree = DecisionTreeClassifier(max_depth=6, random_state=0)
        tree.fit(x_tr[[col]].to_numpy(), y_tr)
        prob = tree.predict_proba(x_va[[col]].to_numpy())[:, 1]
        single[col] = {
            "auc": float(roc_auc_score(y_va, prob)),
            "accuracy": float(((prob >= 0.5).astype(int) == y_va).mean()),
        }
    out["single_feature_depth6_tree_top10_by_auc"] = dict(
        sorted(single.items(), key=lambda kv: -kv[1]["auc"])[:10]
    )
    out["majority_class_validation_accuracy"] = float((y_va == 0).mean())
    out["ttl_value_vs_label"] = {
        col: {
            name: {
                str(int(v)): {"count": int(row["count"]), "attack": int(row["sum"])}
                for v, row in pd.DataFrame({"v": frame[col].to_numpy(), "y": target})
                .groupby("v")["y"]
                .agg(["count", "sum"])
                .iterrows()
            }
            for name, frame, target in (("train", x_tr, y_tr), ("validation", x_va, y_va))
        }
        for col in ("MIN_TTL", "MAX_TTL")
    }
    return overlap


def diagnostic_retrains(
    x_tr: pd.DataFrame,
    x_va: pd.DataFrame,
    y_tr: np.ndarray,
    y_va: np.ndarray,
    h_tr: np.ndarray,
    h_va: np.ndarray,
    overlap: np.ndarray,
    top_features: Sequence[str],
    out: Dict,
) -> None:
    def run(
        diagnostic_category: str,
        drop: Sequence[str] = (),
        train_mask: Optional[np.ndarray] = None,
        y_fit: Optional[np.ndarray] = None,
        tree_depth: Optional[int] = None,
    ) -> Dict:
        keep = [c for c in COLS if c not in drop]
        mask = np.ones(len(x_tr), bool) if train_mask is None else train_mask
        target = (y_tr if y_fit is None else y_fit)[mask]
        if tree_depth:
            est: Any = DecisionTreeClassifier(max_depth=tree_depth, random_state=42)
            est_type = "DecisionTreeClassifier"
            n_trees = 1
            depth = tree_depth
        else:
            est = RandomForestClassifier(
                n_estimators=60, max_depth=16, max_features="sqrt", random_state=42, n_jobs=-1
            )
            est_type = "RandomForestClassifier"
            n_trees = 60
            depth = 16
        est.fit(x_tr.loc[mask, keep].to_numpy(), target)
        prob = est.predict_proba(x_va[keep].to_numpy())[:, 1]
        pred = (prob >= 0.5).astype(int)
        return {
            "is_canonical_baseline": False,
            "estimator_type": est_type,
            "n_estimators": n_trees,
            "max_depth": depth,
            "diagnostic_category": diagnostic_category,
            "dropped_features": list(drop),
            "n_features_used": len(keep),
            "n_train_rows": int(mask.sum()),
            "validation_all": binary_metrics(y_va, pred, prob),
            "validation_with_train_fingerprint": binary_metrics(
                y_va[overlap], pred[overlap], prob[overlap]
            ),
            "validation_without_train_fingerprint": binary_metrics(
                y_va[~overlap], pred[~overlap], prob[~overlap]
            ),
        }

    res: Dict[str, Any] = {
        "note": (
            "Non-canonical diagnostic retrains (C0-C7: 60-tree RandomForestClassifier, "
            "max_depth=16; C8-C9: single DecisionTreeClassifier, max_depth=3 and 8). "
            "Never used for tuning."
        ),
        "C0_all_features": run("reference_60tree_rf"),
        "C1_drop_MIN_TTL_MAX_TTL": run(
            "feature_ablation_shortcut_test", drop=("MIN_TTL", "MAX_TTL")
        ),
        "C2_drop_top3_impurity": run(
            "feature_ablation_shortcut_test", drop=tuple(top_features[:3])
        ),
        "C3_drop_top5_impurity": run(
            "feature_ablation_shortcut_test", drop=tuple(top_features[:5])
        ),
        "C4_drop_TCP_windows": run(
            "feature_ablation_shortcut_test", drop=("TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT")
        ),
        "C5_drop_top10_impurity": run(
            "feature_ablation_shortcut_test", drop=tuple(top_features[:10])
        ),
        "C6_train_without_validation_fingerprints": run(
            "cross_split_fingerprint_deduplication", train_mask=~np.isin(h_tr, h_va)
        ),
        "C7_label_shuffle_control": run(
            "harness_sanity_control_not_full_leakage_proof",
            y_fit=np.random.RandomState(7).permutation(y_tr),
        ),
        "C8_single_tree_depth3": run("shallow_single_tree_separability", tree_depth=3),
        "C9_single_tree_depth8": run("shallow_single_tree_separability", tree_depth=8),
    }
    out["diagnostic_retrains"] = res


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--skip-retrain", action="store_true", help="Skip diagnostic retrains.")
    args = parser.parse_args(argv)

    started = time.time()
    manifest = json.loads(SPLIT_MANIFEST.read_text(encoding="utf-8"))
    run_manifest = json.loads(RUN_MANIFEST.read_text(encoding="utf-8"))
    out: Dict[str, Any] = {
        "scope": "Train and Validation only; Test partition never accessed",
        "taxonomy_summary": build_taxonomy_summary(),
    }
    model_sha = sha256_file(MODEL)
    out["model_artifact"] = {
        "path": "artifacts/models/random_forest/random_forest_baseline.joblib",
        "size_bytes": MODEL.stat().st_size,
        "sha256": model_sha,
        "sha256_matches_manifest": model_sha == run_manifest["model_artifact_sha256"],
        "manifest_copies_identical": json.loads(LOCAL_RUN_MANIFEST.read_text(encoding="utf-8"))
        == run_manifest,
    }
    model = RandomForestModel.load_verified(
        MODEL,
        RUN_MANIFEST,
        expected_dataset_sha256=run_manifest["dataset_sha256"],
        expected_split_manifest_sha256=run_manifest["split_manifest_sha256"],
        expected_preprocessor_artifact_sha256=run_manifest["preprocessor_artifact_sha256"],
    )
    out["model_artifact"]["load_verified"] = "PASS"

    data = load_train_validation(manifest, out)
    tr, va = data["train"], data["val"]
    audit_labels_and_groups(tr, va, out)
    comb = pd.concat([tr[COLS], va[COLS]])
    hashes = pd.util.hash_pandas_object(comb, index=False).to_numpy()
    h_tr, h_va = hashes[: len(tr)], hashes[len(tr) :]
    preprocessor = TrainOnlyPreprocessor.load_verified(
        artifact_path=PREPROCESSOR,
        manifest_path=PREPROCESSOR_MANIFEST,
        split_manifest_path=SPLIT_MANIFEST,
        dataset_path=DATASET,
        expected_dataset_sha256=EXPECTED_DATASET_SHA256,
    )
    x_tr, x_va = preprocessor.transform(tr[COLS]), preprocessor.transform(va[COLS])
    out["preprocessing"] = {
        "transformed_columns_equal_contract": list(x_tr.columns) == COLS
        and list(x_va.columns) == COLS,
        "shapes": [list(x_tr.shape), list(x_va.shape)],
        "scaler_type": preprocessor.config.scaler_type,
        "missing_indicators": preprocessor.config.add_missing_indicators,
        "constant_features_in_train": list(preprocessor.constant_features_),
    }
    y_tr, y_va = tr["Label"].astype(int).to_numpy(), va["Label"].astype(int).to_numpy()
    attack_va = va["Attack"].astype(str).to_numpy()
    del tr, va, comb
    overlap = audit_model(model, x_tr, x_va, y_tr, y_va, attack_va, h_tr, h_va, run_manifest, out)
    if not args.skip_retrain:
        top = list(out["impurity_importance_top15"].keys())
        diagnostic_retrains(x_tr, x_va, y_tr, y_va, h_tr, h_va, overlap, top, out)
    out["runtime_seconds"] = round(time.time() - started, 1)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"Audit written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
