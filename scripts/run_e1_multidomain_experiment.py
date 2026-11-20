#!/usr/bin/env python3
"""Multi-Domain E1 (AIT + CTU-SME-11 + UWF-ZeekData24) & Variance-Normalized Autoencoder E3b.

Implements:
- Comment #14 Solution 1: Multi-Domain E1 training on stratified AIT-NDS-v2 + chronological
  70/15/15 splits of CTU-SME-11 and UWF-ZeekData24, with in-memory TrainOnlyPreprocessor
  fitted strictly on E1_Train, domain-and-class balanced sample weights, and E1_Val
  threshold calibration.
- Comment #13 Direction 2: Variance-Normalized Autoencoder E3b (One-Hot protocol_num +
  bounded_scale_floor=0.25 via asinh_robust + feature-wise benign residual variance
  normalization s(x) = (1/D) sum_j ((x_j - x_hat_j)^2 / (sigma^2_{err,j} + eps))).

Completely isolated from frozen E0 .joblib artifacts (read-only E0 baseline comparison).
"""

from __future__ import annotations

import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neural_network import MLPRegressor
from xgboost import XGBClassifier

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = PROJECT_ROOT / "src"
_SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(_SRC_DIR), str(_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from _v2_train_common import (  # noqa: E402
    PREPROC_ARTIFACT_PATH,
    PROCESSED_V2_DIR,
    build_environment_block,
)

from network_anomaly.config import RANDOM_SEED  # noqa: E402
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.ingestion.adapters.uwf_zeek import parse_uwf_zeek_row  # noqa: E402
from network_anomaly.models.registry import ModelRegistry  # noqa: E402
from network_anomaly.models.stage2_multiclass import CANONICAL_6_CLASSES  # noqa: E402
from network_anomaly.preprocessing.pipeline import (  # noqa: E402
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)

RAW_UWF_DIR = PROJECT_ROOT / "data" / "raw" / "uwf_zeekdata24"
OUT_JSON = PROJECT_ROOT / "reports" / "experiments" / "ml" / "e1_multidomain_experiment_report.json"
OUT_MD = PROJECT_ROOT / "docs" / "experiments" / "E1_MULTIDOMAIN_EXPERIMENT.md"

CLASS_TO_IDX: Dict[str, int] = {c: i for i, c in enumerate(CANONICAL_6_CLASSES)}
PROTO_IDX: int = list(ML_FEATURE_COLUMNS).index("protocol_num")


def _stratified_subsample_preserve_rare(
    df: pd.DataFrame,
    *,
    max_rows: int,
    rare_threshold: int = 5_000,
    seed: int = RANDOM_SEED,
) -> pd.DataFrame:
    """Subsample df up to max_rows while preserving 100% of rare attack categories."""
    if len(df) <= max_rows:
        return df.reset_index(drop=True)

    rng = np.random.default_rng(seed)
    counts = df["attack_category"].value_counts()
    rare_cats = set(counts[counts <= rare_threshold].index.tolist())

    rare_mask = df["attack_category"].isin(rare_cats)
    df_rare = df[rare_mask]
    df_major = df[~rare_mask]

    remaining_budget = max(0, max_rows - len(df_rare))
    if remaining_budget == 0 or len(df_major) == 0:
        return df_rare.reset_index(drop=True)

    major_parts: List[pd.DataFrame] = []
    major_total = len(df_major)
    for _, grp in df_major.groupby("attack_category", sort=True):
        alloc = max(1, int(round(remaining_budget * (len(grp) / major_total))))
        alloc = min(alloc, len(grp))
        idx = rng.choice(grp.index.to_numpy(), size=alloc, replace=False)
        major_parts.append(df.loc[np.sort(idx)])

    combined = pd.concat([df_rare] + major_parts, axis=0)
    return combined.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _chronological_split_70_15_15(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Deterministic 70% Train / 15% Val / 15% Test split by row/chronological order."""
    n = len(df)
    n_train = int(n * 0.70)
    n_val = int(n * 0.15)
    return (
        df.iloc[:n_train].reset_index(drop=True),
        df.iloc[n_train : n_train + n_val].reset_index(drop=True),
        df.iloc[n_train + n_val :].reset_index(drop=True),
    )


def _load_ait_splits(
    *,
    max_train: int = 200_000,
    max_val: int = 60_000,
    max_test: int = 100_000,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    usecols = list(ML_FEATURE_COLUMNS) + ["label_binary", "attack_category"]
    parts = []
    for fname, cap in (
        ("ait_train.csv.gz", max_train),
        ("ait_val.csv.gz", max_val),
        ("ait_test.csv.gz", max_test),
    ):
        df = pd.read_csv(PROCESSED_V2_DIR / fname, usecols=usecols, low_memory=False)
        df["domain"] = "AIT"
        df["subsource"] = "AIT-NDS-v2"
        parts.append(_stratified_subsample_preserve_rare(df, max_rows=cap, seed=RANDOM_SEED))
    return parts[0], parts[1], parts[2]


def _stratified_block_split_70_15_15(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Deterministic stratified 70/15/15 chronological block split per attack_category."""
    if "timestamp_ms" in df.columns:
        df = df.sort_values("timestamp_ms", kind="mergesort").reset_index(drop=True)
    tr_parts, va_parts, te_parts = [], [], []
    for _, grp in df.groupby("attack_category", sort=True):
        n = len(grp)
        n_tr = int(n * 0.70)
        n_va = int(n * 0.15)
        tr_parts.append(grp.iloc[:n_tr])
        va_parts.append(grp.iloc[n_tr : n_tr + n_va])
        te_parts.append(grp.iloc[n_tr + n_va :])
    return (
        pd.concat(tr_parts, ignore_index=True),
        pd.concat(va_parts, ignore_index=True),
        pd.concat(te_parts, ignore_index=True),
    )


def _load_ctu_splits() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    base_cols = list(ML_FEATURE_COLUMNS) + ["label_binary", "attack_category"]
    tr_list, va_list, te_list = [], [], []
    for fname, subname in (
        ("ctu_echo.csv.gz", "CTU-Echo"),
        ("ctu_windows7ad.csv.gz", "CTU-Win7AD"),
    ):
        fpath = PROCESSED_V2_DIR / fname
        avail_cols = set(pd.read_csv(fpath, nrows=0).columns)
        usecols = base_cols + (["timestamp_ms"] if "timestamp_ms" in avail_cols else [])
        df = pd.read_csv(fpath, usecols=usecols, low_memory=False)
        if "timestamp_ms" in df.columns:
            df = df.sort_values("timestamp_ms", kind="mergesort").reset_index(drop=True)
            df = df.drop(columns=["timestamp_ms"])
        df["domain"] = "CTU"
        df["subsource"] = subname
        if subname == "CTU-Win7AD":
            tr, va, te = _stratified_block_split_70_15_15(df)
        else:
            tr, va, te = _chronological_split_70_15_15(df)
        tr_list.append(tr)
        va_list.append(va)
        te_list.append(te)
    return (
        pd.concat(tr_list, ignore_index=True),
        pd.concat(va_list, ignore_index=True),
        pd.concat(te_list, ignore_index=True),
    )


def _load_uwf_splits() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    tr_list, va_list, te_list = [], [], []
    for csv_path in sorted(RAW_UWF_DIR.glob("*.csv")):
        subset = csv_path.stem
        rows: List[Dict[str, Any]] = []
        with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for raw in reader:
                try:
                    row = parse_uwf_zeek_row(raw, allow_zeek_unset_zero=True, subset_name=subset)
                except Exception:
                    continue
                if row["label_binary"] is None:
                    continue
                rec = {col: float(row[col]) for col in ML_FEATURE_COLUMNS}
                rec["label_binary"] = int(row["label_binary"])
                rec["attack_category"] = str(row["attack_category"])
                rec["domain"] = "UWF"
                rec["subsource"] = f"UWF-{subset}"
                rows.append(rec)
        if not rows:
            continue
        df_sub = pd.DataFrame(rows)
        tr, va, te = _chronological_split_70_15_15(df_sub)
        tr_list.append(tr)
        va_list.append(va)
        te_list.append(te)
    return (
        pd.concat(tr_list, ignore_index=True),
        pd.concat(va_list, ignore_index=True),
        pd.concat(te_list, ignore_index=True),
    )


def _compute_domain_class_weights(
    domains: pd.Series,
    y_binary: np.ndarray,
    *,
    max_weight: float = 100.0,
) -> np.ndarray:
    """Compute sqrt inverse-frequency domain-and-class balanced sample weights."""
    keys = [f"{d}::{int(y)}" for d, y in zip(domains.astype(str), y_binary)]
    counts: Dict[str, int] = {}
    for k in keys:
        counts[k] = counts.get(k, 0) + 1
    total = float(len(keys))
    n_groups = float(max(1, len(counts)))
    weights = np.array(
        [np.sqrt(total / (n_groups * counts[k])) for k in keys],
        dtype=np.float32,
    )
    return np.clip(weights, 1.0, max_weight)


def _calibrate_f1_threshold(y_val: np.ndarray, scores_val: np.ndarray) -> float:
    """Select F1-maximizing threshold strictly on validation scores."""
    prec, rec, ths = precision_recall_curve(y_val, scores_val)
    if len(ths) == 0:
        return 0.5
    f1s = (2.0 * prec[:-1] * rec[:-1]) / np.maximum(prec[:-1] + rec[:-1], 1e-12)
    best_idx = int(np.argmax(f1s))
    return float(ths[best_idx])


def _binary_metrics(
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    attack_cats: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    pred = (scores >= threshold).astype(np.int64)
    tn_mask = y_true == 0
    fp = int(np.sum(pred[tn_mask] == 1))
    tn = int(np.sum(tn_mask))
    fpr = float(fp / tn) if tn > 0 else 0.0
    try:
        auc = float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) > 1 else None
    except Exception:
        auc = None

    out: Dict[str, Any] = {
        "n_rows": int(len(y_true)),
        "n_attack": int(np.sum(y_true == 1)),
        "n_benign": int(tn),
        "threshold": round(float(threshold), 6),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "fpr": round(fpr, 6),
        "roc_auc": round(auc, 4) if auc is not None else None,
    }
    if attack_cats is not None:
        per_cat: Dict[str, Any] = {}
        for cat in (
            "Credential_Attack",
            "Exploitation_And_C2",
            "Data_Exfiltration",
            "Post_Exploitation_Discovery",
            "Reconnaissance",
        ):
            cmask = attack_cats == cat
            cnt = int(np.sum(cmask))
            if cnt > 0:
                per_cat[cat] = {
                    "count": cnt,
                    "recall": round(float(np.mean(pred[cmask] == 1)), 4),
                }
        out["per_attack_recall"] = per_cat
    return out


def _encode_ae_e3b_features(X_scaled: np.ndarray) -> np.ndarray:
    """Replace protocol_num (index 5) with 4-dim One-Hot [TCP, UDP, ICMP, Other]."""
    proto = X_scaled[:, PROTO_IDX]
    oh = np.zeros((X_scaled.shape[0], 4), dtype=np.float32)
    oh[:, 0] = (proto == 6).astype(np.float32)
    oh[:, 1] = (proto == 17).astype(np.float32)
    oh[:, 2] = (proto == 1).astype(np.float32)
    oh[:, 3] = (~np.isin(proto, [6, 17, 1])).astype(np.float32)
    other_cols = [i for i in range(X_scaled.shape[1]) if i != PROTO_IDX]
    return np.hstack([X_scaled[:, other_cols].astype(np.float32), oh])


def main() -> int:
    t0 = time.perf_counter()
    print("[E1] Loading AIT, CTU-SME-11, and UWF-ZeekData24 splits...", flush=True)
    ait_tr, ait_va, ait_te = _load_ait_splits()
    ctu_tr, ctu_va, ctu_te = _load_ctu_splits()
    uwf_tr, uwf_va, uwf_te = _load_uwf_splits()

    e1_train_df = pd.concat([ait_tr, ctu_tr, uwf_tr], ignore_index=True)
    e1_val_df = pd.concat([ait_va, ctu_va, uwf_va], ignore_index=True)

    # Fit in-memory E1 preprocessor strictly on E1_Train (asinh_robust with MIN_BOUNDED_SCALE_FLOOR=0.25)
    print(
        f"[E1] Fitting in-memory TrainOnlyPreprocessor on E1_Train ({len(e1_train_df):,} rows)...",
        flush=True,
    )
    e1_preproc = TrainOnlyPreprocessor(PreprocessingConfig(scaler_type="asinh_robust"))
    e1_preproc.fit(e1_train_df[list(ML_FEATURE_COLUMNS)])

    X_e1_tr = e1_preproc.transform(
        e1_train_df[list(ML_FEATURE_COLUMNS)], partition_name="e1_train"
    ).to_numpy(dtype=np.float32)
    y_e1_tr = e1_train_df["label_binary"].to_numpy(dtype=np.int64)
    w_e1_tr = _compute_domain_class_weights(e1_train_df["domain"], y_e1_tr)

    X_e1_va = e1_preproc.transform(
        e1_val_df[list(ML_FEATURE_COLUMNS)], partition_name="e1_val"
    ).to_numpy(dtype=np.float32)
    y_e1_va = e1_val_df["label_binary"].to_numpy(dtype=np.int64)

    test_splits: Dict[str, pd.DataFrame] = {
        "AIT_Test": ait_te,
        "CTU_Test": ctu_te,
        "CTU_Win7AD_Test": ctu_te[ctu_te["subsource"] == "CTU-Win7AD"].reset_index(drop=True),
        "UWF_Test": uwf_te,
    }
    X_tests_e1 = {
        k: e1_preproc.transform(df[list(ML_FEATURE_COLUMNS)], partition_name=k).to_numpy(
            dtype=np.float32
        )
        for k, df in test_splits.items()
    }

    # 1. E1 RandomForest Binary
    print("[E1] Training E1_RandomForest_Binary...", flush=True)
    e1_rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_leaf=3,
        class_weight="balanced_subsample",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    e1_rf.fit(X_e1_tr, y_e1_tr, sample_weight=w_e1_tr)
    e1_rf_th = _calibrate_f1_threshold(y_e1_va, e1_rf.predict_proba(X_e1_va)[:, 1])

    # 2. E1 XGBoost Binary
    print("[E1] Training E1_XGBoost_Binary...", flush=True)
    e1_xgb = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        eval_metric="logloss",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    e1_xgb.fit(X_e1_tr, y_e1_tr, sample_weight=w_e1_tr)
    e1_xgb_th = _calibrate_f1_threshold(y_e1_va, e1_xgb.predict_proba(X_e1_va)[:, 1])

    # 3. E1 RandomForest 6-Class
    print("[E1] Training E1_RandomForest_6Class...", flush=True)
    mask_6c = e1_train_df["attack_category"].isin(CANONICAL_6_CLASSES).to_numpy()
    y_6c_tr = e1_train_df.loc[mask_6c, "attack_category"].map(CLASS_TO_IDX).to_numpy(dtype=np.int64)
    e1_rf_6c = RandomForestClassifier(
        n_estimators=80,
        max_depth=20,
        min_samples_leaf=3,
        class_weight="balanced_subsample",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    e1_rf_6c.fit(X_e1_tr[mask_6c], y_6c_tr, sample_weight=w_e1_tr[mask_6c])

    # 4. Autoencoder E3b (Variance-Normalized + One-Hot protocol_num + bounded_scale_floor=0.25)
    print("[E1/E3b] Training Autoencoder_E3b_VarianceNormalized on Benign E1_Train...", flush=True)
    benign_tr_mask = y_e1_tr == 0
    X_ae_tr_benign = _encode_ae_e3b_features(X_e1_tr[benign_tr_mask])
    if len(X_ae_tr_benign) > 150_000:
        rng = np.random.default_rng(RANDOM_SEED)
        idx_sub = rng.choice(len(X_ae_tr_benign), size=150_000, replace=False)
        X_ae_fit = X_ae_tr_benign[idx_sub]
    else:
        X_ae_fit = X_ae_tr_benign

    ae_e3b = MLPRegressor(
        hidden_layer_sizes=(32, 12, 32),
        activation="relu",
        solver="adam",
        alpha=1e-4,
        batch_size=256,
        learning_rate_init=1e-3,
        max_iter=80,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=5,
        random_state=RANDOM_SEED,
    )
    ae_e3b.fit(X_ae_fit, X_ae_fit)
    X_hat_fit = ae_e3b.predict(X_ae_fit)
    sigma2_err = np.var(X_ae_fit - X_hat_fit, axis=0)

    def _score_ae_e3b(X_scaled: np.ndarray) -> np.ndarray:
        X_ae = _encode_ae_e3b_features(X_scaled)
        X_hat = ae_e3b.predict(X_ae)
        return np.mean(((X_ae - X_hat) ** 2) / (sigma2_err + 1e-6), axis=1)

    ae_e3b_val_scores = _score_ae_e3b(X_e1_va)
    ae_e3b_th = _calibrate_f1_threshold(y_e1_va, ae_e3b_val_scores)

    # Evaluate E1 models & compare against frozen E0 baselines
    print("[E1] Evaluating E1 models vs frozen E0 zero-shot baselines...", flush=True)
    e0_preproc = TrainOnlyPreprocessor.load(PREPROC_ARTIFACT_PATH)
    e0_reg = ModelRegistry(warmup=True)
    e0_summary = {m["model_key"]: m["threshold"] for m in e0_reg.summary()["models"]}

    results_by_split: Dict[str, Any] = {}
    for split_name, df_sp in test_splits.items():
        y_sp = df_sp["label_binary"].to_numpy(dtype=np.int64)
        cats_sp = df_sp["attack_category"].to_numpy(dtype=object)
        X_sp_e1 = X_tests_e1[split_name]
        X_sp_e0 = e0_preproc.transform(
            df_sp[list(ML_FEATURE_COLUMNS)], partition_name=split_name
        ).to_numpy(dtype=np.float64)

        e0_rf_s, _ = e0_reg.score_batch("random_forest", X_sp_e0)
        e0_xgb_s, _ = e0_reg.score_batch("xgboost", X_sp_e0)
        e0_ae_s, _ = e0_reg.score_batch("autoencoder", X_sp_e0)

        # 6-class macro-F1 on canonical classes
        m6 = df_sp["attack_category"].isin(CANONICAL_6_CLASSES).to_numpy()
        y_6c_sp = df_sp.loc[m6, "attack_category"].map(CLASS_TO_IDX).to_numpy(dtype=np.int64)
        pred_6c = e1_rf_6c.predict(X_sp_e1[m6])
        present_labels = sorted(set(y_6c_sp.tolist()))
        macro_f1_6c = float(
            f1_score(y_6c_sp, pred_6c, labels=present_labels, average="macro", zero_division=0)
        )

        results_by_split[split_name] = {
            "E0_RandomForest_ZeroShot": _binary_metrics(
                y_sp, e0_rf_s, float(e0_summary["random_forest"]), cats_sp
            ),
            "E1_RandomForest_Binary": _binary_metrics(
                y_sp, e1_rf.predict_proba(X_sp_e1)[:, 1], e1_rf_th, cats_sp
            ),
            "E0_XGBoost_ZeroShot": _binary_metrics(
                y_sp, e0_xgb_s, float(e0_summary["xgboost"]), cats_sp
            ),
            "E1_XGBoost_Binary": _binary_metrics(
                y_sp, e1_xgb.predict_proba(X_sp_e1)[:, 1], e1_xgb_th, cats_sp
            ),
            "E0_Autoencoder_ZeroShot": _binary_metrics(
                y_sp, e0_ae_s, float(e0_summary["autoencoder"]), cats_sp
            ),
            "Autoencoder_E3b_VarianceNormalized": _binary_metrics(
                y_sp, _score_ae_e3b(X_sp_e1), ae_e3b_th, cats_sp
            ),
            "E1_RandomForest_6Class_MacroF1_Present": round(macro_f1_6c, 4),
        }

    env_block = build_environment_block()

    report = {
        "experiment_id": "EXP-E1-MULTIDOMAIN-AND-E3B-01",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.perf_counter() - t0, 2),
        "e0_artifacts_untouched": True,
        "split_counts": {
            "AIT_Train": int(len(ait_tr)),
            "CTU_Train": int(len(ctu_tr)),
            "UWF_Train": int(len(uwf_tr)),
            "E1_Train_Total": int(len(e1_train_df)),
            "E1_Val_Total": int(len(e1_val_df)),
            "AIT_Test": int(len(ait_te)),
            "CTU_Test": int(len(ctu_te)),
            "CTU_Win7AD_Test": int(len(test_splits["CTU_Win7AD_Test"])),
            "UWF_Test": int(len(uwf_te)),
        },
        "calibrated_thresholds_on_e1_val": {
            "E1_RandomForest_Binary": round(e1_rf_th, 6),
            "E1_XGBoost_Binary": round(e1_xgb_th, 6),
            "Autoencoder_E3b_VarianceNormalized": round(ae_e3b_th, 6),
        },
        "results_by_test_split": results_by_split,
        "environment": env_block,
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")

    md_lines = [
        "# Multi-Domain E1 (`AIT + CTU-SME-11 + UWF-ZeekData24`) & Autoencoder E3b Experiment",
        "",
        f"- **Executed At (UTC):** `{report['executed_at_utc']}` | **Elapsed:** `{report['elapsed_seconds']}s`",
        "- **Isolation Guarantee:** `e0_artifacts_untouched = true`",
        f"- **E1 Train Rows:** `{len(e1_train_df):,}` (`AIT={len(ait_tr):,}`, `CTU={len(ctu_tr):,}`, `UWF={len(uwf_tr):,}`)",
        "",
        "## Test Split Comparison (`E1` vs Frozen `E0` Zero-Shot)",
        "",
        "| Test Split | Model | Precision | Recall | F1 | FPR | ROC-AUC |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for split_name in ("AIT_Test", "CTU_Test", "CTU_Win7AD_Test", "UWF_Test"):
        sp_res = results_by_split[split_name]
        for mname in (
            "E0_RandomForest_ZeroShot",
            "E1_RandomForest_Binary",
            "E0_XGBoost_ZeroShot",
            "E1_XGBoost_Binary",
            "E0_Autoencoder_ZeroShot",
            "Autoencoder_E3b_VarianceNormalized",
        ):
            m = sp_res[mname]
            auc_s = f"{m['roc_auc']:.4f}" if m["roc_auc"] is not None else "N/A"
            md_lines.append(
                f"| `{split_name}` | `{mname}` | {m['precision']:.4f} | {m['recall']:.4f} | "
                f"**{m['f1']:.4f}** | {m['fpr']:.6f} | {auc_s} |"
            )

    md_lines.extend(
        [
            "",
            "## Limitations & Governance Disclosure",
            "",
            "- **UWF-ZeekData24 Governance (`evaluation_only = true` for frozen `E0`):** "
            "`data/UWF_ZEEKDATA24_MANIFEST.json` designates `UWF-ZeekData24` as `evaluation_only = true` "
            "for the frozen `E0` baseline models. In this separate `E1` multi-domain experiment, `UWF_Train` "
            "is included in `E1_Train`, so `E1`'s `UWF_Test` evaluation is an **in-domain multi-source split** "
            "(NOT zero-shot generalization), whereas `E0_*_ZeroShot` rows remain true zero-shot evaluations.",
            "- **Frozen `E0` Isolation:** All four frozen `E0` `.joblib` artifacts and `E0` thresholds remain "
            "**100% untouched** (`e0_artifacts_untouched = true`); `E1` and `Autoencoder_E3b` are trained and "
            "evaluated strictly in-memory as experimental models.",
            "- **CTU-Win7AD Stratified Chronological Block Split:** Because raw `ctu_windows7ad.csv.gz` "
            "places all `Exploitation_And_C2` attack flows in the first 85% of the chronological stream, "
            "`CTU-Win7AD` uses a deterministic stratified 70/15/15 chronological block split per `attack_category` "
            "so `CTU_Win7AD_Test` contains both Benign and Attack rows.",
        ]
    )

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
    print(f"[done] E1/E3b experiment written: {OUT_JSON} and {OUT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
