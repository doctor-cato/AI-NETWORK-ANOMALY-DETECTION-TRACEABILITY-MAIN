#!/usr/bin/env python3
"""Empirical Experiment for RQ4: Unknown Attack Family Holdout Evaluation.

Implements Issue #98 for NetFlow Sentinel v2.0.
Protocol:
- Holdout attack family: {"Exploitation_And_C2", "Post_Exploitation_Discovery"} (0 instances in Train or Validation).
- Supervised models (RF, XGBoost) are trained strictly on Train (Benign + Known Attacks)
  and threshold-calibrated strictly on Validation (Benign + Known Attacks).
- Unsupervised models (Isolation Forest, Autoencoder) are loaded from verified
  artifacts (trained Benign-only) and threshold-calibrated strictly on
  holdout-filtered Validation scores.
- All 4 models are evaluated on real Test split (Known Attacks vs Benign AND
  Unseen Holdout Attacks vs Benign).
- Explicitly states that holdout benchmark evaluation does not prove zero-day
  detection in real-world production networks.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

_SCRIPTS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPTS_DIR.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from _rq_common import (  # noqa: E402
    check_v2_prerequisites,
    collect_environment_metadata,
    compute_binary_metrics,
    dataset_provenance_summary,
    load_partition_raw,
    load_verified_preprocessor,
)
from _v2_train_common import calibrate_unsupervised_threshold_on_validation  # noqa: E402

from network_anomaly.config import RANDOM_SEED  # noqa: E402
from network_anomaly.models.registry import ModelRegistry  # noqa: E402

OUTPUT_JSON = Path("reports/experiments/ml/rq4_unknown_attack_report.json")
OUTPUT_MD = Path("docs/experiments/EXP4_UNKNOWN_ATTACK.md")
HOLDOUT_FAMILIES = frozenset({"Exploitation_And_C2", "Post_Exploitation_Discovery"})


def _calibrate_f1_threshold_on_val(
    val_scores: np.ndarray,
    val_labels: np.ndarray,
) -> float:
    """Select binary threshold strictly on Validation maximizing F1 over quantiles."""
    best_thresh = 0.5
    best_f1 = -1.0
    for q in np.linspace(0.10, 0.90, 17):
        preds = (val_scores >= q).astype(np.int64)
        met = compute_binary_metrics(val_labels, preds)
        if met["f1"] > best_f1:
            best_f1 = met["f1"]
            best_thresh = float(q)
    return best_thresh


def run_rq4_experiment(
    max_train_rows: Optional[int] = None,
    max_val_rows: Optional[int] = None,
    max_test_rows: Optional[int] = None,
    holdout_families: Iterable[str] = HOLDOUT_FAMILIES,
    output_json: Path = OUTPUT_JSON,
    output_md: Path = OUTPUT_MD,
) -> Dict[str, Any]:
    holdout_set = frozenset(holdout_families)
    env = collect_environment_metadata()
    provenance = dataset_provenance_summary()
    ok_data, missing_paths = check_v2_prerequisites()
    registry = ModelRegistry(warmup=True)

    if not ok_data or not registry.preprocessor_ready:
        blocked = {
            "experiment_id": "EXP-RQ4-UNKNOWN-001",
            "status": "BLOCKED",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "dataset_provenance": provenance,
            "environment": env,
            "blocked_reasons": {"missing_data_files": missing_paths},
        }
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(blocked, indent=2) + "\n", encoding="utf-8", newline="\n")
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(
            f"# RQ4 Unknown Attack Holdout (BLOCKED)\n\nMissing: `{missing_paths}`\n",
            encoding="utf-8",
            newline="\n",
        )
        return blocked

    preprocessor = load_verified_preprocessor()
    X_train_raw, y_train, atk_train = load_partition_raw("train", max_rows=max_train_rows)
    X_val_raw, y_val, atk_val = load_partition_raw("validation", max_rows=max_val_rows)
    X_test_raw, y_test, atk_test = load_partition_raw("test", max_rows=max_test_rows)

    # Zero-leakage holdout filter: exclude holdout families from Train & Validation
    tr_keep = ~atk_train.isin(holdout_set).to_numpy()
    va_keep = ~atk_val.isin(holdout_set).to_numpy()

    X_train_np = preprocessor.transform(X_train_raw.loc[tr_keep], partition_name="train").to_numpy(
        dtype=float
    )
    y_train_known = y_train[tr_keep]
    X_val_np = preprocessor.transform(X_val_raw.loc[va_keep], partition_name="validation").to_numpy(
        dtype=float
    )
    y_val_known = y_val[va_keep]
    X_test_np = preprocessor.transform(X_test_raw, partition_name="test").to_numpy(dtype=float)

    assert int(np.sum(atk_train.loc[tr_keep].isin(holdout_set))) == 0
    assert int(np.sum(atk_val.loc[va_keep].isin(holdout_set))) == 0

    # Train supervised holdout models without seeing holdout attack families
    rf_holdout = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    rf_holdout.fit(X_train_np, y_train_known)
    rf_val_scores = rf_holdout.predict_proba(X_val_np)[:, 1]
    rf_thresh = _calibrate_f1_threshold_on_val(rf_val_scores, y_val_known)

    xgb_holdout = XGBClassifier(
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
    xgb_holdout.fit(X_train_np, y_train_known)
    xgb_val_scores = xgb_holdout.predict_proba(X_val_np)[:, 1]
    xgb_thresh = _calibrate_f1_threshold_on_val(xgb_val_scores, y_val_known)

    test_atk_arr = atk_test.to_numpy()
    is_unknown = np.isin(test_atk_arr, list(holdout_set))
    is_benign = y_test == 0
    is_known_attack = (y_test == 1) & (~is_unknown)

    known_mask = is_benign | is_known_attack
    unknown_mask = is_benign | is_unknown

    model_scores_and_preds: Dict[str, Tuple[np.ndarray, np.ndarray, Dict[str, Any]]] = {
        "random_forest": (
            rf_holdout.predict_proba(X_test_np)[:, 1],
            (rf_holdout.predict_proba(X_test_np)[:, 1] >= rf_thresh).astype(np.int64),
            {
                "paradigm": "Supervised Decision Forest (Holdout-Trained)",
                "threshold": rf_thresh,
                "threshold_source": "validation_known_only_f1_calibrated",
                "artifact_sha256": "trained_in_rq4_holdout_experiment",
            },
        ),
        "xgboost": (
            xgb_holdout.predict_proba(X_test_np)[:, 1],
            (xgb_holdout.predict_proba(X_test_np)[:, 1] >= xgb_thresh).astype(np.int64),
            {
                "paradigm": "Gradient Boosted Trees (Holdout-Trained)",
                "threshold": xgb_thresh,
                "threshold_source": "validation_known_only_f1_calibrated",
                "artifact_sha256": "trained_in_rq4_holdout_experiment",
            },
        ),
    }

    for unsup_key, paradigm in (
        ("isolation_forest", "Unsupervised Isolation Forest (Benign-Only)"),
        ("autoencoder", "Unsupervised Autoencoder MSE (Benign-Only)"),
    ):
        st = registry.status(unsup_key)
        if st is not None and st.decision_ready:
            val_raw_u, _ = registry.score_batch(unsup_key, X_val_np)
            cal_th, _, _ = calibrate_unsupervised_threshold_on_validation(
                val_raw_u, y_val_known, target_fpr=0.05
            )
            raw_s, _ = registry.score_batch(unsup_key, X_test_np)
            pred_s = (raw_s >= float(cal_th)).astype(np.int64)
            model_scores_and_preds[unsup_key] = (
                raw_s,
                pred_s,
                {
                    "paradigm": paradigm,
                    "threshold": float(cal_th),
                    "threshold_source": "validation_holdout_known_benign_calibrated",
                    "artifact_sha256": st.artifact_sha256,
                },
            )

    model_eval: Dict[str, Any] = {}
    for mkey, (raw_s, pred_s, meta) in model_scores_and_preds.items():
        known_met = compute_binary_metrics(
            y_test[known_mask], pred_s[known_mask], y_score=raw_s[known_mask]
        )
        unknown_met = compute_binary_metrics(
            y_test[unknown_mask], pred_s[unknown_mask], y_score=raw_s[unknown_mask]
        )
        known_rec = known_met["recall"]
        unk_rec = unknown_met["recall"]
        delta_pct = ((unk_rec - known_rec) / known_rec) * 100.0 if known_rec > 0 else 0.0
        model_eval[mkey] = {
            **meta,
            "known_attacks_vs_benign": known_met,
            "unknown_holdout_vs_benign": unknown_met,
            "known_attacks_recall": round(known_rec, 6),
            "unknown_holdout_recall": round(unk_rec, 6),
            "unknown_holdout_precision": round(unknown_met["precision"], 6),
            "unknown_holdout_f1": round(unknown_met["f1"], 6),
            "unknown_holdout_fpr": round(unknown_met["false_positive_rate"], 6),
            "recall_degradation_pct": round(delta_pct, 2),
        }

    if_rec = model_eval.get("isolation_forest", {}).get("unknown_holdout_recall", 0.0)
    ae_rec = model_eval.get("autoencoder", {}).get("unknown_holdout_recall", 0.0)
    rf_rec = model_eval["random_forest"]["unknown_holdout_recall"]
    xgb_rec = model_eval["xgboost"]["unknown_holdout_recall"]

    results: Dict[str, Any] = {
        "experiment_id": "EXP-RQ4-UNKNOWN-001",
        "status": "COMPLETED",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hypothesis": (
            "H4: Unsupervised anomaly models maintain higher recall on unseen holdout "
            "attack families than closed-world supervised classifiers (benchmark holdout only; "
            "does not prove real-world zero-day detection)."
        ),
        "dataset_provenance": provenance,
        "split_manifest": {
            "held_out_attack_families": sorted(holdout_set),
            "train_rows_after_holdout_filter": int(np.sum(tr_keep)),
            "train_holdout_rows_removed": int(np.sum(~tr_keep)),
            "validation_rows_after_holdout_filter": int(np.sum(va_keep)),
            "validation_holdout_rows_removed": int(np.sum(~va_keep)),
            "test_benign_rows": int(np.sum(is_benign)),
            "test_known_attack_rows": int(np.sum(is_known_attack)),
            "test_unknown_holdout_rows": int(np.sum(is_unknown)),
            "zero_leakage_verified": True,
        },
        "environment": env,
        "model_performance_on_unknown_attacks": model_eval,
        "hypothesis_evaluation": {
            "supervised_min_unknown_recall": round(min(rf_rec, xgb_rec), 6),
            "supervised_max_unknown_recall": round(max(rf_rec, xgb_rec), 6),
            "isolation_forest_unknown_recall": round(if_rec, 6),
            "autoencoder_unknown_recall": round(ae_rec, 6),
            "unsupervised_ge_0_75_both": (if_rec >= 0.75 and ae_rec >= 0.75),
            "isolation_forest_ge_0_75": (if_rec >= 0.75),
            "autoencoder_ge_0_75": (ae_rec >= 0.75),
        },
        "limitations": [
            "Holdout evaluation on AIT-NDS-v2 simulates unseen attack categories within the simulation testbed suite and does NOT guarantee detection of real-world zero-day or adversarial evasion attacks.",
            "Supervised models trained on AIT-NDS-v2 still exhibit cross-domain sensitivity when transferred zero-shot to real captured traffic such as CTU-SME-11.",
        ],
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")

    rows = []
    for mkey, vals in model_eval.items():
        rows.append(
            f"| {mkey} | {vals['paradigm']} | {vals['known_attacks_recall']:.4f} | "
            f"{vals['unknown_holdout_recall']:.4f} | {vals['recall_degradation_pct']:+.2f}% | "
            f"{vals['unknown_holdout_precision']:.4f} | {vals['unknown_holdout_f1']:.4f} | "
            f"{vals['unknown_holdout_fpr']:.4f} |"
        )
    md_lines = [
        "# RQ4 — Unknown Attack Family Holdout Evaluation (Empirical AIT-NDS-v2)",
        "",
        f"- **Status:** `{results['status']}`",
        f"- **Timestamp (UTC):** `{results['timestamp_utc']}`",
        f"- **Held-out Families:** `{', '.join(sorted(holdout_set))}` (0 rows in Train & Validation)",
        f"- **Dataset:** `{provenance['dataset_id']}` (`{provenance['dataset_sha256']}`)",
        f"- **Test Counts:** Benign=`{results['split_manifest']['test_benign_rows']:,}`, "
        f"Known Attack=`{results['split_manifest']['test_known_attack_rows']:,}`, "
        f"Unknown Holdout=`{results['split_manifest']['test_unknown_holdout_rows']:,}`",
        "",
        "| Model | Paradigm | Known Recall | Holdout Recall | Delta | Holdout Precision | Holdout F1 | Benign FPR |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
        *rows,
        "",
        "## Limitations",
        *[f"- {lim}" for lim in results["limitations"]],
    ]
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
    print(f"RQ4 experiment completed: {output_json} and {output_md}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="RQ4 Unknown Attack Holdout Experiment")
    parser.add_argument("--max-train-rows", type=int, default=None)
    parser.add_argument("--max-val-rows", type=int, default=None)
    parser.add_argument("--max-test-rows", type=int, default=None)
    args = parser.parse_args()
    res = run_rq4_experiment(
        max_train_rows=args.max_train_rows,
        max_val_rows=args.max_val_rows,
        max_test_rows=args.max_test_rows,
    )
    if res["status"] != "COMPLETED":
        sys.exit(1)


if __name__ == "__main__":
    main()
