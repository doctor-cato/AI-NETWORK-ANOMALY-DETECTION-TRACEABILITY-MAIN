#!/usr/bin/env python3
"""Empirical Experiment for RQ2: Class Imbalance and Rare Attack Evaluation.

Implements Issue #96 for NetFlow Sentinel v2.0.
Computes real per-class sample counts, real prevalence, cost-sensitive supervised
models (trained strictly on Train), and real unsupervised model predictions on
AIT-NDS-v2. Never uses hardcoded metrics.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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

from network_anomaly.config import RANDOM_SEED  # noqa: E402
from network_anomaly.models.registry import ModelRegistry  # noqa: E402

OUTPUT_JSON = Path("reports/experiments/imbalance/rq2_imbalance_report.json")
OUTPUT_MD = Path("reports/experiments/imbalance/rq2_imbalance_report.md")


def _rare_category_metrics(
    y_pred: np.ndarray,
    y_true: np.ndarray,
    attack_test: np.ndarray,
    category: str,
) -> Dict[str, Any]:
    """Evaluate detection on (Benign + specific rare category) in the Test split."""
    mask_cat = attack_test == category
    mask_benign = y_true == 0
    sub_mask = mask_cat | mask_benign
    sub_true = (attack_test[sub_mask] == category).astype(np.int64)
    sub_pred = y_pred[sub_mask].astype(np.int64)
    metrics = compute_binary_metrics(sub_true, sub_pred)
    detected = int(np.sum(y_pred[mask_cat] == 1))
    total = int(np.sum(mask_cat))
    return {
        "category_test_count": total,
        "category_detected": detected,
        "category_detection_rate": float(detected / total) if total > 0 else 0.0,
        "one_vs_benign_precision": metrics["precision"],
        "one_vs_benign_recall": metrics["recall"],
        "one_vs_benign_f1": metrics["f1"],
        "benign_false_positive_rate": metrics["false_positive_rate"],
    }


def run_rq2_experiment(
    max_train_rows: Optional[int] = None,
    max_test_rows: Optional[int] = None,
    rare_prevalence_pct: float = 0.5,
    output_json: Path = OUTPUT_JSON,
    output_md: Path = OUTPUT_MD,
) -> Dict[str, Any]:
    """Run empirical RQ2 rare-attack experiment on real AIT-NDS-v2 splits."""
    env = collect_environment_metadata()
    provenance = dataset_provenance_summary()
    ok_data, missing_paths = check_v2_prerequisites()
    registry = ModelRegistry(warmup=True)

    if not ok_data or not registry.preprocessor_ready:
        blocked = {
            "experiment_id": "EXP-RQ2-IMBALANCE-001",
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
            f"# RQ2 Class Imbalance Experiment (BLOCKED)\n\nMissing: `{missing_paths}`\n",
            encoding="utf-8",
            newline="\n",
        )
        return blocked

    preprocessor = load_verified_preprocessor()
    X_train_raw, y_train, attack_train = load_partition_raw("train", max_rows=max_train_rows)
    X_test_raw, y_test, attack_test = load_partition_raw("test", max_rows=max_test_rows)

    X_train_np = preprocessor.transform(X_train_raw, partition_name="train").to_numpy(dtype=float)
    X_test_np = preprocessor.transform(X_test_raw, partition_name="test").to_numpy(dtype=float)

    train_counts = {str(k): int(v) for k, v in attack_train.value_counts().items()}
    test_counts = {str(k): int(v) for k, v in attack_test.value_counts().items()}
    total_test = len(y_test)
    total_train = len(y_train)

    rare_categories: List[str] = []
    for cat, cnt in sorted(test_counts.items()):
        if cat == "Benign":
            continue
        prev = (cnt / total_test) * 100.0 if total_test else 0.0
        if prev < rare_prevalence_pct:
            rare_categories.append(cat)

    pos_train = int(np.sum(y_train == 1))
    neg_train = int(np.sum(y_train == 0))
    scale_pos_weight = float(neg_train / max(1, pos_train))

    # Train unweighted & cost-sensitive supervised baselines strictly on Train
    rf_unweighted = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        class_weight=None,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    rf_unweighted.fit(X_train_np, y_train)

    rf_cost_sensitive = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        class_weight="balanced_subsample",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    rf_cost_sensitive.fit(X_train_np, y_train)

    xgb_cost_sensitive = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        tree_method="hist",
        eval_metric="logloss",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    xgb_cost_sensitive.fit(X_train_np, y_train)

    predictions: Dict[str, np.ndarray] = {
        "RandomForest_Unweighted": rf_unweighted.predict(X_test_np).astype(np.int64),
        "RandomForest_CostSensitive": rf_cost_sensitive.predict(X_test_np).astype(np.int64),
        "XGBoost_ScalePosWeight": xgb_cost_sensitive.predict(X_test_np).astype(np.int64),
    }
    scores: Dict[str, Optional[np.ndarray]] = {
        "RandomForest_Unweighted": rf_unweighted.predict_proba(X_test_np)[:, 1],
        "RandomForest_CostSensitive": rf_cost_sensitive.predict_proba(X_test_np)[:, 1],
        "XGBoost_ScalePosWeight": xgb_cost_sensitive.predict_proba(X_test_np)[:, 1],
    }
    artifact_hashes: Dict[str, Optional[str]] = {
        "RandomForest_Unweighted": "trained_in_experiment",
        "RandomForest_CostSensitive": "trained_in_experiment",
        "XGBoost_ScalePosWeight": "trained_in_experiment",
    }

    for unsup_key, label in (
        ("isolation_forest", "IsolationForest"),
        ("autoencoder", "Autoencoder_Reconstruction"),
    ):
        st = registry.status(unsup_key)
        if st is not None and st.decision_ready:
            raw_s, pred_s = registry.score_batch(unsup_key, X_test_np)
            predictions[label] = pred_s
            scores[label] = raw_s
            artifact_hashes[label] = st.artifact_sha256

    overall_models = {
        name: compute_binary_metrics(y_test, pred, y_score=scores[name])
        for name, pred in predictions.items()
    }

    attack_test_arr = attack_test.to_numpy()
    rare_results: Dict[str, Any] = {}
    for cat in rare_categories:
        tr_cnt = train_counts.get(cat, 0)
        te_cnt = test_counts.get(cat, 0)
        rare_results[cat] = {
            "sample_count_train": tr_cnt,
            "sample_count_test": te_cnt,
            "train_prevalence_pct": (
                round((tr_cnt / total_train) * 100.0, 4) if total_train else 0.0
            ),
            "test_prevalence_pct": round((te_cnt / total_test) * 100.0, 4) if total_test else 0.0,
            "models": {
                name: _rare_category_metrics(pred, y_test, attack_test_arr, cat)
                for name, pred in predictions.items()
            },
        }

    # Evaluate H2 strictly from computed numbers
    cost_sens_all_ge_070 = bool(rare_categories) and all(
        rare_results[c]["models"]["RandomForest_CostSensitive"]["category_detection_rate"] >= 0.70
        and rare_results[c]["models"]["XGBoost_ScalePosWeight"]["category_detection_rate"] >= 0.70
        for c in rare_categories
    )
    ae_available = "Autoencoder_Reconstruction" in predictions
    ae_all_ge_070 = (
        bool(rare_categories)
        and ae_available
        and all(
            rare_results[c]["models"]["Autoencoder_Reconstruction"]["one_vs_benign_f1"] >= 0.70
            for c in rare_categories
        )
    )

    results: Dict[str, Any] = {
        "experiment_id": "EXP-RQ2-IMBALANCE-001",
        "status": "COMPLETED",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hypothesis": (
            "H2: Cost-sensitive weighting and anomaly reconstruction enable reliable detection "
            "(F1 / detection rate >= 0.70) of rare attack categories (prevalence < 0.5%) "
            "without synthetic oversampling of validation/test distributions."
        ),
        "dataset_provenance": provenance,
        "split_counts": {
            "train_total": total_train,
            "train_benign": neg_train,
            "train_attack": pos_train,
            "scale_pos_weight_used": round(scale_pos_weight, 4),
            "test_total": total_test,
            "train_class_distribution": train_counts,
            "test_class_distribution": test_counts,
        },
        "model_artifact_hashes": artifact_hashes,
        "environment": env,
        "overall_test_metrics": overall_models,
        "rare_attack_categories": rare_results,
        "hypothesis_evaluation": {
            "cost_sensitive_detection_rate_ge_0_70_all_rare": cost_sens_all_ge_070,
            "autoencoder_one_vs_benign_f1_ge_0_70_all_rare": ae_all_ge_070,
            "h2_full_confirmed": cost_sens_all_ge_070 and ae_all_ge_070,
        },
        "limitations": [
            "One-vs-benign rare-class precision/F1 treats all Benign false positives as denominator against a single rare attack class, making F1 sensitive to benign FPR when category support is tiny (e.g., Worms).",
            "No SMOTE or synthetic oversampling was applied to Train, Validation, or Test.",
        ],
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")

    md_lines = [
        "# RQ2 — Class Imbalance & Rare Attack Evaluation (Empirical AIT-NDS-v2)",
        "",
        f"- **Status:** `{results['status']}`",
        f"- **Timestamp (UTC):** `{results['timestamp_utc']}`",
        f"- **Dataset:** `{provenance['dataset_id']}` (`{provenance['dataset_sha256']}`)",
        f"- **Train Rows:** `{total_train:,}` (`scale_pos_weight={scale_pos_weight:.2f}`) | **Test Rows:** `{total_test:,}`",
        f"- **Rare Categories (Test < {rare_prevalence_pct}%):** `{', '.join(rare_categories) or 'None'}`",
        "",
        "## Rare Attack Category Results",
        "",
        "| Category | Test Count | Prevalence | Model | Detection Rate (Recall) | One-vs-Benign F1 | Benign FPR |",
        "|---|---:|---:|---|---:|---:|---:|",
    ]
    for cat in rare_categories:
        cat_info = rare_results[cat]
        for mname, mvals in cat_info["models"].items():
            md_lines.append(
                f"| {cat} | {cat_info['sample_count_test']} | {cat_info['test_prevalence_pct']:.4f}% | "
                f"{mname} | {mvals['category_detection_rate']:.4f} | {mvals['one_vs_benign_f1']:.4f} | "
                f"{mvals['benign_false_positive_rate']:.6f} |"
            )
    md_lines.extend(
        [
            "",
            "## Hypothesis Evaluation",
            f"- Cost-sensitive RF/XGB detection rate >= 0.70 across all rare classes: `{cost_sens_all_ge_070}`",
            f"- Autoencoder one-vs-benign F1 >= 0.70 across all rare classes: `{ae_all_ge_070}`",
            f"- Full H2 confirmed: `{results['hypothesis_evaluation']['h2_full_confirmed']}`",
            "",
            "## Limitations",
            *[f"- {lim}" for lim in results["limitations"]],
        ]
    )

    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
    print(f"RQ2 experiment completed: {output_json} and {output_md}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="RQ2 Rare Attack Imbalance Experiment")
    parser.add_argument("--max-train-rows", type=int, default=None)
    parser.add_argument("--max-test-rows", type=int, default=None)
    args = parser.parse_args()
    res = run_rq2_experiment(max_train_rows=args.max_train_rows, max_test_rows=args.max_test_rows)
    if res["status"] != "COMPLETED":
        sys.exit(1)


if __name__ == "__main__":
    main()
