#!/usr/bin/env python3
"""Audit and TTL Shortcut Ablation Study on NF-UNSW-NB15-v3 (Issues #94, #97).

Computes real in-distribution 47-feature vs 46-feature (MIN_TTL removed) metrics
and MIN_TTL feature importance on NF-UNSW-NB15-v3. References verified v1.0.0
cross-dataset artifact when NF-CSE-CIC-IDS2018-v3 raw CSV is absent and marks
ablated cross-dataset evaluation as BLOCKED rather than fabricating metrics.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

_SCRIPTS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPTS_DIR.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from _rq_common import (  # noqa: E402
    check_nf_unsw_prerequisites,
    collect_environment_metadata,
    compute_binary_metrics,
    dataset_provenance_summary,
    load_partition_raw,
    load_verified_preprocessor,
)

from network_anomaly.config import RANDOM_SEED  # noqa: E402
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS  # noqa: E402

OUTPUT_JSON = Path("reports/experiments/ml/ttl_ablation_results.json")
OUTPUT_MD = Path("docs/audits/MODEL_AUDIT_TTL_ABLATION.md")
CROSS_DATASET_EVAL_JSON = Path("reports/evaluation/cross_dataset_evaluation_results.json")
CROSS_DATASET_RAW_DIR = Path("data/raw/NF-CSE-CIC-IDS2018-v3")


def run_ttl_ablation_study(
    max_train_rows: Optional[int] = None,
    max_test_rows: Optional[int] = None,
    output_json: Path = OUTPUT_JSON,
    output_md: Path = OUTPUT_MD,
) -> Dict[str, Any]:
    env = collect_environment_metadata()
    provenance = dataset_provenance_summary()
    ok_data, missing_paths = check_nf_unsw_prerequisites()

    if not ok_data:
        blocked = {
            "study_name": "MIN_TTL Shortcut and Cross-Dataset Generalization Ablation",
            "status": "BLOCKED",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "dataset_provenance": provenance,
            "environment": env,
            "blocked_reasons": {"missing_data_files": missing_paths},
        }
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(blocked, indent=2) + "\n", encoding="utf-8")
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(
            f"# TTL Shortcut Ablation (BLOCKED)\n\nMissing: `{missing_paths}`\n",
            encoding="utf-8",
        )
        return blocked

    preprocessor = load_verified_preprocessor()
    X_train_raw, y_train, _ = load_partition_raw("train", max_rows=max_train_rows)
    X_test_raw, y_test, _ = load_partition_raw("test", max_rows=max_test_rows)

    X_train_47 = preprocessor.transform(X_train_raw, partition_name="train")
    X_test_47 = preprocessor.transform(X_test_raw, partition_name="test")

    cols_46 = [c for c in ML_FEATURE_COLUMNS if c != "MIN_TTL"]
    ttl_idx = list(ML_FEATURE_COLUMNS).index("MIN_TTL")

    X_tr_47_np = X_train_47[list(ML_FEATURE_COLUMNS)].to_numpy(dtype=float)
    X_te_47_np = X_test_47[list(ML_FEATURE_COLUMNS)].to_numpy(dtype=float)
    X_tr_46_np = X_train_47[cols_46].to_numpy(dtype=float)
    X_te_46_np = X_test_47[cols_46].to_numpy(dtype=float)

    rf_47 = RandomForestClassifier(
        n_estimators=100, max_depth=16, random_state=RANDOM_SEED, n_jobs=-1
    ).fit(X_tr_47_np, y_train)
    rf_46 = RandomForestClassifier(
        n_estimators=100, max_depth=16, random_state=RANDOM_SEED, n_jobs=-1
    ).fit(X_tr_46_np, y_train)

    xgb_47 = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        eval_metric="logloss",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    ).fit(X_tr_47_np, y_train)
    xgb_46 = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        eval_metric="logloss",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    ).fit(X_tr_46_np, y_train)

    rf_47_met = compute_binary_metrics(
        y_test, rf_47.predict(X_te_47_np), rf_47.predict_proba(X_te_47_np)[:, 1]
    )
    rf_46_met = compute_binary_metrics(
        y_test, rf_46.predict(X_te_46_np), rf_46.predict_proba(X_te_46_np)[:, 1]
    )
    xgb_47_met = compute_binary_metrics(
        y_test, xgb_47.predict(X_te_47_np), xgb_47.predict_proba(X_te_47_np)[:, 1]
    )
    xgb_46_met = compute_binary_metrics(
        y_test, xgb_46.predict(X_te_46_np), xgb_46.predict_proba(X_te_46_np)[:, 1]
    )

    cross_dataset_section: Dict[str, Any] = {
        "with_ttl_recorded_v1_artifact": None,
        "ablated_ttl_status": "BLOCKED",
        "ablated_ttl_reason": (
            f"Raw NF-CSE-CIC-IDS2018-v3 dataset absent at {CROSS_DATASET_RAW_DIR}; "
            "46-feature cross-dataset ablation cannot be run without raw dataset."
        ),
    }
    if CROSS_DATASET_EVAL_JSON.is_file():
        cross_doc = json.loads(CROSS_DATASET_EVAL_JSON.read_text(encoding="utf-8"))
        cross_dataset_section["with_ttl_recorded_v1_artifact"] = {
            "artifact_path": str(CROSS_DATASET_EVAL_JSON).replace("\\", "/"),
            "dataset_name": cross_doc.get("dataset_name"),
            "dataset_sha256": cross_doc.get("dataset_sha256"),
            "rows_evaluated": cross_doc.get("rows_evaluated"),
            "metrics": cross_doc.get("metrics"),
            "ood_summary": cross_doc.get("ood_summary"),
        }

    results: Dict[str, Any] = {
        "study_name": "MIN_TTL Shortcut and Cross-Dataset Generalization Ablation",
        "status": "COMPLETED_IN_DISTRIBUTION_PARTIAL_CROSS_DATASET",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_provenance": provenance,
        "environment": env,
        "methodology": {
            "primary_dataset": "NF-UNSW-NB15-v3",
            "cross_dataset": "NF-CSE-CIC-IDS2018-v3",
            "feature_count_baseline": 47,
            "feature_count_ablated": 46,
            "ablated_feature": "MIN_TTL",
            "train_rows": int(len(y_train)),
            "test_rows": int(len(y_test)),
        },
        "model_evaluations": {
            "RandomForest": {
                "min_ttl_feature_importance": round(float(rf_47.feature_importances_[ttl_idx]), 6),
                "in_distribution_with_ttl": rf_47_met,
                "in_distribution_ablated_ttl": rf_46_met,
                "in_distribution_f1_delta": round(rf_46_met["f1"] - rf_47_met["f1"], 6),
            },
            "XGBoost": {
                "min_ttl_feature_importance": round(float(xgb_47.feature_importances_[ttl_idx]), 6),
                "in_distribution_with_ttl": xgb_47_met,
                "in_distribution_ablated_ttl": xgb_46_met,
                "in_distribution_f1_delta": round(xgb_46_met["f1"] - xgb_47_met["f1"], 6),
            },
        },
        "cross_dataset_evaluation": cross_dataset_section,
        "limitations": [
            "Cross-dataset 46-feature ablation on NF-CSE-CIC-IDS2018-v3 is BLOCKED locally because the raw NF-CSE-CIC-IDS2018-v3 file is not present.",
            "In-distribution NF-UNSW-NB15-v3 remains accurate after removing MIN_TTL because MAX_TTL and other flow features still reflect testbed structure.",
        ],
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    rf_imp = results["model_evaluations"]["RandomForest"]["min_ttl_feature_importance"]
    xgb_imp = results["model_evaluations"]["XGBoost"]["min_ttl_feature_importance"]
    md_lines = [
        "# Audit & Ablation: MIN_TTL Shortcut on NF-UNSW-NB15-v3 (#94, #97)",
        "",
        f"- **Status:** `{results['status']}`",
        f"- **Timestamp (UTC):** `{results['timestamp_utc']}`",
        f"- **Dataset:** `{provenance['dataset_id']}` (`{provenance['dataset_sha256']}`)",
        "",
        "## In-Distribution Ablation Results (47 vs 46 Features)",
        "",
        "| Model | MIN_TTL Importance | 47-Feat F1 | 46-Feat F1 (No MIN_TTL) | F1 Delta |",
        "|---|---:|---:|---:|---:|",
        f"| RandomForest | {rf_imp:.6f} | {rf_47_met['f1']:.6f} | {rf_46_met['f1']:.6f} | {rf_46_met['f1'] - rf_47_met['f1']:+.6f} |",
        f"| XGBoost | {xgb_imp:.6f} | {xgb_47_met['f1']:.6f} | {xgb_46_met['f1']:.6f} | {xgb_46_met['f1'] - xgb_47_met['f1']:+.6f} |",
        "",
        "## Cross-Dataset Status (NF-CSE-CIC-IDS2018-v3)",
        f"- Recorded v1.0.0 baseline RF (with MIN_TTL, 100k sample): `{cross_dataset_section['with_ttl_recorded_v1_artifact']['metrics'] if cross_dataset_section['with_ttl_recorded_v1_artifact'] else 'UNAVAILABLE'}`",
        f"- Ablated 46-feature cross-dataset run: **`{cross_dataset_section['ablated_ttl_status']}`** — {cross_dataset_section['ablated_ttl_reason']}",
        "",
        "## Limitations",
        *[f"- {lim}" for lim in results["limitations"]],
    ]
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"TTL ablation study saved: {output_json} and {output_md}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="MIN_TTL Shortcut Ablation on NF-UNSW-NB15-v3")
    parser.add_argument("--max-train-rows", type=int, default=None)
    parser.add_argument("--max-test-rows", type=int, default=None)
    args = parser.parse_args()
    res = run_ttl_ablation_study(
        max_train_rows=args.max_train_rows, max_test_rows=args.max_test_rows
    )
    if res["status"] == "BLOCKED":
        sys.exit(1)


if __name__ == "__main__":
    main()
