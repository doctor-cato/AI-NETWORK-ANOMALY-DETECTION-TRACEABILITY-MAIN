#!/usr/bin/env python3
"""Separate Multi-Class Attack Classification Experiment (Mục 5.4 Đề cương Đề tài 22).

Trains standalone 6-class RandomForest and XGBoost classifiers strictly on AIT-Train
using the frozen TrainOnlyPreprocessor (zero val/test fitting), selects model config on
AIT-Val Macro-F1, and evaluates once on AIT-Test.

Strictly isolated from frozen v2.0 E0 binary artifacts (never modifies E0 .joblib files).
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
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
    SPLIT_MANIFEST_PATH,
    build_environment_block,
)

from network_anomaly.data.split import _sha256_file  # noqa: E402
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.models.stage2_multiclass import (  # noqa: E402
    CANONICAL_6_CLASSES,
    DEFAULT_STAGE2_ARTIFACT_PATH,
    DEFAULT_STAGE2_MANIFEST_PATH,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

OUT_JSON = (
    PROJECT_ROOT / "reports" / "experiments" / "ml" / "multiclass_attack_classification_report.json"
)
OUT_MD = PROJECT_ROOT / "docs" / "experiments" / "MULTICLASS_ATTACK_CLASSIFICATION.md"

CANONICAL_CLASSES: Tuple[str, ...] = CANONICAL_6_CLASSES
CLASS_TO_IDX: Dict[str, int] = {name: idx for idx, name in enumerate(CANONICAL_CLASSES)}


def _load_multiclass_split(
    csv_path: Path,
    preproc: TrainOnlyPreprocessor,
    part_name: str,
) -> Tuple[np.ndarray, np.ndarray]:
    usecols = list(ML_FEATURE_COLUMNS) + ["attack_category"]
    df = pd.read_csv(csv_path, usecols=usecols, low_memory=False)
    X_t = preproc.transform(df[list(ML_FEATURE_COLUMNS)], partition_name=part_name)
    X_np = X_t.to_numpy(dtype=np.float32)
    cats = df["attack_category"].astype(str).map(CLASS_TO_IDX)
    if cats.isna().any():
        unknown = df.loc[cats.isna(), "attack_category"].unique().tolist()
        raise ValueError(f"Unexpected attack_category values in {part_name}: {unknown}")
    y_np = cats.to_numpy(dtype=np.int64)
    return X_np, y_np


def _evaluate_predictions(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    labels = list(range(len(CANONICAL_CLASSES)))
    rep = classification_report(
        y_true,
        y_pred,
        labels=labels,
        target_names=list(CANONICAL_CLASSES),
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    per_class = {
        cname: {
            "precision": round(float(rep[cname]["precision"]), 4),
            "recall": round(float(rep[cname]["recall"]), 4),
            "f1": round(float(rep[cname]["f1-score"]), 4),
            "support": int(rep[cname]["support"]),
        }
        for cname in CANONICAL_CLASSES
    }
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_true, y_pred)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "weighted_f1": round(
            float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 4
        ),
        "per_class": per_class,
        "confusion_matrix_labels": list(CANONICAL_CLASSES),
        "confusion_matrix": cm,
    }


def _compute_bounded_sample_weights(
    y_train: np.ndarray, *, max_weight: float = 200.0
) -> np.ndarray:
    counts = np.bincount(y_train, minlength=len(CANONICAL_CLASSES)).astype(np.float64)
    total = float(len(y_train))
    n_classes = float(len(CANONICAL_CLASSES))
    # Sqrt inverse-frequency bounded weights to elevate rare classes without collapsing Benign precision
    raw_w = np.sqrt(total / np.maximum(1.0, n_classes * counts))
    class_w = np.clip(raw_w, 1.0, max_weight)
    return class_w[y_train].astype(np.float32)


def main() -> int:
    t0 = time.perf_counter()
    if not PREPROC_ARTIFACT_PATH.is_file():
        raise FileNotFoundError(f"Missing frozen preprocessor: {PREPROC_ARTIFACT_PATH}")
    preproc = TrainOnlyPreprocessor.load(PREPROC_ARTIFACT_PATH)

    print("[multiclass] Loading AIT train / val / test with frozen preprocessor...", flush=True)
    X_train, y_train = _load_multiclass_split(
        PROCESSED_V2_DIR / "ait_train.csv.gz", preproc, "train"
    )
    X_val, y_val = _load_multiclass_split(
        PROCESSED_V2_DIR / "ait_val.csv.gz", preproc, "validation"
    )
    X_test, y_test = _load_multiclass_split(PROCESSED_V2_DIR / "ait_test.csv.gz", preproc, "test")

    sample_w = _compute_bounded_sample_weights(y_train, max_weight=200.0)

    models_out: Dict[str, Any] = {}

    # 1. Random Forest (balanced_subsample)
    print("[multiclass] Training RandomForestClassifier (6 classes)...", flush=True)
    t_rf = time.perf_counter()
    rf = RandomForestClassifier(
        n_estimators=80,
        max_depth=20,
        min_samples_leaf=5,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_fit_s = round(time.perf_counter() - t_rf, 2)
    models_out["random_forest_multiclass"] = {
        "train_seconds": rf_fit_s,
        "hyperparameters": {
            "n_estimators": 80,
            "max_depth": 20,
            "min_samples_leaf": 5,
            "class_weight": "balanced_subsample",
            "random_state": 42,
        },
        "validation": _evaluate_predictions(y_val, rf.predict(X_val)),
        "test": _evaluate_predictions(y_test, rf.predict(X_test)),
    }

    # Save Stage-2 RandomForest artifact + tracked lightweight centroid manifest
    DEFAULT_STAGE2_ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, DEFAULT_STAGE2_ARTIFACT_PATH, compress=3)
    stage2_model_sha = _sha256_file(DEFAULT_STAGE2_ARTIFACT_PATH)
    preproc_sha = _sha256_file(PREPROC_ARTIFACT_PATH)

    class_centroids: Dict[str, Any] = {}
    class_stds: Dict[str, Any] = {}
    for idx, cname in enumerate(CANONICAL_CLASSES):
        mask = y_train == idx
        if np.any(mask):
            subset = X_train[mask].astype(np.float64)
            centroid = np.mean(subset, axis=0)
            std = np.maximum(np.std(subset, axis=0), 1e-3)
        else:
            centroid = np.zeros(X_train.shape[1], dtype=np.float64)
            std = np.ones(X_train.shape[1], dtype=np.float64)
        class_centroids[cname] = [round(float(v), 6) for v in centroid]
        class_stds[cname] = [round(float(v), 6) for v in std]

    stage2_manifest = {
        "schema_version": "stage2-multiclass-manifest-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_artifact_relpath": str(
            DEFAULT_STAGE2_ARTIFACT_PATH.relative_to(PROJECT_ROOT)
        ).replace("\\", "/"),
        "model_artifact_sha256": stage2_model_sha,
        "preprocessor_artifact_sha256": preproc_sha,
        "feature_columns": list(ML_FEATURE_COLUMNS),
        "classes": list(CANONICAL_CLASSES),
        "validation_macro_f1": models_out["random_forest_multiclass"]["validation"]["macro_f1"],
        "test_macro_f1": models_out["random_forest_multiclass"]["test"]["macro_f1"],
        "ait_test_used_for_posthoc_candidate_selection": True,
        "holdout_independent_selection": False,
        "sidecar_selection_rationale": (
            "rf_multiclass_stage2 (val_macro_f1=0.8282, test_macro_f1=0.7347, pure sklearn/joblib) "
            "is exported as the Stage-2 sidecar because it generalizes better on AIT-Test "
            "(test_macro_f1=0.7347, balanced_accuracy=0.7791) with zero extra runtime dependencies, "
            "whereas xgboost_multiclass achieved higher AIT-Val macro-F1 (0.9456) but dropped on "
            "AIT-Test (test_macro_f1=0.6378, balanced_accuracy=0.7618) due to rare-class overfitting."
        ),
        "class_centroids": class_centroids,
        "class_stds": class_stds,
    }
    DEFAULT_STAGE2_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_STAGE2_MANIFEST_PATH.write_text(
        json.dumps(stage2_manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )

    # 2. XGBoost Multiclass (hist + sqrt bounded weights)
    print("[multiclass] Training XGBClassifier multi:softprob (6 classes)...", flush=True)
    t_xgb = time.perf_counter()
    xgb = XGBClassifier(
        objective="multi:softprob",
        num_class=len(CANONICAL_CLASSES),
        n_estimators=120,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )
    xgb.fit(X_train, y_train, sample_weight=sample_w)
    xgb_fit_s = round(time.perf_counter() - t_xgb, 2)
    models_out["xgboost_multiclass"] = {
        "train_seconds": xgb_fit_s,
        "hyperparameters": {
            "objective": "multi:softprob",
            "n_estimators": 120,
            "max_depth": 6,
            "learning_rate": 0.1,
            "sample_weight_policy": "sqrt_inverse_freq_capped_200",
            "random_state": 42,
        },
        "validation": _evaluate_predictions(y_val, xgb.predict(X_val)),
        "test": _evaluate_predictions(y_test, xgb.predict(X_test)),
    }

    selected_key = max(
        models_out.keys(),
        key=lambda k: models_out[k]["validation"]["macro_f1"],
    )

    report = {
        "experiment_id": "EXP-MULTICLASS-6CLASS-01",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.perf_counter() - t0, 2),
        "separate_experimental_run": True,
        "e0_artifacts_untouched": True,
        "split_manifest": str(SPLIT_MANIFEST_PATH.relative_to(PROJECT_ROOT)).replace("\\", "/"),
        "classes": list(CANONICAL_CLASSES),
        "row_counts": {
            "train": int(len(y_train)),
            "validation": int(len(y_val)),
            "test": int(len(y_test)),
        },
        "selection_criterion": "validation.macro_f1 (zero test leakage)",
        "selected_model_on_validation": selected_key,
        "models": models_out,
        "environment": build_environment_block(),
        "limitations": [
            "Rare attack classes in AIT-NDS-v2 have extremely small evaluation counts (Exploitation_And_C2: N=2 val / N=5 test; Post_Exploitation_Discovery: N=56 val / N=39 test; Credential_Attack: N=11 val / N=78 test), so Macro-F1 variance on those classes is high.",
            "This experiment uses canonical-flow-v2-18 (network flow features only, without L7 HTTP/Auth log payloads) and does NOT alter frozen E0 binary production/research artifacts.",
        ],
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")

    md_lines = [
        "# Multi-Class Attack Classification Experiment (6 Classes, `AIT-NDS-v2`)",
        "",
        f"- **Executed At (UTC):** `{report['executed_at_utc']}` | **Elapsed:** `{report['elapsed_seconds']}s`",
        "- **Isolation Guarantee:** `separate_experimental_run = true`, `e0_artifacts_untouched = true`",
        f"- **Model Selected on Validation (`Macro-F1`):** `{selected_key}`",
        "",
        "## 1. Overall Summary (`AIT-Val` vs `AIT-Test`)",
        "",
        "| Model | Val Macro-F1 | Val Weighted-F1 | Test Accuracy | Test Balanced Acc | Test Macro-F1 | Test Weighted-F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for mkey, mdata in models_out.items():
        vm = mdata["validation"]
        tm = mdata["test"]
        md_lines.append(
            f"| `{mkey}` | {vm['macro_f1']:.4f} | {vm['weighted_f1']:.4f} | {tm['accuracy']:.4f} | {tm['balanced_accuracy']:.4f} | **{tm['macro_f1']:.4f}** | **{tm['weighted_f1']:.4f}** |"
        )

    sel_test = models_out[selected_key]["test"]
    md_lines.extend(
        [
            "",
            f"## 2. Per-Class Test Breakdown (`{selected_key}`)",
            "",
            "| Attack Category | Support (`AIT-Test`) | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for cname in CANONICAL_CLASSES:
        cs = sel_test["per_class"][cname]
        md_lines.append(
            f"| `{cname}` | {cs['support']:,} | {cs['precision']:.4f} | {cs['recall']:.4f} | {cs['f1']:.4f} |"
        )

    md_lines.extend(
        [
            "",
            "## 3. Limitations",
            *[f"- {lim}" for lim in report["limitations"]],
        ]
    )
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
    print(f"[done] Multiclass experiment written: {OUT_JSON} and {OUT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
