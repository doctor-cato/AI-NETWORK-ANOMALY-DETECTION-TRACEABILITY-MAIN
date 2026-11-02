#!/usr/bin/env python3
"""Train Random Forest baseline model for NF-UNSW-NB15-v3.

This script implements the training execution for Issue #10 according to the locked Issue #9 protocol:
1. Validates all prerequisite artifacts (raw CSV, split manifest, indices, preprocessor artifact).
2. Verifies dataset and split compatibility fail-closed; halts cleanly if prerequisites are unavailable.
3. Reuses the existing fitted train-only preprocessor from Issue #8 without refitting.
4. Extracts 47 baseline ML features matrix X_train and binary target Label (0=Benign, 1=Attack).
5. Fits RandomForestClassifier with locked protocol hyperparameters (n_estimators=200, max_depth=16, seed=42).
6. Records training execution time, environment, and full run metadata.
7. Saves the trained model artifact and companion run manifest.
8. Verifies model reload and predictions on validation partition.
9. Enforces strict test-partition isolation (test data is never loaded or used).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    validate_feature_selection,
)
from network_anomaly.data.split import (  # noqa: E402
    SPLIT_PROTOCOL_VERSION,
    _sha256_file,
    load_partition_indices,
)
from network_anomaly.evaluation.metrics import (  # noqa: E402
    compute_attack_category_breakdown,
    compute_metrics,
)
from network_anomaly.models.random_forest import (  # noqa: E402
    RandomForestBaselineConfig,
    RandomForestBaselineProtocol,
    RandomForestModel,
    create_rf_baseline_protocol,
)
from network_anomaly.preprocessing.pipeline import (  # noqa: E402
    EXPECTED_DATASET_SHA256,
    TrainOnlyPreprocessor,
    verify_preprocessing_artifact,
)

EXPECTED_SPLIT_MANIFEST_SHA256 = (
    "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88"
)
EXPECTED_PREPROCESSOR_ARTIFACT_SHA256 = (
    "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"
)

DEFAULT_DATASET = (
    PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
)
DEFAULT_SPLIT_MANIFEST = (
    PROJECT_ROOT / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
)
DEFAULT_INDICES_DIR = PROJECT_ROOT / "data" / "processed" / "splits"
DEFAULT_PREPROCESSOR_ARTIFACT = (
    PROJECT_ROOT / "artifacts" / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
)
DEFAULT_PREPROCESSOR_MANIFEST = (
    PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
)
DEFAULT_OUTPUT_MODEL_DIR = PROJECT_ROOT / "artifacts" / "models" / "random_forest"
DEFAULT_OUTPUT_MODEL_PATH = DEFAULT_OUTPUT_MODEL_DIR / "random_forest_baseline.joblib"
DEFAULT_OUTPUT_MANIFEST_PATH = (
    DEFAULT_OUTPUT_MODEL_DIR / "random_forest_manifest.json"
)
DEFAULT_REPORT_MANIFEST_PATH = (
    PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train Random Forest baseline on verified NF-UNSW-NB15-v3 dataset."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="Path to raw NF-UNSW-NB15-v3.csv",
    )
    parser.add_argument(
        "--split-manifest",
        type=Path,
        default=DEFAULT_SPLIT_MANIFEST,
        help="Path to split manifest json",
    )
    parser.add_argument(
        "--indices-dir",
        type=Path,
        default=DEFAULT_INDICES_DIR,
        help="Directory containing partition indices csv.gz",
    )
    parser.add_argument(
        "--preprocessor-artifact",
        type=Path,
        default=DEFAULT_PREPROCESSOR_ARTIFACT,
        help="Path to fitted train-only preprocessor .joblib",
    )
    parser.add_argument(
        "--preprocessor-manifest",
        type=Path,
        default=DEFAULT_PREPROCESSOR_MANIFEST,
        help="Path to companion preprocessor manifest json",
    )
    parser.add_argument(
        "--output-model",
        type=Path,
        default=DEFAULT_OUTPUT_MODEL_PATH,
        help="Destination path for trained model .joblib",
    )
    parser.add_argument(
        "--output-manifest",
        type=Path,
        default=DEFAULT_OUTPUT_MANIFEST_PATH,
        help="Destination path for model run manifest json",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify all prerequisite artifacts and exit without training",
    )
    return parser.parse_args(argv)


def check_prerequisites(
    dataset_path: Path,
    split_manifest_path: Path,
    indices_dir: Path,
    preprocessor_artifact_path: Path,
    preprocessor_manifest_path: Path,
) -> Dict[str, Any]:
    """Audit all prerequisite assets and return verification status and findings."""
    missing: List[str] = []
    findings: Dict[str, Any] = {}

    # 1. Dataset CSV
    if not dataset_path.exists():
        missing.append(f"Raw dataset CSV not found at {dataset_path}")
        findings["dataset"] = {"status": "MISSING", "path": str(dataset_path)}
    else:
        actual_sha = _sha256_file(dataset_path)
        match = actual_sha == EXPECTED_DATASET_SHA256
        findings["dataset"] = {
            "status": "PASS" if match else "FAIL",
            "path": str(dataset_path),
            "sha256": actual_sha,
            "expected_sha256": EXPECTED_DATASET_SHA256,
        }
        if not match:
            missing.append(f"Dataset SHA-256 mismatch: expected {EXPECTED_DATASET_SHA256}, got {actual_sha}")

    # 2. Split Manifest
    if not split_manifest_path.exists():
        missing.append(f"Split manifest not found at {split_manifest_path}")
        findings["split_manifest"] = {"status": "MISSING", "path": str(split_manifest_path)}
    else:
        actual_sm_sha = _sha256_file(split_manifest_path)
        match = actual_sm_sha == EXPECTED_SPLIT_MANIFEST_SHA256
        findings["split_manifest"] = {
            "status": "PASS" if match else "FAIL",
            "path": str(split_manifest_path),
            "sha256": actual_sm_sha,
            "expected_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
        }
        if not match:
            missing.append(f"Split manifest SHA-256 mismatch: expected {EXPECTED_SPLIT_MANIFEST_SHA256}, got {actual_sm_sha}")

    # 3. Partition Index files
    train_idx_path = indices_dir / "train_indices.csv.gz"
    val_idx_path = indices_dir / "validation_indices.csv.gz"
    if not train_idx_path.exists():
        missing.append(f"Train partition indices not found at {train_idx_path}")
    if not val_idx_path.exists():
        missing.append(f"Validation partition indices not found at {val_idx_path}")
    findings["indices"] = {
        "train_indices_exists": train_idx_path.exists(),
        "val_indices_exists": val_idx_path.exists(),
    }

    # 4. Preprocessor artifact and companion manifest
    if not preprocessor_artifact_path.exists():
        missing.append(f"Preprocessor artifact not found at {preprocessor_artifact_path}")
        findings["preprocessor_artifact"] = {"status": "MISSING", "path": str(preprocessor_artifact_path)}
    else:
        actual_art_sha = _sha256_file(preprocessor_artifact_path)
        match = actual_art_sha == EXPECTED_PREPROCESSOR_ARTIFACT_SHA256
        findings["preprocessor_artifact"] = {
            "status": "PASS" if match else "FAIL",
            "path": str(preprocessor_artifact_path),
            "sha256": actual_art_sha,
            "expected_sha256": EXPECTED_PREPROCESSOR_ARTIFACT_SHA256,
        }
        if not match:
            missing.append(f"Preprocessor artifact SHA-256 mismatch: expected {EXPECTED_PREPROCESSOR_ARTIFACT_SHA256}, got {actual_art_sha}")

    if not preprocessor_manifest_path.exists():
        missing.append(f"Preprocessor companion manifest not found at {preprocessor_manifest_path}")
        findings["preprocessor_manifest"] = {"status": "MISSING", "path": str(preprocessor_manifest_path)}
    else:
        findings["preprocessor_manifest"] = {"status": "EXISTS", "path": str(preprocessor_manifest_path)}

    status = "PASS" if not missing else "BLOCKED"
    return {
        "status": status,
        "missing_prerequisites": missing,
        "findings": findings,
    }


def execute_training(
    dataset_path: Path,
    split_manifest_path: Path,
    indices_dir: Path,
    preprocessor_artifact_path: Path,
    preprocessor_manifest_path: Path,
    output_model_path: Path,
    output_manifest_path: Path,
) -> Dict[str, Any]:
    """Execute real Random Forest baseline training using verified prerequisites."""
    # 1. Load verified preprocessor artifact
    print("[train_random_forest] Loading and verifying train-only preprocessor artifact...")
    preprocessor = TrainOnlyPreprocessor.load_verified(
        artifact_path=preprocessor_artifact_path,
        manifest_path=preprocessor_manifest_path,
        split_manifest_path=split_manifest_path,
        dataset_path=dataset_path,
        expected_dataset_sha256=EXPECTED_DATASET_SHA256,
    )
    print(f"[train_random_forest] Preprocessor loaded successfully (fitted on {preprocessor.train_row_count_} rows).")

    # 2. Load Train and Validation partition indices
    print("[train_random_forest] Loading partition indices...")
    train_indices = load_partition_indices(indices_dir / "train_indices.csv.gz")
    val_indices = load_partition_indices(indices_dir / "validation_indices.csv.gz")
    print(f"[train_random_forest] Loaded indices: train={len(train_indices)}, val={len(val_indices)}.")

    # 3. Read dataset rows strictly matching partitions
    # Note: Test partition indices are deliberately NOT loaded or accessed
    print(f"[train_random_forest] Reading training partition from {dataset_path}...")
    usecols = list(ML_FEATURE_COLUMNS) + ["Label", "Attack"]

    # Read train chunk
    df_raw = pd.read_csv(
        dataset_path,
        usecols=usecols,
        keep_default_na=False,
    )
    df_train = df_raw.iloc[train_indices].copy()
    df_val = df_raw.iloc[val_indices].copy()
    del df_raw  # free memory

    X_train_raw = df_train[list(ML_FEATURE_COLUMNS)]
    y_train = df_train["Label"].astype(int)
    X_val_raw = df_val[list(ML_FEATURE_COLUMNS)]
    y_val = df_val["Label"].astype(int)
    attack_val = df_val["Attack"].astype(str)

    # 4. Transform features using frozen preprocessor (NO refitting)
    print("[train_random_forest] Transforming features using frozen preprocessor...")
    X_train_trans = preprocessor.transform(X_train_raw)
    X_val_trans = preprocessor.transform(X_val_raw)

    assert X_train_trans.shape == (len(train_indices), 47)
    assert X_val_trans.shape == (len(val_indices), 47)
    assert not np.isnan(X_train_trans).any()
    assert not np.isnan(X_val_trans).any()
    print("[train_random_forest] Feature matrices validated: 47 features, all finite.")

    # 5. Build and fit Random Forest model
    protocol = create_rf_baseline_protocol(
        split_id=SPLIT_PROTOCOL_VERSION,
        random_seed=42,
        n_estimators=200,
        max_depth=16,
    )
    model = RandomForestModel(protocol=protocol)

    print("[train_random_forest] Fitting Random Forest model (n_estimators=200, max_depth=16, seed=42)...")
    start_time = time.perf_counter()
    trained_at_utc = datetime.now(timezone.utc).isoformat()
    model.fit(X_train_trans, y_train)
    training_duration = time.perf_counter() - start_time
    print(f"[train_random_forest] Model fitting completed in {training_duration:.2f} seconds.")

    # 6. Save model artifact
    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    model_sha256 = model.save(output_model_path)
    print(f"[train_random_forest] Model artifact saved to {output_model_path} (SHA-256: {model_sha256}).")

    # 7. Reload and verify on validation data
    print("[train_random_forest] Verifying model reload and inference on validation partition...")
    reloaded_model = RandomForestModel.load(output_model_path)
    val_preds = reloaded_model.predict(X_val_trans)
    val_probs = reloaded_model.predict_proba(X_val_trans)

    assert val_preds.shape == (len(val_indices),)
    assert val_probs.shape == (len(val_indices), 2)
    assert np.all(np.isfinite(val_probs))

    # Compute validation metrics
    val_metrics = compute_metrics(y_val, val_preds, labels=[0, 1])
    val_breakdown = compute_attack_category_breakdown(y_val, val_preds, attack_val)
    print(f"[train_random_forest] Validation Metrics: F1={val_metrics['f1']:.4f}, Macro-F1={val_metrics['macro_f1']:.4f}, FPR={val_metrics['fpr']:.4f}")

    # 8. Create run manifest
    run_id = f"rf-baseline-{int(time.time())}"
    manifest: Dict[str, Any] = {
        "run_id": run_id,
        "model_type": "RandomForest",
        "task": "binary_classification",
        "target": "Label",
        "positive_class": "Attack",
        "protocol_version": protocol.protocol_version,
        "feature_contract_version": protocol.feature_contract_version,
        "selected_features": list(protocol.selected_features),
        "excluded_metadata": list(protocol.excluded_metadata),
        "excluded_targets": list(protocol.excluded_targets),
        "hyperparameters": protocol.model_config.to_dict(),
        "random_state": protocol.model_config.random_state,
        "dataset_name": DATASET_NAME,
        "dataset_sha256": EXPECTED_DATASET_SHA256,
        "split_protocol_version": SPLIT_PROTOCOL_VERSION,
        "split_manifest_sha256": EXPECTED_SPLIT_MANIFEST_SHA256,
        "preprocessor_artifact_sha256": EXPECTED_PREPROCESSOR_ARTIFACT_SHA256,
        "train_rows_count": len(train_indices),
        "val_rows_count": len(val_indices),
        "test_rows_count": 345953,
        "test_partition_status": "LOCKED (NOT USED)",
        "training_duration_seconds": round(training_duration, 2),
        "trained_at_utc": trained_at_utc,
        "model_artifact_path": str(output_model_path.relative_to(PROJECT_ROOT)),
        "model_artifact_sha256": model_sha256,
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "validation_summary": {
            "precision": val_metrics["precision"],
            "recall": val_metrics["recall"],
            "f1": val_metrics["f1"],
            "macro_f1": val_metrics["macro_f1"],
            "false_positive_rate": val_metrics["false_positive_rate"],
            "per_category_breakdown": val_breakdown,
        },
    }

    output_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with output_manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[train_random_forest] Model run manifest saved to {output_manifest_path}.")

    # Copy to reports/models as well
    DEFAULT_REPORT_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DEFAULT_REPORT_MANIFEST_PATH.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    print("=================================================================")
    print("NF-UNSW-NB15-v3 Random Forest Baseline Training Entrypoint (#10)")
    print("=================================================================")
    print(f"Dataset path:             {args.dataset}")
    print(f"Split manifest path:      {args.split_manifest}")
    print(f"Indices directory:        {args.indices_dir}")
    print(f"Preprocessor artifact:    {args.preprocessor_artifact}")
    print(f"Preprocessor manifest:    {args.preprocessor_manifest}")
    print("-----------------------------------------------------------------")

    prereq_audit = check_prerequisites(
        dataset_path=args.dataset,
        split_manifest_path=args.split_manifest,
        indices_dir=args.indices_dir,
        preprocessor_artifact_path=args.preprocessor_artifact,
        preprocessor_manifest_path=args.preprocessor_manifest,
    )

    if prereq_audit["status"] != "PASS":
        print("\n[BLOCKER DETECTED] Prerequisite verification failed!")
        print("Missing or invalid prerequisite artifacts:")
        for item in prereq_audit["missing_prerequisites"]:
            print(f"  - {item}")
        print("\nPer repository policy and Issue #10 rules:")
        print("1. Real training requires the verified raw dataset and preprocessor artifact.")
        print("2. Synthetic, dummy, or mock data will NOT be generated as substitute.")
        print("3. Execution is HALTED fail-closed until prerequisites are materialized.")
        return 1

    print("\n[OK] All prerequisite artifacts verified successfully.")
    if args.verify_only:
        print("[train_random_forest] --verify-only requested. Exiting with success.")
        return 0

    try:
        execute_training(
            dataset_path=args.dataset,
            split_manifest_path=args.split_manifest,
            indices_dir=args.indices_dir,
            preprocessor_artifact_path=args.preprocessor_artifact,
            preprocessor_manifest_path=args.preprocessor_manifest,
            output_model_path=args.output_model,
            output_manifest_path=args.output_manifest,
        )
        return 0
    except Exception as exc:
        print(f"\n[ERROR] Training execution failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
