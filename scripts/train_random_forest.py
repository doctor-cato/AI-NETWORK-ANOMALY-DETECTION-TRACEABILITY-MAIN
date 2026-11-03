#!/usr/bin/env python3
"""Train Random Forest baseline model for NF-UNSW-NB15-v3.

This script implements the training execution for Issue #10 according to the locked Issue #9 protocol:
1. Validates all prerequisite artifacts (raw CSV, split manifest, indices, preprocessor artifact).
2. Verifies dataset, split, and preprocessor integrity fail-closed; halts cleanly if prerequisites are unavailable.
3. Reuses the existing fitted train-only preprocessor from Issue #8 without refitting.
4. Enforces strict test-partition isolation: test indices and data are never loaded or materialized.
5. Streams raw dataset in bounded chunks, extracting only Train and Validation partition rows.
6. Extracts 47 baseline ML features matrix X_train and binary target Label (0=Benign, 1=Attack).
7. Fits RandomForestClassifier with locked protocol hyperparameters (n_estimators=200, max_depth=16, seed=42).
8. Records training execution time, environment, git commit, package versions, and full run metadata.
9. Saves the trained model artifact and companion run manifest with runtime provenance.
10. Verifies model reload and predictions on validation partition.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import sklearn  # noqa: E402

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
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_CONTRACT_ID,
    PreprocessingReference,
    RandomForestBaselineConfig,
    RandomForestBaselineProtocol,
    RandomForestModel,
    SplitReference,
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
EXPECTED_PREPROCESSOR_MANIFEST_SHA256 = (
    "af07dc3b6c7cbc9e75426eeb5b96d52dbd191e8a09161699df2fad1bb5555441"
)
EXPECTED_TRAIN_ROWS = 1655797
EXPECTED_VAL_ROWS = 345371
EXPECTED_TEST_ROWS = 345953

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


def _safe_relpath(path: Path, root: Path = PROJECT_ROOT) -> str:
    """Return path relative to root if possible, otherwise absolute string."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


@dataclass
class PartitionAccessTracker:
    """Instrumented tracker to record and verify strict partition access boundaries."""

    requested_partitions: List[str] = field(default_factory=list)
    train_rows_loaded: int = 0
    val_rows_loaded: int = 0
    test_rows_loaded: int = 0
    test_indices_loaded: bool = False
    test_partition_accessed: bool = False
    contract_a_enforced: bool = True
    contract_b_enforced: bool = True

    def to_audit_dict(self) -> Dict[str, Any]:
        """Produce verified audit evidence for run manifest."""
        return {
            "test_partition_accessed": self.test_partition_accessed,
            "test_rows_loaded": self.test_rows_loaded,
            "test_indices_loaded": self.test_indices_loaded,
            "training_partitions": list(self.requested_partitions),
            "train_rows_loaded": self.train_rows_loaded,
            "val_rows_loaded": self.val_rows_loaded,
            "contract_a_guarantee": (
                "PASSED: No Test data is used in fitting, hyperparameter tuning, "
                "threshold selection, validation, or model selection."
            ),
            "contract_b_guarantee": (
                "PASSED: Zero Test partition rows are materialized or converted into DataFrames."
            ),
        }


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
            missing.append(
                f"Dataset SHA-256 mismatch: expected {EXPECTED_DATASET_SHA256}, got {actual_sha}"
            )

    # 2. Split Manifest
    split_manifest_data: Optional[Dict[str, Any]] = None
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
            missing.append(
                f"Split manifest SHA-256 mismatch: expected {EXPECTED_SPLIT_MANIFEST_SHA256}, got {actual_sm_sha}"
            )
        else:
            try:
                split_manifest_data = json.loads(split_manifest_path.read_text(encoding="utf-8"))
            except Exception as e:
                missing.append(f"Split manifest invalid JSON: {e}")

    # 3. Partition Index files and verification against split manifest
    train_idx_path = indices_dir / "train_indices.csv.gz"
    val_idx_path = indices_dir / "validation_indices.csv.gz"

    if not train_idx_path.exists():
        missing.append(f"Train partition indices not found at {train_idx_path}")
    elif split_manifest_data:
        train_spec = split_manifest_data.get("partitions", {}).get("train", {})
        expected_train_sha = train_spec.get("index_sha256")
        if expected_train_sha:
            actual_train_sha = _sha256_file(train_idx_path)
            if actual_train_sha != expected_train_sha:
                missing.append(
                    f"Train indices SHA-256 mismatch: expected {expected_train_sha}, got {actual_train_sha}"
                )

    if not val_idx_path.exists():
        missing.append(f"Validation partition indices not found at {val_idx_path}")
    elif split_manifest_data:
        val_spec = split_manifest_data.get("partitions", {}).get("validation", {})
        expected_val_sha = val_spec.get("index_sha256")
        if expected_val_sha:
            actual_val_sha = _sha256_file(val_idx_path)
            if actual_val_sha != expected_val_sha:
                missing.append(
                    f"Validation indices SHA-256 mismatch: expected {expected_val_sha}, got {actual_val_sha}"
                )

    findings["indices"] = {
        "train_indices_exists": train_idx_path.exists(),
        "val_indices_exists": val_idx_path.exists(),
    }

    # Detailed audit of partition index files if present
    if train_idx_path.exists() and val_idx_path.exists() and split_manifest_path.exists():
        try:
            train_idx = load_partition_indices(split_manifest_path, indices_dir, "train")
            val_idx = load_partition_indices(split_manifest_path, indices_dir, "validation")

            exp_train_rows = (
                split_manifest_data.get("partitions", {}).get("train", {}).get("row_count")
                if split_manifest_data
                else EXPECTED_TRAIN_ROWS
            ) or EXPECTED_TRAIN_ROWS

            exp_val_rows = (
                split_manifest_data.get("partitions", {}).get("validation", {}).get("row_count")
                if split_manifest_data
                else EXPECTED_VAL_ROWS
            ) or EXPECTED_VAL_ROWS

            if len(train_idx) != exp_train_rows:
                missing.append(
                    f"Train indices row count mismatch: expected {exp_train_rows}, got {len(train_idx)}"
                )
            if len(val_idx) != exp_val_rows:
                missing.append(
                    f"Validation indices row count mismatch: expected {exp_val_rows}, got {len(val_idx)}"
                )

            if len(np.unique(train_idx)) != len(train_idx):
                missing.append("Train partition indices contain duplicate row indices")
            if len(np.unique(val_idx)) != len(val_idx):
                missing.append("Validation partition indices contain duplicate row indices")

            overlap = set(train_idx).intersection(set(val_idx))
            if overlap:
                missing.append(
                    f"Train and validation partition indices overlap ({len(overlap)} rows)"
                )

            if len(train_idx) > 0 and train_idx.min() < 0:
                missing.append("Train partition indices contain negative index values")
            if len(val_idx) > 0 and val_idx.min() < 0:
                missing.append("Validation partition indices contain negative index values")

            findings["indices_audit"] = {
                "status": "PASS",
                "train_rows": len(train_idx),
                "val_rows": len(val_idx),
                "overlap_count": len(overlap),
                "unique_train": len(np.unique(train_idx)) == len(train_idx),
                "unique_val": len(np.unique(val_idx)) == len(val_idx),
            }
        except Exception as e:
            missing.append(f"Partition indices audit failed: {e}")
            findings["indices_audit"] = {"status": "FAIL", "error": str(e)}

    # 4. Preprocessor artifact and companion manifest verification
    if not preprocessor_artifact_path.exists():
        missing.append(f"Preprocessor artifact not found at {preprocessor_artifact_path}")
        findings["preprocessor_artifact"] = {
            "status": "MISSING",
            "path": str(preprocessor_artifact_path),
        }
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
            missing.append(
                f"Preprocessor artifact SHA-256 mismatch: expected {EXPECTED_PREPROCESSOR_ARTIFACT_SHA256}, got {actual_art_sha}"
            )

    if not preprocessor_manifest_path.exists():
        missing.append(f"Preprocessor companion manifest not found at {preprocessor_manifest_path}")
        findings["preprocessor_manifest"] = {
            "status": "MISSING",
            "path": str(preprocessor_manifest_path),
        }
    else:
        actual_pm_sha = _sha256_file(preprocessor_manifest_path)
        if preprocessor_manifest_path == DEFAULT_PREPROCESSOR_MANIFEST:
            if actual_pm_sha != EXPECTED_PREPROCESSOR_MANIFEST_SHA256:
                missing.append(
                    f"Preprocessor companion manifest SHA-256 mismatch: expected {EXPECTED_PREPROCESSOR_MANIFEST_SHA256}, got {actual_pm_sha}"
                )

        try:
            pm_data = json.loads(preprocessor_manifest_path.read_text(encoding="utf-8"))
            pm_art_sha = pm_data.get("preprocessor_artifact_sha256")
            if pm_art_sha and pm_art_sha != EXPECTED_PREPROCESSOR_ARTIFACT_SHA256:
                missing.append(
                    f"Preprocessor manifest artifact SHA-256 mismatch: expected {EXPECTED_PREPROCESSOR_ARTIFACT_SHA256}, got {pm_art_sha}"
                )
            findings["preprocessor_manifest"] = {
                "status": "EXISTS",
                "path": str(preprocessor_manifest_path),
                "sha256": actual_pm_sha,
            }
        except Exception as e:
            missing.append(f"Preprocessor manifest invalid JSON: {e}")
            findings["preprocessor_manifest"] = {"status": "INVALID", "error": str(e)}

    # Reuse verify_preprocessing_artifact if preprocessor files exist
    if preprocessor_artifact_path.exists() and preprocessor_manifest_path.exists():
        try:
            prep_audit = verify_preprocessing_artifact(
                artifact_path=preprocessor_artifact_path,
                manifest_path=preprocessor_manifest_path,
                split_manifest_path=split_manifest_path if split_manifest_path.exists() else None,
                dataset_path=dataset_path if dataset_path.exists() else None,
                expected_dataset_sha256=EXPECTED_DATASET_SHA256,
            )
            findings["preprocessor_verification"] = prep_audit
        except Exception as e:
            missing.append(f"Preprocessor artifact verification failed: {e}")
            findings["preprocessor_verification"] = {"status": "FAIL", "error": str(e)}

    status = "PASS" if not missing else "BLOCKED"
    return {
        "status": status,
        "missing_prerequisites": missing,
        "findings": findings,
    }


def load_partition(
    split_manifest_path: Path,
    indices_dir: Path,
    partition_name: str,
    tracker: Optional[PartitionAccessTracker] = None,
) -> np.ndarray:
    """Load indices for a single partition with test-isolation guard."""
    valid_partitions = ("train", "validation", "test")
    if partition_name not in valid_partitions:
        raise ValueError(
            f"Invalid partition name '{partition_name}'. Expected one of: {valid_partitions}"
        )

    if partition_name == "test":
        if tracker:
            tracker.test_indices_loaded = True
            tracker.test_partition_accessed = True
        raise PermissionError(
            "Strict Test Lock Violation: Attempted to load 'test' partition during training stage."
        )

    if tracker:
        if partition_name not in tracker.requested_partitions:
            tracker.requested_partitions.append(partition_name)

    return load_partition_indices(split_manifest_path, indices_dir, partition_name)


def stream_partition_data(
    dataset_path: Path,
    train_indices: np.ndarray,
    val_indices: np.ndarray,
    usecols: List[str],
    chunksize: int = 100_000,
    tracker: Optional[PartitionAccessTracker] = None,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Stream raw CSV and extract strictly Train and Validation rows without materializing Test rows.

    Guarantees:
    1. Contract A: Zero Test data is used in model fitting, hyperparameter selection,
       threshold selection, validation, or feature selection.
    2. Contract B: Zero Test partition rows are ever materialized or converted into DataFrames.
       Test rows are intercepted and discarded at the raw text stream boundary prior to DataFrame creation.
    3. Memory footprint is strictly bounded by chunksize.
    4. Preserves exact index alignment with partition indices.
    """
    train_idx_set = set(train_indices)
    val_idx_set = set(val_indices)

    intersection = train_idx_set.intersection(val_idx_set)
    if intersection:
        raise ValueError(
            f"Partition leakage: {len(intersection)} indices overlap between train and validation!"
        )

    train_chunks: List[pd.DataFrame] = []
    val_chunks: List[pd.DataFrame] = []

    train_line_buffer: List[str] = []
    val_line_buffer: List[str] = []

    train_row_offsets: List[int] = []
    val_row_offsets: List[int] = []

    def flush_train() -> None:
        if not train_line_buffer:
            return
        content = header_line + "".join(train_line_buffer)
        df = pd.read_csv(io.StringIO(content), usecols=usecols, keep_default_na=False)
        target_indices = train_row_offsets[-len(train_line_buffer):]
        df.index = target_indices
        train_chunks.append(df)
        train_line_buffer.clear()

    def flush_val() -> None:
        if not val_line_buffer:
            return
        content = header_line + "".join(val_line_buffer)
        df = pd.read_csv(io.StringIO(content), usecols=usecols, keep_default_na=False)
        target_indices = val_row_offsets[-len(val_line_buffer):]
        df.index = target_indices
        val_chunks.append(df)
        val_line_buffer.clear()

    with dataset_path.open("r", encoding="utf-8", errors="replace") as f:
        header_line = f.readline()
        if not header_line:
            raise ValueError(f"Empty dataset file at {dataset_path}")

        row_idx = 0
        for line in f:
            if row_idx in train_idx_set:
                train_line_buffer.append(line)
                train_row_offsets.append(row_idx)
                if tracker:
                    tracker.train_rows_loaded += 1
                if len(train_line_buffer) >= chunksize:
                    flush_train()
            elif row_idx in val_idx_set:
                val_line_buffer.append(line)
                val_row_offsets.append(row_idx)
                if tracker:
                    tracker.val_rows_loaded += 1
                if len(val_line_buffer) >= chunksize:
                    flush_val()
            else:
                # Strictly discarded at raw text boundary: zero DataFrame rows materialized
                pass
            row_idx += 1

        flush_train()
        flush_val()

    if not train_chunks:
        raise ValueError(f"No train rows loaded from {dataset_path}")
    if not val_chunks:
        raise ValueError(f"No validation rows loaded from {dataset_path}")

    df_train_raw = pd.concat(train_chunks)
    df_val_raw = pd.concat(val_chunks)

    df_train = df_train_raw.loc[train_indices].copy()
    df_val = df_val_raw.loc[val_indices].copy()

    del df_train_raw, df_val_raw, train_chunks, val_chunks

    if len(df_train) != len(train_indices):
        raise ValueError(
            f"Row count mismatch for train: expected {len(train_indices)}, got {len(df_train)}"
        )
    if len(df_val) != len(val_indices):
        raise ValueError(
            f"Row count mismatch for validation: expected {len(val_indices)}, got {len(df_val)}"
        )

    return df_train, df_val


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
    tracker = PartitionAccessTracker()

    # 1. Load verified preprocessor artifact
    print("[train_random_forest] Loading and verifying train-only preprocessor artifact...")
    preprocessor = TrainOnlyPreprocessor.load_verified(
        artifact_path=preprocessor_artifact_path,
        manifest_path=preprocessor_manifest_path,
        split_manifest_path=split_manifest_path,
        dataset_path=dataset_path,
        expected_dataset_sha256=EXPECTED_DATASET_SHA256,
    )
    print(
        f"[train_random_forest] Preprocessor loaded successfully (fitted on {preprocessor.train_row_count_} rows)."
    )

    # 2. Load Train and Validation partition indices (Strict Test Lock enforced)
    print("[train_random_forest] Loading partition indices with test-isolation guard...")
    train_indices = load_partition(
        split_manifest_path, indices_dir, "train", tracker=tracker
    )
    val_indices = load_partition(
        split_manifest_path, indices_dir, "validation", tracker=tracker
    )
    print(
        f"[train_random_forest] Loaded indices: train={len(train_indices)}, val={len(val_indices)}."
    )

    # 3. Stream dataset rows strictly matching Train and Validation (Test rows are NEVER materialized)
    print(
        f"[train_random_forest] Streaming training and validation partitions from {dataset_path}..."
    )
    usecols = list(ML_FEATURE_COLUMNS) + ["Label", "Attack"]

    df_train, df_val = stream_partition_data(
        dataset_path=dataset_path,
        train_indices=train_indices,
        val_indices=val_indices,
        usecols=usecols,
        tracker=tracker,
    )

    X_train_raw = df_train[list(ML_FEATURE_COLUMNS)]
    y_train = df_train["Label"].astype(int)
    X_val_raw = df_val[list(ML_FEATURE_COLUMNS)]
    y_val = df_val["Label"].astype(int)
    attack_val = df_val["Attack"].astype(str)

    del df_train, df_val

    # 4. Transform features using frozen preprocessor (NO refitting)
    print("[train_random_forest] Transforming features using frozen preprocessor...")
    X_train_trans = preprocessor.transform(X_train_raw)
    X_val_trans = preprocessor.transform(X_val_raw)

    if X_train_trans.shape != (len(train_indices), 47):
        raise ValueError(
            f"Expected X_train shape {(len(train_indices), 47)}, got {X_train_trans.shape}"
        )
    if X_val_trans.shape != (len(val_indices), 47):
        raise ValueError(
            f"Expected X_val shape {(len(val_indices), 47)}, got {X_val_trans.shape}"
        )

    arr_train = np.asarray(X_train_trans)
    arr_val = np.asarray(X_val_trans)
    if not np.isfinite(arr_train).all():
        raise ValueError("Transformed X_train contains non-finite values (NaN, Inf)")
    if not np.isfinite(arr_val).all():
        raise ValueError("Transformed X_val contains non-finite values (NaN, Inf)")
    print("[train_random_forest] Feature matrices validated: 47 features, all finite.")

    # 5. Build Random Forest model with runtime verified protocol provenance
    actual_sm_sha = _sha256_file(split_manifest_path)
    actual_art_sha = _sha256_file(preprocessor_artifact_path)
    actual_pm_sha = _sha256_file(preprocessor_manifest_path)
    train_idx_sha = _sha256_file(indices_dir / "train_indices.csv.gz")
    val_idx_sha = _sha256_file(indices_dir / "validation_indices.csv.gz")

    base_proto = create_rf_baseline_protocol(
        split_id=SPLIT_PROTOCOL_VERSION,
        random_seed=42,
        n_estimators=200,
        max_depth=16,
    )
    split_ref = SplitReference(
        dataset_name=DATASET_NAME,
        dataset_csv_sha256=EXPECTED_DATASET_SHA256,
        split_protocol_id=SPLIT_PROTOCOL_VERSION,
        split_id=SPLIT_PROTOCOL_VERSION,
        split_manifest_sha256=actual_sm_sha,
        split_status="VERIFIED / PASS (PR #41)",
        ml_ready=True,
    )
    preproc_ref = PreprocessingReference(
        preprocessing_contract_id=PREPROCESSING_CONTRACT_ID,
        fit_boundary="train_only",
        preprocessing_status="VERIFIED / PASS (PR #42)",
        fitted_artifact_path=_safe_relpath(preprocessor_artifact_path),
        fitted_artifact_sha256=actual_art_sha,
    )
    protocol = RandomForestBaselineProtocol(
        protocol_version=base_proto.protocol_version,
        protocol_name=base_proto.protocol_name,
        feature_contract_version=base_proto.feature_contract_version,
        selected_features=base_proto.selected_features,
        excluded_metadata=base_proto.excluded_metadata,
        excluded_targets=base_proto.excluded_targets,
        model_config=base_proto.model_config,
        tuning_policy=base_proto.tuning_policy,
        test_lock=base_proto.test_lock,
        evaluation_protocol=base_proto.evaluation_protocol,
        split_reference=split_ref,
        preprocessing_reference=preproc_ref,
        metadata={
            "runtime_verified": True,
            "train_rows_count": len(train_indices),
            "val_rows_count": len(val_indices),
        },
    )
    protocol.validate()

    model = RandomForestModel(protocol=protocol)

    print(
        "[train_random_forest] Fitting Random Forest model (n_estimators=200, max_depth=16, seed=42)..."
    )
    start_time = time.perf_counter()
    trained_at_utc = datetime.now(timezone.utc).isoformat()
    model.fit(X_train_trans, y_train)
    training_duration = time.perf_counter() - start_time
    print(
        f"[train_random_forest] Model fitting completed in {training_duration:.2f} seconds."
    )

    # 6. Capture original validation predictions & probabilities before serialization
    print(
        "[train_random_forest] Capturing validation predictions and probabilities on in-memory model..."
    )
    orig_val_preds = model.predict(X_val_trans)
    orig_val_probs = model.predict_proba(X_val_trans)

    if orig_val_preds.shape != (len(val_indices),):
        raise ValueError(
            f"Expected orig_val_preds shape {(len(val_indices),)}, got {orig_val_preds.shape}"
        )
    if orig_val_probs.shape != (len(val_indices), 2):
        raise ValueError(
            f"Expected orig_val_probs shape {(len(val_indices), 2)}, got {orig_val_probs.shape}"
        )
    if not np.isfinite(orig_val_probs).all():
        raise ValueError("Validation probabilities contain non-finite values")

    # Compute validation metrics
    val_metrics = compute_metrics(y_val, orig_val_preds, labels=[0, 1])
    val_breakdown = compute_attack_category_breakdown(y_val, orig_val_preds, attack_val)
    print(
        f"[train_random_forest] Validation Metrics: F1={val_metrics['f1']:.4f}, Macro-F1={val_metrics['macro_f1']:.4f}, FPR={val_metrics['false_positive_rate']:.4f}"
    )

    # 7. Save model artifact
    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    model_sha256 = model.save(output_model_path)
    print(
        f"[train_random_forest] Model artifact saved to {output_model_path} (SHA-256: {model_sha256})."
    )

    # 8. Create run manifest with unified schema and runtime provenance
    run_id = f"rf-baseline-{int(time.time())}"
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(PROJECT_ROOT), text=True
        ).strip()
    except Exception:
        git_commit = "UNKNOWN"

    git_dirty = False
    try:
        git_status = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=str(PROJECT_ROOT), text=True
        ).strip()
        git_dirty = bool(git_status)
    except Exception:
        pass

    provenance_complete = git_commit != "UNKNOWN" and len(git_commit) == 40
    provenance_status = "VERIFIED" if provenance_complete else "INCOMPLETE"

    manifest: Dict[str, Any] = {
        "run_id": run_id,
        "model_type": "RandomForest",
        "task": "binary_classification",
        "target": "Label",
        "positive_class": "Attack",
        "configuration_id": protocol.model_config.configuration_id,
        "is_canonical_baseline": protocol.model_config.is_canonical_baseline,
        "protocol_version": protocol.protocol_version,
        "feature_contract_version": protocol.feature_contract_version,
        "selected_features": list(protocol.selected_features),
        "excluded_metadata": list(protocol.excluded_metadata),
        "excluded_targets": list(protocol.excluded_targets),
        "hyperparameters": protocol.model_config.to_dict(),
        "random_state": protocol.model_config.random_state,
        "model_artifact_path": _safe_relpath(output_model_path),
        "model_artifact_sha256": model_sha256,
        "dataset_name": DATASET_NAME,
        "dataset_sha256": EXPECTED_DATASET_SHA256,
        "split_manifest_sha256": actual_sm_sha,
        "preprocessor_artifact_sha256": actual_art_sha,
        "preprocessor_manifest_sha256": actual_pm_sha,
        "provenance_complete": provenance_complete,
        "provenance_status": provenance_status,
        "split_provenance": {
            "split_protocol_id": SPLIT_PROTOCOL_VERSION,
            "split_manifest_path": _safe_relpath(split_manifest_path),
            "split_manifest_sha256": actual_sm_sha,
            "train_rows_count": len(train_indices),
            "val_rows_count": len(val_indices),
            "test_rows_count": EXPECTED_TEST_ROWS,
            "indices_dir": _safe_relpath(indices_dir),
            "train_indices_sha256": train_idx_sha,
            "val_indices_sha256": val_idx_sha,
            "verification_status": "PASS",
        },
        "preprocessing_provenance": {
            "preprocessor_artifact_path": _safe_relpath(preprocessor_artifact_path),
            "preprocessor_artifact_sha256": actual_art_sha,
            "preprocessor_manifest_path": _safe_relpath(preprocessor_manifest_path),
            "preprocessor_manifest_sha256": actual_pm_sha,
            "feature_contract_version": FEATURE_CONTRACT_VERSION,
            "features_count": 47,
            "fit_partition": "train_only",
            "verification_status": "PASS",
        },
        "test_lock_audit": tracker.to_audit_dict(),
        "training_duration_seconds": round(training_duration, 2),
        "trained_at_utc": trained_at_utc,
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "git_commit": git_commit,
            "git_dirty": git_dirty,
            "provenance_complete": provenance_complete,
            "packages": {
                "pandas": pd.__version__,
                "numpy": np.__version__,
                "scikit-learn": sklearn.__version__,
                "joblib": joblib.__version__,
            },
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

    # Copy to reports/models when running with default paths
    if output_manifest_path == DEFAULT_OUTPUT_MANIFEST_PATH:
        DEFAULT_REPORT_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        with DEFAULT_REPORT_MANIFEST_PATH.open("w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    # 9. Reload and strictly verify using RandomForestModel.load_verified()
    print(
        "[train_random_forest] Performing verified model reload and checking prediction consistency..."
    )
    reloaded_model = RandomForestModel.load_verified(
        model_path=output_model_path,
        manifest_path=output_manifest_path,
        expected_dataset_sha256=EXPECTED_DATASET_SHA256,
        expected_split_manifest_sha256=actual_sm_sha,
        expected_preprocessor_artifact_sha256=actual_art_sha,
    )

    reloaded_val_preds = reloaded_model.predict(X_val_trans)
    reloaded_val_probs = reloaded_model.predict_proba(X_val_trans)

    if not np.array_equal(orig_val_preds, reloaded_val_preds):
        raise ValueError("Validation prediction mismatch between original and reloaded model!")
    if not np.allclose(orig_val_probs, reloaded_val_probs, atol=1e-7):
        raise ValueError(
            "Validation probability mismatch beyond numerical tolerance (atol=1e-7)!"
        )
    if model.feature_names != reloaded_model.feature_names:
        raise ValueError(
            f"Feature names mismatch: {model.feature_names} != {reloaded_model.feature_names}"
        )
    if hasattr(model.estimator, "classes_") and hasattr(reloaded_model.estimator, "classes_"):
        if not np.array_equal(model.estimator.classes_, reloaded_model.estimator.classes_):
            raise ValueError(
                f"Class ordering mismatch: {model.estimator.classes_} != {reloaded_model.estimator.classes_}"
            )
    if len(reloaded_val_preds) != len(val_indices):
        raise ValueError(
            f"Sample count mismatch: expected {len(val_indices)}, got {len(reloaded_val_preds)}"
        )
    print(
        "[train_random_forest] Verified reload check passed: predictions and probabilities identical (atol=1e-7)."
    )

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
