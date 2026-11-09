#!/usr/bin/env python3
"""Training and Evaluation Pipeline for Autoencoder Anomaly Detection (C4 / Issue #29).

This pipeline trains an unsupervised MLP Autoencoder on benign network flows from
the Train partition, calibrates an anomaly decision threshold strictly on the
Validation partition (with pre-registered unknown attack categories held out),
enforces the held-out Test Lock, and saves verified model artifacts and audit reports.

Pipeline stages:
1. Fail-closed prerequisite audit: dataset SHA-256, split manifest + index checksums,
   preprocessor artifact + companion manifest, 47-feature schema contract.
2. Verified preprocessor loading: loaded strictly via TrainOnlyPreprocessor.load_verified().
3. Partition loading: reads canonical partition indices with 'source_row_index' header;
   streams CSV using usecols to minimize memory footprint.
4. Leakage & schema audit: asserts zero target/metadata leakage across Train, Val, and Test.
5. Training population filtering: benign-only (Label == 0) from Train partition.
6. Model training: unsupervised MLP Autoencoder (reconstruction error objective).
7. Validation-only threshold calibration: target FPR quantile or FPR-constrained
   threshold; pre-registered unknown categories (Worms, Backdoor) strictly excluded.
8. Held-out Test Lock: Test data is not loaded by default; evaluated only with --evaluate-test
   after model and threshold are frozen.
9. Verification & serialization: model artifact SHA-256, companion manifest,
   round-trip reload check.
10. Reports: metrics.json, threshold_calibration.json, training_metadata.json, run_metadata.json,
    evaluation_report.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import numbers
import platform
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from network_anomaly.config import (
    PROJECT_ROOT,
    RANDOM_SEED,
)
from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.data.split import (
    load_partition_indices as load_canonical_partition_indices,
)
from network_anomaly.models.autoencoder import (
    build_model,
    fit_model,
    reconstruction_errors,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor

# ---------------------------------------------------------------------------
# Default Paths and Constants
# ---------------------------------------------------------------------------

DATASET_SHA256 = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

DATA_MANIFEST_PATH = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json"
RAW_DATA_PATH = PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
SPLIT_MANIFEST_PATH = PROJECT_ROOT / "data" / "processed" / "nf_unsw_nb15_v3_split_manifest.json"
INDICES_DIR_PATH = PROJECT_ROOT / "data" / "processed" / "splits"
PREPROCESSOR_ARTIFACT_PATH = (
    PROJECT_ROOT / "artifacts" / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
)
PREPROCESSOR_MANIFEST_PATH = (
    PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
)

DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "artifacts" / "models" / "autoencoder"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports" / "evaluation" / "autoencoder"

ATTACK_CATEGORIES = (
    "Analysis",
    "Backdoor",
    "Benign",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
)

# Unknown attack categories pre-registered for holdout evaluation (consistent with Issue #11)
DEFAULT_UNKNOWN_ATTACK_CATEGORIES = frozenset({"Worms", "Backdoor"})

CHUNK_BYTES = 8 * 1024 * 1024  # 8 MiB for hashing


def safe_relpath(path: Path) -> str:
    """Return POSIX relative path to PROJECT_ROOT or fallback to string."""
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    """Compute SHA-256 digest of a file in streaming chunks."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_BYTES):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Prerequisite Checks
# ---------------------------------------------------------------------------


def check_dataset(
    manifest_path: Path | None = None,
    raw_path: Path | None = None,
    skip_checksum: bool = False,
) -> dict[str, Any]:
    """Verify raw dataset against official manifest."""
    man_path = manifest_path or DATA_MANIFEST_PATH
    data_path = raw_path or RAW_DATA_PATH

    if not man_path.exists():
        return {
            "status": "BLOCKED",
            "message": f"Dataset manifest not found at {man_path}",
            "path": str(man_path),
        }
    if not data_path.exists():
        return {
            "status": "BLOCKED",
            "message": (
                f"Raw dataset CSV not found at {data_path}. "
                "Dataset must be placed in data/raw/NF-UNSW-NB15-v3/."
            ),
            "path": str(data_path),
        }

    try:
        with man_path.open(encoding="utf-8") as fh:
            manifest = json.load(fh)
    except Exception as exc:
        return {
            "status": "BLOCKED",
            "message": f"Dataset manifest unreadable: {exc}",
            "path": str(man_path),
        }

    csv_entries = [
        f for f in manifest.get("files", []) if f.get("file") == "data/NF-UNSW-NB15-v3.csv"
    ]
    if not csv_entries:
        return {
            "status": "BLOCKED",
            "message": "Dataset manifest missing entry for data/NF-UNSW-NB15-v3.csv",
            "path": str(man_path),
        }

    expected_sha256 = csv_entries[0].get("sha256")
    if not expected_sha256:
        return {
            "status": "BLOCKED",
            "message": "Dataset manifest entry missing sha256 field",
            "path": str(man_path),
        }

    actual_sha256 = None
    if not skip_checksum:
        actual_sha256 = sha256_file(data_path)
        if actual_sha256 != expected_sha256:
            return {
                "status": "BLOCKED",
                "message": (
                    f"Raw dataset SHA-256 mismatch.\n"
                    f"  expected: {expected_sha256}\n"
                    f"  actual  : {actual_sha256}"
                ),
                "path": str(data_path),
            }

    return {
        "status": "PASS",
        "message": "Dataset manifest and file verified.",
        "path": str(data_path),
        "manifest_path": str(man_path),
        "sha256": actual_sha256 or expected_sha256,
        "expected_sha256": expected_sha256,
        "checksum_verified": not skip_checksum,
    }


def check_split_manifest(
    manifest_path: Path | None = None,
    indices_dir: Path | None = None,
    skip_checksum: bool = False,
) -> dict[str, Any]:
    """Verify split manifest and required partition index files fail-closed."""
    man_path = manifest_path or SPLIT_MANIFEST_PATH
    idx_dir = indices_dir or INDICES_DIR_PATH

    if not man_path.exists():
        return {
            "status": "BLOCKED",
            "message": f"Split manifest not found at {man_path}",
            "path": str(man_path),
        }

    try:
        with man_path.open(encoding="utf-8") as fh:
            manifest = json.load(fh)
    except Exception as exc:
        return {
            "status": "BLOCKED",
            "message": f"Split manifest unreadable: {exc}",
            "path": str(man_path),
        }

    partitions = manifest.get("partitions", {})
    required_parts = ["train", "validation", "test"]
    for part in required_parts:
        if part not in partitions:
            return {
                "status": "BLOCKED",
                "message": f"Split manifest missing required partition: '{part}'",
                "path": str(man_path),
            }
        part_meta = partitions[part]
        if not isinstance(part_meta, dict):
            return {
                "status": "BLOCKED",
                "message": f"Split manifest partition metadata for '{part}' must be a dict.",
                "path": str(man_path),
            }
        expected_sha = part_meta.get("index_sha256")
        if not expected_sha or not isinstance(expected_sha, str) or not expected_sha.strip():
            return {
                "status": "BLOCKED",
                "message": (
                    f"Partition metadata for '{part}' missing required non-empty 'index_sha256'."
                ),
                "path": str(man_path),
            }

    # Verify index files and checksums
    verified_indices: dict[str, dict[str, Any]] = {}
    for part in required_parts:
        index_file = idx_dir / f"{part}_indices.csv.gz"
        if not index_file.exists():
            index_file_raw = idx_dir / f"{part}_indices.csv"
            if index_file_raw.exists():
                index_file = index_file_raw
            else:
                return {
                    "status": "BLOCKED",
                    "message": f"Partition index file not found for {part} in {idx_dir}",
                    "path": str(index_file),
                }

        part_meta = partitions[part]
        expected_sha = part_meta["index_sha256"].strip()
        expected_rows = part_meta.get("row_count")

        actual_sha = None
        if not skip_checksum:
            actual_sha = sha256_file(index_file)
            if actual_sha != expected_sha:
                return {
                    "status": "BLOCKED",
                    "message": (
                        f"Partition index SHA-256 mismatch for {part}.\n"
                        f"  expected: {expected_sha}\n"
                        f"  actual  : {actual_sha}"
                    ),
                    "path": str(index_file),
                }

        verified_indices[part] = {
            "path": str(index_file),
            "expected_rows": expected_rows,
            "sha256": actual_sha or expected_sha,
            "verified": not skip_checksum,
        }

    manifest_sha = sha256_file(man_path)
    return {
        "status": "PASS",
        "message": "Split manifest and partition index files verified.",
        "path": str(man_path),
        "manifest": manifest,
        "manifest_sha256": manifest_sha,
        "partitions": partitions,
        "verified_indices": verified_indices,
    }


def check_preprocessor_artifact(
    artifact_path: Path | None = None,
    manifest_path: Path | None = None,
    skip_checksum: bool = False,
) -> dict[str, Any]:
    """Verify fitted preprocessor artifact from Issue #8."""
    art_path = artifact_path or PREPROCESSOR_ARTIFACT_PATH
    man_path = manifest_path or PREPROCESSOR_MANIFEST_PATH

    if not art_path.exists():
        return {
            "status": "BLOCKED",
            "message": f"Preprocessor artifact not found at {art_path}",
            "path": str(art_path),
        }
    if not man_path.exists():
        return {
            "status": "BLOCKED",
            "message": f"Preprocessor manifest not found at {man_path}",
            "path": str(man_path),
        }

    try:
        with man_path.open(encoding="utf-8") as fh:
            manifest = json.load(fh)
    except Exception as exc:
        return {
            "status": "BLOCKED",
            "message": f"Preprocessor manifest unreadable: {exc}",
            "path": str(man_path),
        }

    expected_sha256 = manifest.get("artifact_sha256")
    if not expected_sha256:
        return {
            "status": "BLOCKED",
            "message": "Preprocessor manifest missing artifact_sha256",
            "path": str(man_path),
        }

    actual_sha256 = None
    if not skip_checksum:
        actual_sha256 = sha256_file(art_path)
        if actual_sha256 != expected_sha256:
            return {
                "status": "BLOCKED",
                "message": (
                    f"Preprocessor artifact SHA-256 mismatch.\n"
                    f"  expected: {expected_sha256}\n"
                    f"  actual  : {actual_sha256}"
                ),
                "path": str(art_path),
            }

    return {
        "status": "PASS",
        "message": "Preprocessor artifact and manifest verified.",
        "path": str(art_path),
        "manifest_path": str(man_path),
        "sha256": actual_sha256 or expected_sha256,
        "manifest": manifest,
        "checksum_verified": not skip_checksum,
    }


def check_feature_schema(columns: Sequence[str]) -> dict[str, Any]:
    """Verify that feature columns exactly match the canonical 47 features in order."""
    cols_tuple = tuple(columns)
    if cols_tuple != ML_FEATURE_COLUMNS:
        missing = [c for c in ML_FEATURE_COLUMNS if c not in cols_tuple]
        extra = [c for c in cols_tuple if c not in ML_FEATURE_COLUMNS]
        order_diff = len(cols_tuple) == len(ML_FEATURE_COLUMNS) and cols_tuple != ML_FEATURE_COLUMNS
        return {
            "status": "FAIL",
            "message": (
                f"Feature schema does not match canonical 47 baseline. "
                f"Missing: {missing}, Extra: {extra}, Order mismatch: {order_diff}"
            ),
            "expected_count": len(ML_FEATURE_COLUMNS),
            "actual_count": len(cols_tuple),
        }
    return {
        "status": "PASS",
        "message": "Feature schema matches canonical 47 baseline exactly.",
        "count": len(ML_FEATURE_COLUMNS),
    }


def check_no_leakage_in_matrix(X_df: pd.DataFrame) -> dict[str, Any]:
    """Verify that targets and trace metadata are completely absent from X."""
    cols = set(X_df.columns)
    leaked_targets = cols.intersection(set(TARGET_COLUMNS))
    leaked_meta = cols.intersection(set(TRACE_METADATA_COLUMNS))
    if leaked_targets or leaked_meta:
        return {
            "status": "FAIL",
            "message": (
                f"Leakage detected in feature matrix: "
                f"targets={sorted(leaked_targets)}, metadata={sorted(leaked_meta)}"
            ),
        }
    return {"status": "PASS", "message": "No target or trace metadata leakage in X."}


def check_finite_values(X_array: np.ndarray, partition_name: str) -> dict[str, Any]:
    """Verify that array contains no NaN or infinite values."""
    if not np.isfinite(X_array).all():
        n_nan = int(np.isnan(X_array).sum())
        n_inf = int(np.isinf(X_array).sum())
        return {
            "status": "FAIL",
            "message": f"Non-finite values in {partition_name}: NaN={n_nan}, Inf={n_inf}",
        }
    return {"status": "PASS", "message": f"All values finite in {partition_name}."}


# ---------------------------------------------------------------------------
# Data Loading & Partition Extraction
# ---------------------------------------------------------------------------


def read_partition_indices_file(
    idx_path: Path,
    max_rows: int | None = None,
) -> np.ndarray:
    """Read partition indices directly from a CSV or CSV.GZ file enforcing canonical header."""
    path = Path(idx_path)
    if not path.is_file():
        raise FileNotFoundError(f"Missing partition index file: {path}")
    compression = "gzip" if str(path).endswith(".gz") else None
    df_idx = pd.read_csv(path, compression=compression)
    if "source_row_index" not in df_idx.columns:
        raise ValueError(
            f"Partition index file {path.name} missing canonical header 'source_row_index'"
        )
    col = df_idx["source_row_index"]
    try:
        indices = col.to_numpy(dtype=np.int64)
    except Exception as exc:
        raise ValueError(f"Invalid non-integer data in partition index {path.name}: {exc}") from exc
    if max_rows is not None and len(indices) > max_rows:
        indices = indices[:max_rows]
    return indices


def load_partition_indices(
    manifest_or_path: Any,
    indices_dir: Path,
    partition_name: str,
    max_rows: int | None = None,
) -> np.ndarray:
    """Load canonical partition indices using split.load_partition_indices with optional limit."""
    indices = load_canonical_partition_indices(manifest_or_path, Path(indices_dir), partition_name)
    if max_rows is not None and len(indices) > max_rows:
        indices = indices[:max_rows]
    return indices


def load_and_transform_partitions(
    raw_data_path: Path,
    indices_dir: Path,
    split_manifest: Any,
    preprocessor: Any,
    include_test: bool = False,
    sample_size: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Stream raw CSV using usecols and extract transformed features, labels, and attacks.

    Guarantees:
    - Held-out Test is never loaded unless include_test=True.
    - Preprocessor transform-only (no fitting).
    - Uses usecols=list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS) to minimize RAM footprint.
    - Ensures exact 47 canonical ML features are in canonical order.
    """
    train_indices = load_partition_indices(
        split_manifest, indices_dir, "train", max_rows=sample_size
    )
    val_indices = load_partition_indices(
        split_manifest, indices_dir, "validation", max_rows=sample_size
    )
    test_indices = (
        load_partition_indices(split_manifest, indices_dir, "test", max_rows=sample_size)
        if include_test
        else np.array([], dtype=np.int64)
    )

    needed_indices = np.unique(np.concatenate([train_indices, val_indices, test_indices]))

    cols_to_read = list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS)

    # Verify that required columns exist in raw CSV header
    header_df = pd.read_csv(raw_data_path, nrows=0)
    missing_cols = [c for c in cols_to_read if c not in header_df.columns]
    if missing_cols:
        raise ValueError(f"Raw dataset CSV missing required columns: {missing_cols}")

    train_rows: list[pd.DataFrame] = []
    val_rows: list[pd.DataFrame] = []
    test_rows: list[pd.DataFrame] = []

    # Stream CSV in chunks using usecols
    chunk_size = 100_000
    current_idx = 0
    for chunk in pd.read_csv(
        raw_data_path,
        usecols=cols_to_read,
        chunksize=chunk_size,
        low_memory=False,
    ):
        chunk_indices = np.arange(current_idx, current_idx + len(chunk))
        current_idx += len(chunk)

        # Check intersection
        mask_needed = np.isin(chunk_indices, needed_indices)
        if not np.any(mask_needed):
            continue

        sub_chunk = chunk[mask_needed].copy()
        sub_indices = chunk_indices[mask_needed]

        mask_train = np.isin(sub_indices, train_indices)
        if np.any(mask_train):
            train_rows.append(sub_chunk[mask_train])

        mask_val = np.isin(sub_indices, val_indices)
        if np.any(mask_val):
            val_rows.append(sub_chunk[mask_val])

        if include_test:
            mask_test = np.isin(sub_indices, test_indices)
            if np.any(mask_test):
                test_rows.append(sub_chunk[mask_test])

    def assemble_partition(row_chunks: list[pd.DataFrame]) -> dict[str, Any]:
        if not row_chunks:
            return {
                "X": np.empty((0, len(ML_FEATURE_COLUMNS))),
                "y": np.array([], dtype=np.int64),
                "attack": np.array([], dtype=object),
                "X_raw_df": pd.DataFrame(columns=list(ML_FEATURE_COLUMNS)),
                "X_raw_cols": list(ML_FEATURE_COLUMNS),
            }
        df = pd.concat(row_chunks, ignore_index=True)
        y = df["Label"].to_numpy(dtype=np.int64)
        attack = df["Attack"].to_numpy(dtype=object)

        # Reorder columns explicitly to 47 canonical ML features
        X_raw = df[list(ML_FEATURE_COLUMNS)].copy()

        # Transform via preprocessor
        if hasattr(preprocessor, "transform"):
            X_trans = preprocessor.transform(X_raw)
        else:
            X_trans = np.asarray(X_raw, dtype=np.float64)

        return {
            "X": X_trans,
            "y": y,
            "attack": attack,
            "X_raw_df": X_raw,
            "X_raw_cols": list(X_raw.columns),
        }

    results = {
        "train": assemble_partition(train_rows),
        "validation": assemble_partition(val_rows),
    }
    if include_test:
        results["test"] = assemble_partition(test_rows)
    return results


# ---------------------------------------------------------------------------
# Threshold Calibration (Validation Only)
# ---------------------------------------------------------------------------


def calibrate_threshold(
    val_scores: np.ndarray,
    val_y: np.ndarray,
    val_attack: np.ndarray,
    method: str = "benign_quantile",
    target_fpr: float = 0.05,
    unknown_categories: frozenset[str] = DEFAULT_UNKNOWN_ATTACK_CATEGORIES,
) -> dict[str, Any]:
    """Calibrate anomaly threshold strictly on the Validation partition.

    Unknown attack categories are strictly excluded from calibration.
    Supported methods:
    - 'benign_quantile': threshold = quantile(1 - target_fpr) of benign reconstruction errors.
    - 'fpr_constrained': empirical search for threshold achieving FPR <= target_fpr on benign.
    - 'supervised_best_f1': search for threshold maximizing F1 on benign + known attacks.
    """
    if len(val_scores) == 0:
        raise ValueError("Cannot calibrate threshold: validation scores are empty.")
    if len(val_scores) != len(val_y):
        raise ValueError("val_scores and val_y length mismatch.")

    # Validate target_fpr
    if not isinstance(target_fpr, (numbers.Real, float, int)) or isinstance(target_fpr, bool):
        raise TypeError(f"target_fpr must be a real number, got {type(target_fpr).__name__}")
    if not np.isfinite(target_fpr):
        raise ValueError(f"target_fpr must be finite, got {target_fpr!r}")
    if not (0.0 <= target_fpr <= 1.0):
        raise ValueError(f"target_fpr must be in [0.0, 1.0], got {target_fpr!r}")

    # Exclude unknown categories from calibration
    is_unknown = np.array([cat in unknown_categories for cat in val_attack])
    is_benign = val_y == 0
    is_known_attack = (val_y == 1) & (~is_unknown)

    calib_mask = is_benign | is_known_attack
    if not np.any(is_benign):
        raise ValueError("Validation set contains no benign samples for threshold calibration.")

    benign_scores = val_scores[is_benign]
    calib_scores = val_scores[calib_mask]
    calib_y = val_y[calib_mask]

    n_benign = int(is_benign.sum())
    n_known_attack = int(is_known_attack.sum())
    n_unknown_excluded = int(is_unknown.sum())

    if method == "benign_quantile":
        quantile = max(0.0, min(1.0, 1.0 - target_fpr))
        threshold = float(np.percentile(benign_scores, quantile * 100))
    elif method == "fpr_constrained":
        sorted_benign = np.sort(benign_scores)
        idx = int(np.floor((1.0 - target_fpr) * len(sorted_benign)))
        idx = max(0, min(idx, len(sorted_benign) - 1))
        threshold = float(sorted_benign[idx])
    elif method == "supervised_best_f1":
        candidate_thresholds = np.percentile(calib_scores, np.linspace(50, 99.9, 100))
        best_f1 = -1.0
        best_th = float(candidate_thresholds[0])
        for th in candidate_thresholds:
            preds = (calib_scores >= th).astype(int)
            tp = int(((preds == 1) & (calib_y == 1)).sum())
            fp = int(((preds == 1) & (calib_y == 0)).sum())
            fn = int(((preds == 0) & (calib_y == 1)).sum())
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
            if f1 > best_f1:
                best_f1 = f1
                best_th = float(th)
        threshold = best_th
    else:
        raise ValueError(f"Unsupported calibration method: {method!r}")

    val_preds_benign = (benign_scores >= threshold).astype(int)
    empirical_fpr = float(val_preds_benign.sum() / len(benign_scores))

    return {
        "threshold": threshold,
        "calibration_method": method,
        "target_fpr": target_fpr,
        "empirical_val_fpr": empirical_fpr,
        "n_benign_used": n_benign,
        "n_known_attack_used": n_known_attack,
        "n_unknown_excluded": n_unknown_excluded,
        "unknown_categories_excluded": sorted(unknown_categories),
        "threshold_frozen": True,
    }


# ---------------------------------------------------------------------------
# Metrics Computation
# ---------------------------------------------------------------------------


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores: np.ndarray,
    attack_col: np.ndarray | None = None,
    unknown_categories: frozenset[str] = DEFAULT_UNKNOWN_ATTACK_CATEGORIES,
) -> dict[str, Any]:
    """Compute comprehensive classification and anomaly detection metrics."""
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    total = len(y_true)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    prec_normal = tn / (tn + fn) if (tn + fn) > 0 else 0.0
    rec_normal = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1_normal = (
        2 * prec_normal * rec_normal / (prec_normal + rec_normal)
        if (prec_normal + rec_normal) > 0
        else 0.0
    )
    macro_f1 = (f1 + f1_normal) / 2.0

    metrics: dict[str, Any] = {
        "total_samples": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall_detection_rate": recall,
        "f1_score": f1,
        "macro_f1": macro_f1,
        "fpr": fpr,
        "tnr": tnr,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }

    if attack_col is not None and len(attack_col) == total:
        category_metrics: dict[str, dict[str, Any]] = {}
        unique_cats = sorted(set(attack_col))

        known_detected = 0
        known_total = 0
        unknown_detected = 0
        unknown_total = 0

        for cat in unique_cats:
            mask = attack_col == cat
            cat_total = int(mask.sum())
            cat_preds = y_pred[mask]
            cat_detected = int((cat_preds == 1).sum())
            cat_rate = cat_detected / cat_total if cat_total > 0 else 0.0

            is_unk = cat in unknown_categories
            is_ben = cat == "Benign"

            if is_ben:
                category_metrics[cat] = {
                    "total": cat_total,
                    "false_positives": cat_detected,
                    "fpr": cat_rate,
                    "type": "benign",
                }
            elif is_unk:
                unknown_total += cat_total
                unknown_detected += cat_detected
                category_metrics[cat] = {
                    "total": cat_total,
                    "detected": cat_detected,
                    "detection_rate": cat_rate,
                    "type": "unknown_attack",
                }
            else:
                known_total += cat_total
                known_detected += cat_detected
                category_metrics[cat] = {
                    "total": cat_total,
                    "detected": cat_detected,
                    "detection_rate": cat_rate,
                    "type": "known_attack",
                }

        metrics["per_category"] = category_metrics
        metrics["aggregate_known_attacks"] = {
            "total": known_total,
            "detected": known_detected,
            "detection_rate": known_detected / known_total if known_total > 0 else 0.0,
        }
        metrics["aggregate_unknown_attacks"] = {
            "total": unknown_total,
            "detected": unknown_detected,
            "detection_rate": unknown_detected / unknown_total if unknown_total > 0 else 0.0,
        }

    return metrics


# ---------------------------------------------------------------------------
# Artifact Saving & Verified Loading
# ---------------------------------------------------------------------------


def save_artifacts(
    model: Any,
    config: dict[str, Any],
    threshold_meta: dict[str, Any],
    training_meta: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    """Save model artifact, configuration, threshold, and companion manifest."""
    output_dir.mkdir(parents=True, exist_ok=True)

    model_file = output_dir / "autoencoder_model.joblib"
    config_file = output_dir / "model_config.json"
    threshold_file = output_dir / "threshold.json"
    manifest_file = output_dir / "autoencoder_manifest.json"

    joblib.dump(model, model_file)
    model_sha256 = sha256_file(model_file)

    with config_file.open("w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)

    with threshold_file.open("w", encoding="utf-8") as fh:
        json.dump(threshold_meta, fh, indent=2)

    manifest_data = {
        "artifact_type": "autoencoder-anomaly-detector",
        "schema_version": "1.0",
        "model_file": model_file.name,
        "model_sha256": model_sha256,
        "model_architecture": {
            "class": "MLPRegressor",
            "hidden_layer_sizes": list(config.get("hidden_layer_sizes", ())),
            "activation": config.get("activation"),
            "solver": config.get("solver"),
            "loss": "squared_error (MSE)",
            "input_dimension": len(ML_FEATURE_COLUMNS),
            "output_dimension": len(ML_FEATURE_COLUMNS),
        },
        "hyperparameters": config,
        "threshold": threshold_meta.get("threshold"),
        "threshold_calibration": threshold_meta,
        "training_population": training_meta.get("training_population"),
        "training_row_count": training_meta.get("n_train_samples"),
        "validation_row_count": training_meta.get("n_val_samples"),
        "unknown_attack_categories": sorted(DEFAULT_UNKNOWN_ATTACK_CATEGORIES),
        "dataset_sha256": training_meta.get("dataset_sha256"),
        "split_manifest_sha256": training_meta.get("split_manifest_sha256"),
        "preprocessor_sha256": training_meta.get("preprocessor_sha256"),
        "preprocessor_source": training_meta.get("preprocessor_source"),
        "feature_contract_version": "nf-unsw-nb15-v3-baseline-47",
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": training_meta.get("git_commit"),
    }

    with manifest_file.open("w", encoding="utf-8") as fh:
        json.dump(manifest_data, fh, indent=2)

    return {
        "directory": str(output_dir),
        "files": {
            "model": str(model_file),
            "config": str(config_file),
            "threshold": str(threshold_file),
            "manifest": str(manifest_file),
        },
        "model_sha256": model_sha256,
        "manifest": manifest_data,
    }


def verify_saved_model(
    model_path: Path,
    original_model: Any,
    X_sample: np.ndarray,
) -> dict[str, Any]:
    """Verify saved model reload matches original outputs."""
    loaded_model = joblib.load(model_path)
    orig_errors = reconstruction_errors(original_model, X_sample)
    loaded_errors = reconstruction_errors(loaded_model, X_sample)

    if not np.allclose(orig_errors, loaded_errors, rtol=1e-5, atol=1e-5):
        max_diff = float(np.max(np.abs(orig_errors - loaded_errors)))
        return {
            "status": "FAIL",
            "message": f"Reloaded model outputs differ from original. Max diff: {max_diff}",
        }
    return {
        "status": "PASS",
        "message": "Reloaded model outputs match original perfectly.",
        "samples_checked": len(X_sample),
    }


def load_verified_autoencoder(
    model_path: Path,
    manifest_path: Path,
) -> tuple[Any, dict[str, Any]]:
    """Fail-closed verified loader for Autoencoder artifact and manifest."""
    if not model_path.exists():
        raise FileNotFoundError(f"Autoencoder model artifact not found: {model_path}")
    if not manifest_path.exists():
        raise FileNotFoundError(f"Autoencoder companion manifest not found: {manifest_path}")

    with manifest_path.open("r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    expected_sha = manifest.get("model_sha256")
    if not expected_sha:
        raise ValueError("Manifest missing required field: model_sha256")

    actual_sha = sha256_file(model_path)
    if actual_sha != expected_sha:
        raise ValueError(
            f"Autoencoder artifact SHA-256 mismatch!\n"
            f"  expected: {expected_sha}\n"
            f"  actual:   {actual_sha}"
        )

    model = joblib.load(model_path)
    return model, manifest


# ---------------------------------------------------------------------------
# Markdown Report Generation
# ---------------------------------------------------------------------------


def generate_markdown_report(
    metrics_val: dict[str, Any],
    metrics_test: dict[str, Any] | None,
    threshold_meta: dict[str, Any],
    training_meta: dict[str, Any],
    report_path: Path,
) -> None:
    """Generate comprehensive evaluation report in Markdown format."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Autoencoder Anomaly Detection Evaluation Report (Issue #29 / C4)",
        "",
        f"- Generated at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"- Git commit: `{training_meta.get('git_commit', 'N/A')}`",
        f"- Model architecture: MLP Autoencoder `{training_meta.get('hidden_layer_sizes')}`",
        f"- Training population: `{training_meta.get('training_population')}`",
        (
            f"- Threshold calibration method: `{threshold_meta.get('calibration_method')}` "
            f"(Frozen: `{threshold_meta.get('threshold_frozen')}`)"
        ),
        f"- Calibrated threshold: `{threshold_meta.get('threshold'):.6f}`",
        (
            f"- Target FPR: `{threshold_meta.get('target_fpr')}` "
            f"(Empirical Val FPR: `{threshold_meta.get('empirical_val_fpr'):.4f}`)"
        ),
        (
            "- Pre-registered unknown attack categories: "
            f"`{sorted(DEFAULT_UNKNOWN_ATTACK_CATEGORIES)}`"
        ),
        "",
        "## 1. Validation Performance",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Accuracy | {metrics_val.get('accuracy', 0.0):.4f} |",
        f"| Precision | {metrics_val.get('precision', 0.0):.4f} |",
        f"| Recall (Detection Rate) | {metrics_val.get('recall_detection_rate', 0.0):.4f} |",
        f"| F1-Score | {metrics_val.get('f1_score', 0.0):.4f} |",
        f"| Macro-F1 | {metrics_val.get('macro_f1', 0.0):.4f} |",
        f"| False Positive Rate (FPR) | {metrics_val.get('fpr', 0.0):.4f} |",
        f"| True Negative Rate (TNR) | {metrics_val.get('tnr', 0.0):.4f} |",
        "",
        "### Validation Confusion Matrix",
        "",
        f"- True Positives (TP): {metrics_val.get('tp', 0):,}",
        f"- False Positives (FP): {metrics_val.get('fp', 0):,}",
        f"- True Negatives (TN): {metrics_val.get('tn', 0):,}",
        f"- False Negatives (FN): {metrics_val.get('fn', 0):,}",
        "",
    ]

    if "per_category" in metrics_val:
        lines.extend(
            [
                "### Validation Per-Category Breakdown",
                "",
                "| Category | Type | Total | Detected | Rate |",
                "|---|---|---|---|---|",
            ]
        )
        for cat, c_meta in sorted(metrics_val["per_category"].items()):
            c_type = c_meta.get("type", "unknown")
            c_total = c_meta.get("total", 0)
            c_det = c_meta.get("detected", c_meta.get("false_positives", 0))
            c_rate = c_meta.get("detection_rate", c_meta.get("fpr", 0.0))
            lines.append(f"| {cat} | {c_type} | {c_total:,} | {c_det:,} | {c_rate:.4f} |")
        lines.append("")

        if "aggregate_known_attacks" in metrics_val and "aggregate_unknown_attacks" in metrics_val:
            known = metrics_val["aggregate_known_attacks"]
            unknown = metrics_val["aggregate_unknown_attacks"]
            kd_rate = known.get("detection_rate", 0.0)
            kd_cnt = known.get("detected", 0)
            kd_tot = known.get("total", 0)
            uk_rate = unknown.get("detection_rate", 0.0)
            uk_cnt = unknown.get("detected", 0)
            uk_tot = unknown.get("total", 0)
            lines.extend(
                [
                    "### Known vs Unknown Attacks Summary (Validation)",
                    "",
                    f"- **Known Attacks Detection Rate**: {kd_rate:.4f} ({kd_cnt:,} / {kd_tot:,})",
                    (
                        "- **Unknown Attacks Detection Rate**: "
                        f"{uk_rate:.4f} ({uk_cnt:,} / {uk_tot:,})"
                    ),
                    "",
                ]
            )

    if metrics_test is not None:
        rec_test = metrics_test.get("recall_detection_rate", 0.0)
        lines.extend(
            [
                "## 2. Test Performance (Held-out Test Lock Evaluated)",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Accuracy | {metrics_test.get('accuracy', 0.0):.4f} |",
                f"| Precision | {metrics_test.get('precision', 0.0):.4f} |",
                f"| Recall (Detection Rate) | {rec_test:.4f} |",
                f"| F1-Score | {metrics_test.get('f1_score', 0.0):.4f} |",
                f"| Macro-F1 | {metrics_test.get('macro_f1', 0.0):.4f} |",
                f"| False Positive Rate (FPR) | {metrics_test.get('fpr', 0.0):.4f} |",
                f"| True Negative Rate (TNR) | {metrics_test.get('tnr', 0.0):.4f} |",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "## 2. Test Performance",
                "",
                "> [!NOTE]",
                "> Held-out Test partition was LOCKED during this run (safety lock).",
                "> Pass `--evaluate-test` to evaluate Test only after threshold is frozen.",
                "",
            ]
        )

    lines.extend(
        [
            "## 3. Scientific Limitations & Assumptions",
            "",
            "1. **No Zero-Day Claim**: Unknown-attack holdout is a controlled benchmark protocol,",
            "   not a guarantee or proof of detecting real-world zero-day attacks.",
            "2. **NetFlow Representation**: Features are aggregated statistics (NF-UNSW-NB15-v3);",
            "   payload contents and sequence transitions are not observed.",
            "3. **Class Imbalance & Repetition**: NetFlow data has recurring traffic patterns",
            "   which may lead to localized reconstruction memorization.",
            "4. **Threshold Dependency**: Detector performance is bounded by calibration",
            "   on Validation. Distribution shifts to Test can affect empirical FPR.",
            "",
        ]
    )

    with report_path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ---------------------------------------------------------------------------
# Pipeline Execution Entrypoint
# ---------------------------------------------------------------------------


def run_pipeline(args: argparse.Namespace) -> int:
    """Execute the Autoencoder training and evaluation pipeline."""
    start_time = time.time()
    print("=" * 70)
    print("Autoencoder Training & Evaluation Pipeline (Issue #29 / C4)")
    print("=" * 70)

    # 1. Prerequisite Verification (Fail-Closed)
    print("[1/8] Auditing prerequisites fail-closed...")
    dataset_res = check_dataset(
        manifest_path=args.data_manifest,
        raw_path=args.raw_data,
        skip_checksum=args.skip_checksums,
    )
    if dataset_res["status"] != "PASS":
        print(f"FAILED: {dataset_res['message']}")
        return 1
    print(f"  OK Dataset verified: {dataset_res['path']}")

    split_res = check_split_manifest(
        manifest_path=args.split_manifest,
        indices_dir=args.indices_dir,
        skip_checksum=args.skip_checksums,
    )
    if split_res["status"] != "PASS":
        print(f"FAILED: {split_res['message']}")
        return 1
    print(f"  OK Split manifest & index files verified: {split_res['path']}")

    prep_res = check_preprocessor_artifact(
        artifact_path=args.preprocessor_artifact,
        manifest_path=args.preprocessor_manifest,
        skip_checksum=args.skip_checksums,
    )
    if prep_res["status"] != "PASS":
        print(f"FAILED: {prep_res['message']}")
        return 1
    print(f"  OK Preprocessor artifact verified: {prep_res['path']}")

    # 2. Load Preprocessor via TrainOnlyPreprocessor.load_verified
    print("[2/8] Loading and verifying preprocessor via TrainOnlyPreprocessor.load_verified...")
    try:
        preprocessor = TrainOnlyPreprocessor.load_verified(
            artifact_path=Path(prep_res["path"]),
            manifest_path=Path(prep_res.get("manifest_path", PREPROCESSOR_MANIFEST_PATH)),
            split_manifest_path=Path(split_res["path"]),
            dataset_path=Path(dataset_res["path"]) if Path(dataset_res["path"]).exists() else None,
            expected_dataset_sha256=dataset_res.get("expected_sha256") or DATASET_SHA256,
        )
    except Exception as exc:
        print(f"[BLOCKED] Preprocessor artifact verification failed: {exc}")
        return 1
    print("  OK Preprocessor verified and loaded via TrainOnlyPreprocessor.load_verified.")

    # 3. Stream & Extract Partitions using usecols
    print(f"[3/8] Loading and transforming partitions (Held-out Test: {args.evaluate_test})...")
    split_manifest_obj = split_res.get("manifest") or json.loads(
        Path(split_res["path"]).read_text(encoding="utf-8")
    )
    try:
        partitions = load_and_transform_partitions(
            raw_data_path=Path(dataset_res["path"]),
            indices_dir=args.indices_dir or INDICES_DIR_PATH,
            split_manifest=split_manifest_obj,
            preprocessor=preprocessor,
            include_test=args.evaluate_test,
            sample_size=args.sample_size,
        )
    except Exception as exc:
        print(f"[BLOCKED] Failed to load partitions: {exc}")
        return 1

    train_data = partitions["train"]
    val_data = partitions["validation"]
    test_data = partitions.get("test")

    print(f"  Train raw samples loaded: {len(train_data['y']):,}")
    print(f"  Validation raw samples loaded: {len(val_data['y']):,}")
    if test_data:
        print(f"  Test raw samples loaded: {len(test_data['y']):,}")

    # 4. Leakage checks across all partitions
    print("[4/8] Auditing feature matrices for target and metadata leakage...")
    for part_name, p_data in [("Train", train_data), ("Validation", val_data)]:
        leak_res = check_no_leakage_in_matrix(p_data["X_raw_df"])
        if leak_res["status"] != "PASS":
            print(f"FAILED: Data leakage in {part_name}: {leak_res['message']}")
            return 1
    if test_data is not None:
        leak_res = check_no_leakage_in_matrix(test_data["X_raw_df"])
        if leak_res["status"] != "PASS":
            print(f"FAILED: Data leakage in Test: {leak_res['message']}")
            return 1
    print("  OK No leakage detected across all loaded partitions.")

    # 5. Schema and Finite checks
    print("[5/8] Verifying feature schema and finite numeric values...")
    for part_name, p_data in [("Train", train_data), ("Validation", val_data)]:
        schema_res = check_feature_schema(p_data["X_raw_cols"])
        if schema_res["status"] != "PASS":
            print(f"FAILED: Feature schema mismatch in {part_name}: {schema_res['message']}")
            return 1
        fin_res = check_finite_values(p_data["X"], part_name)
        if fin_res["status"] != "PASS":
            print(f"FAILED: Non-finite values in {part_name}: {fin_res['message']}")
            return 1
    if test_data is not None:
        schema_res = check_feature_schema(test_data["X_raw_cols"])
        if schema_res["status"] != "PASS":
            print(f"FAILED: Feature schema mismatch in Test: {schema_res['message']}")
            return 1
        fin_res = check_finite_values(test_data["X"], "Test")
        if fin_res["status"] != "PASS":
            print(f"FAILED: Non-finite values in Test: {fin_res['message']}")
            return 1
    print("  OK 47 canonical baseline features and finite values verified.")

    # 6. Filter Training Population (Benign Only) and Fit Autoencoder
    print("[6/8] Fitting Autoencoder on benign-only training population...")
    train_y = train_data["y"]
    benign_mask = train_y == 0
    X_train_benign = train_data["X"][benign_mask]

    n_train_benign = int(benign_mask.sum())
    print(f"  Training population: {n_train_benign:,} benign samples (Label == 0).")
    if n_train_benign == 0:
        print("FAILED: No benign samples available for training.")
        return 1

    hidden_layers = tuple(int(x.strip()) for x in args.hidden_layers.split(","))
    batch_size = args.batch_size
    if isinstance(batch_size, str) and batch_size != "auto":
        try:
            batch_size = int(batch_size)
        except ValueError:
            pass

    model_cfg = {
        "hidden_layer_sizes": hidden_layers,
        "activation": args.activation,
        "solver": args.solver,
        "alpha": args.alpha,
        "batch_size": batch_size,
        "learning_rate_init": args.learning_rate,
        "max_iter": args.max_iter,
        "random_state": RANDOM_SEED,
    }
    model = build_model(config=model_cfg)
    fit_model(model, X_train_benign)
    print("  OK Autoencoder fitted successfully.")

    # 7. Validation Reconstruction & Threshold Calibration
    print("[7/8] Computing validation reconstruction errors and calibrating threshold...")
    val_scores = reconstruction_errors(model, val_data["X"])

    unknown_cats = frozenset([c.strip() for c in args.unknown_categories.split(",") if c.strip()])
    threshold_meta = calibrate_threshold(
        val_scores=val_scores,
        val_y=val_data["y"],
        val_attack=val_data["attack"],
        method=args.calibration_method,
        target_fpr=args.target_fpr,
        unknown_categories=unknown_cats,
    )
    th_val = threshold_meta["threshold"]
    print(f"  OK Frozen threshold: {th_val:.6f} (Method: {args.calibration_method})")
    print(
        f"  Target FPR: {args.target_fpr}, "
        f"Empirical Val FPR: {threshold_meta['empirical_val_fpr']:.4f}"
    )
    print(f"  Unknown categories held out: {sorted(unknown_cats)}")

    val_preds = (val_scores >= th_val).astype(np.int64)
    metrics_val = compute_metrics(
        y_true=val_data["y"],
        y_pred=val_preds,
        scores=val_scores,
        attack_col=val_data["attack"],
        unknown_categories=unknown_cats,
    )

    metrics_test = None
    if args.evaluate_test and test_data:
        print("  Evaluating on held-out Test partition...")
        test_scores = reconstruction_errors(model, test_data["X"])
        test_preds = (test_scores >= th_val).astype(np.int64)
        metrics_test = compute_metrics(
            y_true=test_data["y"],
            y_pred=test_preds,
            scores=test_scores,
            attack_col=test_data["attack"],
            unknown_categories=unknown_cats,
        )

    # 8. Artifacts & Reporting
    print("[8/8] Serializing artifacts and generating reports...")
    output_dir = args.output_dir or DEFAULT_OUTPUT_DIR
    report_dir = args.report_dir or DEFAULT_REPORT_DIR

    try:
        git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        git_commit = "unknown"

    training_meta = {
        "model_type": "Autoencoder (MLPRegressor)",
        "hidden_layer_sizes": hidden_layers,
        "training_population": "benign-only (Label == 0)",
        "n_train_samples": n_train_benign,
        "n_val_samples": len(val_data["y"]),
        "n_test_samples": len(test_data["y"]) if test_data else 0,
        "dataset_sha256": dataset_res.get("sha256"),
        "split_manifest_sha256": split_res.get("manifest_sha256"),
        "preprocessor_sha256": prep_res.get("sha256"),
        "preprocessor_source": "TrainOnlyPreprocessor.load_verified",
        "git_commit": git_commit,
        "elapsed_seconds": round(time.time() - start_time, 2),
    }

    art_res = save_artifacts(
        model=model,
        config=model_cfg,
        threshold_meta=threshold_meta,
        training_meta=training_meta,
        output_dir=output_dir,
    )
    print(f"  OK Artifacts saved to: {output_dir}")

    sample_eval = val_data["X"][: min(100, len(val_data["X"]))]
    verify_res = verify_saved_model(
        model_path=Path(art_res["files"]["model"]),
        original_model=model,
        X_sample=sample_eval,
    )
    if verify_res["status"] != "PASS":
        print(f"FAILED: {verify_res['message']}")
        return 1
    print("  OK Saved artifact verified via reload check.")

    report_dir.mkdir(parents=True, exist_ok=True)
    with (report_dir / "metrics.json").open("w", encoding="utf-8") as fh:
        json.dump(
            {
                "validation": metrics_val,
                "test": metrics_test,
                "threshold_calibration": threshold_meta,
            },
            fh,
            indent=2,
        )

    with (report_dir / "threshold_calibration.json").open("w", encoding="utf-8") as fh:
        json.dump(threshold_meta, fh, indent=2)

    with (report_dir / "training_metadata.json").open("w", encoding="utf-8") as fh:
        json.dump(training_meta, fh, indent=2)

    with (report_dir / "run_metadata.json").open("w", encoding="utf-8") as fh:
        json.dump(
            {
                "arguments": vars(args),
                "platform": platform.platform(),
                "python_version": sys.version,
                "execution_time_seconds": training_meta["elapsed_seconds"],
                "git_commit": git_commit,
                "preprocessor_source": "TrainOnlyPreprocessor.load_verified",
            },
            fh,
            indent=2,
            default=str,
        )

    report_md_path = report_dir / "evaluation_report.md"
    generate_markdown_report(
        metrics_val=metrics_val,
        metrics_test=metrics_test,
        threshold_meta=threshold_meta,
        training_meta=training_meta,
        report_path=report_md_path,
    )
    print(f"  OK Evaluation report written to: {report_md_path}")
    print("=" * 70)
    print(f"Pipeline completed successfully in {training_meta['elapsed_seconds']:.2f}s!")
    print("=" * 70)
    return 0


# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Autoencoder Anomaly Detection Training and Evaluation (Issue #29 / C4)"
    )
    parser.add_argument("--raw-data", type=Path, default=RAW_DATA_PATH)
    parser.add_argument("--data-manifest", type=Path, default=DATA_MANIFEST_PATH)
    parser.add_argument("--split-manifest", type=Path, default=SPLIT_MANIFEST_PATH)
    parser.add_argument("--indices-dir", type=Path, default=INDICES_DIR_PATH)
    parser.add_argument("--preprocessor-artifact", type=Path, default=PREPROCESSOR_ARTIFACT_PATH)
    parser.add_argument("--preprocessor-manifest", type=Path, default=PREPROCESSOR_MANIFEST_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)

    parser.add_argument("--hidden-layers", type=str, default="32,16,32")
    parser.add_argument("--activation", type=str, default="relu")
    parser.add_argument("--solver", type=str, default="adam")
    parser.add_argument("--alpha", type=float, default=0.0001)
    parser.add_argument("--batch-size", type=str, default="256")
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--max-iter", type=int, default=50)

    parser.add_argument("--target-fpr", type=float, default=0.05)
    parser.add_argument(
        "--calibration-method",
        type=str,
        default="benign_quantile",
        choices=["benign_quantile", "fpr_constrained", "supervised_best_f1"],
    )
    parser.add_argument("--unknown-categories", type=str, default="Worms,Backdoor")
    parser.add_argument("--evaluate-test", action="store_true", default=False)
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--skip-checksums", action="store_true", default=False)

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.batch_size != "auto":
        try:
            args.batch_size = int(args.batch_size)
        except ValueError:
            pass
    return run_pipeline(args)


if __name__ == "__main__":
    sys.exit(main())
