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
3. Partition loading (Train/Validation only prior to lock): reads canonical Train/Validation
   indices with 'source_row_index' header; streams unified CSV using usecols up to max required
   Train/Validation index and drops non-selected rows at the chunk-mask boundary.
4. Leakage & schema audit: asserts zero target/metadata leakage across Train and Validation.
5. Training population filtering: benign-only (Label == 0) from Train partition.
6. Model training: unsupervised MLP Autoencoder (reconstruction error objective).
7. Validation-only threshold calibration: target FPR quantile or empirical FPR-constrained
   threshold; pre-registered unknown categories strictly excluded.
8. Held-out Test Lock: Contract A isolates Test from loading, preprocessing transformation,
   fit, early stopping, and threshold calibration; Contract B drops non-Train/Val rows at the
   chunk-mask boundary so 0 Test rows are materialized by default. Only when --evaluate-test
   is enabled, verify_test_evaluation_lock() and load_and_transform_test_partition() load,
   transform, audit, and evaluate Test strictly AFTER model fitting and threshold freeze.
9. Verification & serialization: model/config/threshold SHA-256, companion manifest with
   configured unknown categories & verified partition index hashes, round-trip reload check.
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

_SCRIPT_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_SRC = _SCRIPT_PROJECT_ROOT / "src"
if str(_LOCAL_SRC) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SRC))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import average_precision_score, roc_auc_score  # noqa: E402

from network_anomaly.config import (  # noqa: E402
    PROJECT_ROOT,
    RANDOM_SEED,
)
from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.models.autoencoder import (  # noqa: E402
    build_model,
    fit_model,
    reconstruction_errors,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

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
DEFAULT_REPORT_MANIFEST_PATH = PROJECT_ROOT / "reports" / "models" / "autoencoder_manifest.json"
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


def check_finite_values(X_array: Any, partition_name: str) -> dict[str, Any]:
    """Verify that array contains no NaN or infinite values."""
    arr = np.asarray(X_array, dtype=np.float64)
    if not np.isfinite(arr).all():
        n_nan = int(np.isnan(arr).sum())
        n_inf = int(np.isinf(arr).sum())
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
    """Load canonical partition indices using split manifest verification and canonical header."""
    if isinstance(manifest_or_path, (str, Path)):
        with Path(manifest_or_path).open("r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    elif isinstance(manifest_or_path, dict):
        manifest = manifest_or_path
    else:
        raise TypeError(
            f"manifest_or_path must be a path or dict, got {type(manifest_or_path).__name__}"
        )

    partitions = manifest.get("partitions", {})
    if partition_name not in partitions:
        raise ValueError(f"Partition '{partition_name}' not found in split manifest")

    idx_dir = Path(indices_dir)
    idx_path = idx_dir / f"{partition_name}_indices.csv.gz"
    if not idx_path.is_file():
        idx_path_raw = idx_dir / f"{partition_name}_indices.csv"
        if idx_path_raw.is_file():
            idx_path = idx_path_raw
        else:
            raise FileNotFoundError(
                f"Missing partition index file for '{partition_name}' in {idx_dir}"
            )

    part_meta = partitions[partition_name]
    if isinstance(part_meta, dict):
        expected_sha = part_meta.get("index_sha256")
        if expected_sha and isinstance(expected_sha, str) and expected_sha.strip():
            actual_sha = sha256_file(idx_path)
            if actual_sha != expected_sha.strip():
                raise ValueError(
                    f"SHA-256 mismatch for {idx_path.name}: "
                    f"expected {expected_sha.strip()}, got {actual_sha}"
                )

    indices = read_partition_indices_file(idx_path)

    # Fail-closed checks on indices integrity
    if np.any(indices < 0):
        raise ValueError(f"Partition '{partition_name}' contains negative index values")
    if len(indices) != len(np.unique(indices)):
        raise ValueError(f"Partition '{partition_name}' contains duplicate index values")

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
    chunk_size: int = 100_000,
    partitions: Sequence[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Stream unified raw CSV using usecols and extract transformed features, labels, and attacks.

    Guarantees:
    - Contract A (Fit/Calibration Isolation): Test data never enters fit, early stopping,
      or threshold calibration.
    - Contract B (Stream-Boundary Filtering & Materialization Lock): When Test is not selected,
      test_indices are not read into partition_map; the unified raw CSV stream stops as soon
      as current_row exceeds max selected index, non-selected rows are dropped at the chunk-mask
      boundary, and 0 Test rows are materialized or transformed.
    - Preprocessor transform-only (no fitting); returns float64 NumPy feature matrices.
    - Uses usecols=list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS) to minimize RAM footprint.
    - Ensures exact 47 canonical ML features are in canonical order.
    - Strict verification that partition indices are mutually disjoint.
    - Strict row count verification against expected index sizes.
    """
    if chunk_size < 1:
        raise ValueError(f"chunk_size must be >= 1, got {chunk_size}")

    allowed_partitions = ("train", "validation", "test")
    if partitions is None:
        selected_partitions = (
            ("train", "validation", "test") if include_test else ("train", "validation")
        )
    else:
        deduped = tuple(dict.fromkeys(partitions))
        invalid = [p for p in deduped if p not in allowed_partitions]
        if not deduped or invalid:
            raise ValueError(f"Invalid partition selection {partitions!r}")
        if "test" in deduped and not include_test:
            raise ValueError("Loading 'test' partition requires include_test=True.")
        selected_partitions = deduped

    need_train = "train" in selected_partitions or "test" in selected_partitions
    need_val = "validation" in selected_partitions or "test" in selected_partitions
    need_test = "test" in selected_partitions

    train_indices = (
        load_partition_indices(split_manifest, indices_dir, "train", max_rows=sample_size)
        if need_train
        else np.array([], dtype=np.int64)
    )
    val_indices = (
        load_partition_indices(split_manifest, indices_dir, "validation", max_rows=sample_size)
        if need_val
        else np.array([], dtype=np.int64)
    )
    test_indices = (
        load_partition_indices(split_manifest, indices_dir, "test", max_rows=sample_size)
        if need_test
        else np.array([], dtype=np.int64)
    )

    # Strict assertion: partition index sets must be mutually disjoint
    train_set = set(train_indices)
    val_set = set(val_indices)
    if need_train and need_val:
        tv_overlap = train_set.intersection(val_set)
        if tv_overlap:
            raise ValueError(
                f"Split contamination: train and validation partitions overlap ({len(tv_overlap)} rows)"
            )
    if need_test and len(test_indices) > 0:
        test_set = set(test_indices)
        tt_overlap = train_set.intersection(test_set)
        if tt_overlap:
            raise ValueError(
                f"Split contamination: train and test partitions overlap ({len(tt_overlap)} rows)"
            )
        vt_overlap = val_set.intersection(test_set)
        if vt_overlap:
            raise ValueError(
                "Split contamination: validation and test partitions overlap "
                f"({len(vt_overlap)} rows)"
            )

    all_indices = {"train": train_indices, "validation": val_indices, "test": test_indices}
    indices_by_part = {part: all_indices[part] for part in selected_partitions}

    cols_to_read = list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS)

    # Verify that required columns exist in raw CSV header
    header_df = pd.read_csv(raw_data_path, nrows=0)
    missing_cols = [c for c in cols_to_read if c not in header_df.columns]
    if missing_cols:
        raise ValueError(f"Raw dataset CSV missing required columns: {missing_cols}")

    valid_indices = [idx for idx in indices_by_part.values() if len(idx) > 0]
    if not valid_indices:

        def _empty_part() -> dict[str, Any]:
            return {
                "X": np.empty((0, len(ML_FEATURE_COLUMNS)), dtype=np.float64),
                "y": np.array([], dtype=np.int64),
                "attack": np.array([], dtype=object),
                "X_raw_df": pd.DataFrame(columns=list(ML_FEATURE_COLUMNS)),
                "X_raw_cols": list(ML_FEATURE_COLUMNS),
            }

        return {part: _empty_part() for part in selected_partitions}

    max_idx = max(int(np.max(idx)) for idx in valid_indices)
    partition_map = np.full(max_idx + 1, -1, dtype=np.int8)
    part_codes = {part: code for code, part in enumerate(selected_partitions)}
    for part, code in part_codes.items():
        part_idx = indices_by_part[part]
        if len(part_idx) > 0:
            partition_map[part_idx] = code

    row_chunks: dict[str, list[pd.DataFrame]] = {part: [] for part in selected_partitions}

    # Stream unified CSV in chunks using usecols and partition_map; stop once max_idx is passed
    current_row = 0
    with pd.read_csv(
        raw_data_path,
        usecols=cols_to_read,
        chunksize=chunk_size,
        low_memory=False,
    ) as reader:
        for chunk in reader:
            if current_row > max_idx:
                break

            n_rows = len(chunk)
            end_row = current_row + n_rows
            valid_len = min(n_rows, max_idx + 1 - current_row)
            chunk_mask = partition_map[current_row : current_row + valid_len]
            if valid_len < n_rows:
                chunk_mask = np.pad(chunk_mask, (0, n_rows - valid_len), constant_values=-1)

            for part, code in part_codes.items():
                matched = np.where(chunk_mask == code)[0]
                if len(matched) > 0:
                    sub = chunk.iloc[matched].copy()
                    sub["_src_row_idx"] = current_row + matched
                    row_chunks[part].append(sub)

            current_row = end_row
            if current_row > max_idx:
                break

    def assemble_partition(
        part_chunks: list[pd.DataFrame], expected_indices: np.ndarray, part_name: str
    ) -> dict[str, Any]:
        if not part_chunks:
            df = pd.DataFrame(columns=cols_to_read)
        else:
            df = pd.concat(part_chunks, ignore_index=True)

        if len(df) != len(expected_indices):
            raise ValueError(
                f"Row count mismatch in {part_name}: loaded {len(df)} rows, "
                f"expected {len(expected_indices)} from partition indices."
            )

        if len(expected_indices) > 1 and not np.all(expected_indices[:-1] <= expected_indices[1:]):
            df = df.set_index("_src_row_idx")
            df = df.loc[expected_indices].reset_index(drop=True)
        elif "_src_row_idx" in df.columns:
            df = df.drop(columns=["_src_row_idx"])

        y = df["Label"].to_numpy(dtype=np.int64) if len(df) > 0 else np.array([], dtype=np.int64)
        attack = df["Attack"].to_numpy(dtype=object) if len(df) > 0 else np.array([], dtype=object)

        # Reorder columns explicitly to 47 canonical ML features
        X_raw = df[list(ML_FEATURE_COLUMNS)].copy()

        # Transform via preprocessor and normalize to float64 NumPy array
        if hasattr(preprocessor, "transform"):
            X_trans = np.asarray(preprocessor.transform(X_raw), dtype=np.float64)
        else:
            X_trans = np.asarray(X_raw, dtype=np.float64)

        return {
            "X": X_trans,
            "y": y,
            "attack": attack,
            "X_raw_df": X_raw,
            "X_raw_cols": list(X_raw.columns),
        }

    return {
        part: assemble_partition(row_chunks[part], indices_by_part[part], part.capitalize())
        for part in selected_partitions
    }


def load_and_transform_test_partition(
    raw_data_path: Path,
    indices_dir: Path,
    split_manifest: Any,
    preprocessor: Any,
    model: Any,
    threshold_meta: dict[str, Any],
    evaluate_test: bool,
    sample_size: int | None = None,
    chunk_size: int = 100_000,
) -> dict[str, Any]:
    """Load and transform the held-out Test partition strictly after model fit and threshold freeze."""
    verify_test_evaluation_lock(
        model=model,
        threshold_meta=threshold_meta,
        evaluate_test=evaluate_test,
    )
    return load_and_transform_partitions(
        raw_data_path=raw_data_path,
        indices_dir=indices_dir,
        split_manifest=split_manifest,
        preprocessor=preprocessor,
        include_test=True,
        sample_size=sample_size,
        chunk_size=chunk_size,
        partitions=("test",),
    )["test"]


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
    if not np.isfinite(val_scores).all():
        raise ValueError("Cannot calibrate threshold: validation scores contain NaN or Inf.")

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

    benign_scores = np.asarray(val_scores[is_benign], dtype=np.float64)
    calib_scores = np.asarray(val_scores[calib_mask], dtype=np.float64)
    calib_y = np.asarray(val_y[calib_mask])

    n_benign = int(is_benign.sum())
    n_known_attack = int(is_known_attack.sum())
    n_unknown_excluded = int(is_unknown.sum())

    if method == "benign_quantile":
        quantile = max(0.0, min(1.0, 1.0 - target_fpr))
        threshold = float(np.percentile(benign_scores, quantile * 100))
    elif method == "fpr_constrained":
        sorted_benign = np.sort(benign_scores)
        n_ben = len(sorted_benign)
        unique_vals, first_idxs = np.unique(sorted_benign, return_index=True)
        # Because sorted_benign is non-decreasing and first_idxs holds the first index of each
        # distinct score, the number of benign samples with (score >= unique_vals[k]) is
        # exactly (n_ben - first_idxs[k]).
        candidate_fprs = (n_ben - first_idxs) / n_ben
        valid_mask = candidate_fprs <= target_fpr
        if np.any(valid_mask):
            first_valid_pos = int(np.argmax(valid_mask))
            threshold = float(unique_vals[first_valid_pos])
            while float(
                (benign_scores >= threshold).sum() / n_ben
            ) > target_fpr and first_valid_pos + 1 < len(unique_vals):
                first_valid_pos += 1
                threshold = float(unique_vals[first_valid_pos])
            if float((benign_scores >= threshold).sum() / n_ben) > target_fpr:
                threshold = float(np.nextafter(float(sorted_benign[-1]), np.inf))
        else:
            # No threshold inside observed benign scores meets FPR <= target_fpr (e.g.,
            # target_fpr == 0.0, target_fpr < 1 / n_ben, or ties at the maximum benign score).
            threshold = float(np.nextafter(float(sorted_benign[-1]), np.inf))
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
        "target_fpr": float(target_fpr),
        "empirical_val_fpr": empirical_fpr,
        "n_benign_used": n_benign,
        "n_known_attack_used": n_known_attack,
        "n_unknown_excluded": n_unknown_excluded,
        "unknown_categories_excluded": sorted(unknown_categories),
        "threshold_frozen": True,
    }


def verify_test_evaluation_lock(
    model: Any,
    threshold_meta: dict[str, Any] | None,
    evaluate_test: bool,
) -> None:
    """Fail-closed check ensuring Test evaluation occurs only after model & threshold freeze."""
    if not evaluate_test:
        raise RuntimeError(
            "Held-out Test Lock violation: Test evaluation requires --evaluate-test."
        )
    coefs = getattr(model, "coefs_", None)
    if coefs is None or len(coefs) == 0:
        raise RuntimeError(
            "Held-out Test Lock violation: Autoencoder must be fitted before Test evaluation."
        )
    if not isinstance(threshold_meta, dict) or threshold_meta.get("threshold_frozen") is not True:
        raise RuntimeError(
            "Held-out Test Lock violation: Validation threshold must be calibrated and frozen "
            "before Test evaluation."
        )
    th = threshold_meta.get("threshold")
    if (
        not isinstance(th, (numbers.Real, float, int))
        or isinstance(th, bool)
        or not np.isfinite(th)
        or float(th) < 0.0
    ):
        raise RuntimeError(f"Held-out Test Lock violation: invalid frozen threshold value {th!r}.")


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
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    prec_normal = tn / (tn + fn) if (tn + fn) > 0 else 0.0
    rec_normal = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1_normal = (
        2 * prec_normal * rec_normal / (prec_normal + rec_normal)
        if (prec_normal + rec_normal) > 0
        else 0.0
    )
    macro_f1 = (f1 + f1_normal) / 2.0

    roc_auc: float | None = None
    pr_auc: float | None = None
    if total > 0 and len(np.unique(y_true)) > 1 and len(scores) == total:
        try:
            roc_auc = float(roc_auc_score(y_true, scores))
            pr_auc = float(average_precision_score(y_true, scores))
        except Exception:
            pass

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
        "fnr": fnr,
        "tnr": tnr,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
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


def _resolve_unknown_categories(
    unknown_categories: Sequence[str] | frozenset[str] | set[str] | None,
    training_meta: dict[str, Any],
    threshold_meta: dict[str, Any],
) -> list[str]:
    """Resolve and normalize configured unknown attack categories for manifest metadata."""
    raw = (
        unknown_categories
        if unknown_categories is not None
        else training_meta.get("unknown_attack_categories")
    )
    if raw is None:
        raw = threshold_meta.get("unknown_categories_excluded")
    if raw is None:
        raw = DEFAULT_UNKNOWN_ATTACK_CATEGORIES
    if isinstance(raw, str):
        items = [c.strip() for c in raw.split(",") if c.strip()]
    else:
        items = [str(c).strip() for c in raw if str(c).strip()]
    return sorted(set(items))


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_optional_nonempty_str(value: Any) -> bool:
    return value is None or _is_nonempty_str(value)


def _is_valid_real_number(value: Any) -> bool:
    return isinstance(value, numbers.Real) and not isinstance(value, bool) and np.isfinite(value)


def _verify_safe_sidecar_file(
    manifest_dir: Path,
    manifest: dict[str, Any],
    file_key: str,
    sha_key: str,
    label: str,
) -> dict[str, Any]:
    """Verify safe relative filename, existence, SHA-256 digest, and JSON payload."""
    rel_name = manifest.get(file_key)
    expected_sha = manifest.get(sha_key)
    if not _is_nonempty_str(rel_name) or Path(rel_name).name != rel_name:
        raise ValueError(f"Manifest has invalid or unsafe {file_key}: {rel_name!r}")
    if not _is_nonempty_str(expected_sha):
        raise ValueError(f"Manifest missing required field: {sha_key}")

    sidecar_path = manifest_dir / rel_name
    if not sidecar_path.exists():
        raise FileNotFoundError(f"Autoencoder {label} sidecar not found: {sidecar_path}")

    actual_sha = sha256_file(sidecar_path)
    if actual_sha != expected_sha:
        raise ValueError(
            f"Autoencoder {label} SHA-256 mismatch!\n"
            f"  expected: {expected_sha}\n"
            f"  actual:   {actual_sha}"
        )

    try:
        with sidecar_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception as exc:
        raise ValueError(f"Autoencoder {label} JSON unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Autoencoder {label} JSON payload must be an object.")
    return payload


def _validate_manifest_provenance(
    manifest: dict[str, Any],
    config_payload: dict[str, Any],
    threshold_payload: dict[str, Any],
    require_complete_provenance: bool,
) -> None:
    """Validate linked dataset, split, preprocessor, model, and calibration provenance."""
    unknown_cats = manifest.get("unknown_attack_categories")
    if not isinstance(unknown_cats, list) or not all(_is_nonempty_str(c) for c in unknown_cats):
        raise ValueError("Manifest field 'unknown_attack_categories' must be a list of strings.")

    threshold_val = manifest.get("threshold")
    if not _is_valid_real_number(threshold_val) or float(threshold_val) < 0.0:
        raise ValueError(f"Manifest has invalid threshold: {threshold_val!r}")

    th_cal = manifest.get("threshold_calibration")
    if not isinstance(th_cal, dict) or th_cal != threshold_payload:
        raise ValueError("Manifest 'threshold_calibration' does not match verified threshold file.")
    cal_th = th_cal.get("threshold")
    if not _is_valid_real_number(cal_th) or float(cal_th) != float(threshold_val):
        raise ValueError("Manifest threshold disagrees with threshold_calibration.threshold.")

    cal_unknown = th_cal.get("unknown_categories_excluded")
    if cal_unknown is not None and sorted(map(str, cal_unknown)) != sorted(unknown_cats):
        raise ValueError(
            "Manifest unknown_attack_categories disagrees with "
            "threshold_calibration.unknown_categories_excluded."
        )

    arch = manifest.get("model_architecture")
    expected_dim = len(ML_FEATURE_COLUMNS)
    if (
        not isinstance(arch, dict)
        or arch.get("input_dimension") != expected_dim
        or arch.get("output_dimension") != expected_dim
    ):
        raise ValueError(
            f"Manifest model_architecture dimensions must match canonical {expected_dim} features."
        )

    hparams = manifest.get("hyperparameters")
    if not isinstance(hparams, dict) or not hparams or hparams != config_payload:
        raise ValueError("Manifest hyperparameters missing or inconsistent with config sidecar.")

    part_hashes = manifest.get("partition_indices_sha256")
    if (
        not isinstance(part_hashes, dict)
        or "train" not in part_hashes
        or "validation" not in part_hashes
    ):
        raise ValueError(
            "Manifest missing required 'partition_indices_sha256' entries for train and validation."
        )
    for part_name in ("train", "validation"):
        if not _is_optional_nonempty_str(part_hashes.get(part_name)):
            raise ValueError(f"Manifest has invalid partition index hash for '{part_name}'.")
    if "test" in part_hashes and not _is_optional_nonempty_str(part_hashes.get("test")):
        raise ValueError("Manifest has invalid partition index hash for 'test'.")

    for field in ("dataset_sha256", "split_manifest_sha256", "preprocessor_sha256"):
        if field not in manifest or not _is_optional_nonempty_str(manifest.get(field)):
            raise ValueError(f"Manifest has missing or invalid field: {field}")

    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("Manifest missing required 'provenance' metadata object.")
    prov_dataset = provenance.get("dataset", {})
    prov_split = provenance.get("split", {})
    prov_prep = provenance.get("preprocessor", {})
    prov_model = provenance.get("model", {})
    prov_cal = provenance.get("calibration", {})
    if (
        not isinstance(prov_dataset, dict)
        or not isinstance(prov_split, dict)
        or not isinstance(prov_prep, dict)
        or not isinstance(prov_model, dict)
        or not isinstance(prov_cal, dict)
    ):
        raise ValueError("Manifest 'provenance' sections must be objects.")

    if (
        prov_dataset.get("sha256") != manifest.get("dataset_sha256")
        or prov_split.get("manifest_sha256") != manifest.get("split_manifest_sha256")
        or prov_split.get("partition_indices_sha256") != part_hashes
        or prov_prep.get("artifact_sha256") != manifest.get("preprocessor_sha256")
        or prov_model.get("sha256") != manifest.get("model_sha256")
        or prov_model.get("config_sha256") != manifest.get("config_sha256")
        or prov_cal.get("threshold_sha256") != manifest.get("threshold_sha256")
        or prov_cal.get("unknown_attack_categories") != unknown_cats
    ):
        raise ValueError("Manifest 'provenance' object disagrees with top-level provenance fields.")

    enforce_full = require_complete_provenance or bool(manifest.get("provenance_complete"))
    if enforce_full:
        required_hashes = {
            "dataset_sha256": manifest.get("dataset_sha256"),
            "split_manifest_sha256": manifest.get("split_manifest_sha256"),
            "preprocessor_sha256": manifest.get("preprocessor_sha256"),
            "partition_indices_sha256.train": part_hashes.get("train"),
            "partition_indices_sha256.validation": part_hashes.get("validation"),
        }
        missing = [k for k, v in required_hashes.items() if not _is_nonempty_str(v)]
        if missing:
            raise ValueError(f"Manifest missing complete verified provenance hashes: {missing}")
        if th_cal.get("threshold_frozen") is not True:
            raise ValueError(
                "Complete provenance requires threshold_calibration.threshold_frozen=True."
            )


def compute_score_normalization(scores_val_cal: np.ndarray) -> dict[str, Any]:
    """Build quantile-based [0, 1] display normalization strictly from Validation scores."""
    arr = np.asarray(scores_val_cal, dtype=np.float64)
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        return {}
    grid = np.linspace(0.0, 1.0, 101)
    values = np.quantile(arr, grid)
    return {
        "calibration_partition": "validation",
        "score_direction": "higher_is_more_anomalous",
        "quantile_grid": [round(float(x), 4) for x in grid],
        "score_values": [float(v) for v in values],
    }


def save_artifacts(
    model: Any,
    config: dict[str, Any],
    threshold_meta: dict[str, Any],
    training_meta: dict[str, Any],
    output_dir: Path,
    unknown_categories: Sequence[str] | frozenset[str] | set[str] | None = None,
    score_normalization: dict[str, Any] | None = None,
    evaluation_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Save model artifact, configuration, threshold, and verified companion manifest."""
    output_dir.mkdir(parents=True, exist_ok=True)

    model_file = output_dir / "autoencoder_model.joblib"
    config_file = output_dir / "model_config.json"
    threshold_file = output_dir / "threshold.json"
    manifest_file = output_dir / "autoencoder_manifest.json"

    joblib.dump(model, model_file)
    model_sha256 = sha256_file(model_file)

    with config_file.open("w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)
    config_sha256 = sha256_file(config_file)

    with threshold_file.open("w", encoding="utf-8") as fh:
        json.dump(threshold_meta, fh, indent=2)
    threshold_sha256 = sha256_file(threshold_file)

    resolved_unknown = _resolve_unknown_categories(
        unknown_categories=unknown_categories,
        training_meta=training_meta,
        threshold_meta=threshold_meta,
    )

    raw_part_hashes = training_meta.get("partition_indices_sha256")
    part_hashes = dict(raw_part_hashes) if isinstance(raw_part_hashes, dict) else {}
    train_idx_sha = part_hashes.get("train") or training_meta.get("train_indices_sha256")
    val_idx_sha = part_hashes.get("validation") or training_meta.get("validation_indices_sha256")
    test_idx_sha = part_hashes.get("test") or training_meta.get("test_indices_sha256")

    partition_indices_sha256: dict[str, Any] = {
        "train": train_idx_sha,
        "validation": val_idx_sha,
    }
    if test_idx_sha is not None:
        partition_indices_sha256["test"] = test_idx_sha

    dataset_sha = training_meta.get("dataset_sha256")
    split_manifest_sha = training_meta.get("split_manifest_sha256")
    preprocessor_sha = training_meta.get("preprocessor_sha256")
    preprocessor_manifest_sha = training_meta.get("preprocessor_manifest_sha256")
    provenance_complete = all(
        _is_nonempty_str(v)
        for v in (
            dataset_sha,
            split_manifest_sha,
            preprocessor_sha,
            train_idx_sha,
            val_idx_sha,
        )
    )

    feature_contract_version = "nf-unsw-nb15-v3-baseline-47"
    provenance = {
        "dataset": {
            "sha256": dataset_sha,
        },
        "split": {
            "manifest_sha256": split_manifest_sha,
            "partition_indices_sha256": partition_indices_sha256,
        },
        "preprocessor": {
            "source": training_meta.get("preprocessor_source"),
            "artifact_sha256": preprocessor_sha,
            "manifest_sha256": preprocessor_manifest_sha,
        },
        "model": {
            "file": model_file.name,
            "sha256": model_sha256,
            "config_file": config_file.name,
            "config_sha256": config_sha256,
        },
        "calibration": {
            "threshold_file": threshold_file.name,
            "threshold_sha256": threshold_sha256,
            "method": threshold_meta.get("calibration_method"),
            "threshold_frozen": threshold_meta.get("threshold_frozen"),
            "unknown_attack_categories": resolved_unknown,
        },
        "feature_contract_version": feature_contract_version,
        "git_commit": training_meta.get("git_commit"),
    }

    manifest_data = {
        "artifact_type": "autoencoder-anomaly-detector",
        "schema_version": "1.0",
        "model_file": model_file.name,
        "model_sha256": model_sha256,
        "config_file": config_file.name,
        "config_sha256": config_sha256,
        "threshold_file": threshold_file.name,
        "threshold_sha256": threshold_sha256,
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
        "unknown_attack_categories": resolved_unknown,
        "dataset_sha256": dataset_sha,
        "split_manifest_sha256": split_manifest_sha,
        "partition_indices_sha256": partition_indices_sha256,
        "train_indices_sha256": train_idx_sha,
        "validation_indices_sha256": val_idx_sha,
        "preprocessor_sha256": preprocessor_sha,
        "preprocessor_manifest_sha256": preprocessor_manifest_sha,
        "preprocessor_source": training_meta.get("preprocessor_source"),
        "test_lock": training_meta.get("test_lock"),
        "provenance_complete": provenance_complete,
        "provenance": provenance,
        "feature_contract_version": feature_contract_version,
        "model_artifact_path": safe_relpath(model_file),
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": training_meta.get("git_commit"),
    }
    if score_normalization:
        manifest_data["score_normalization"] = score_normalization
    if evaluation_summary:
        manifest_data["evaluation_summary"] = evaluation_summary
        if evaluation_summary.get("test") is not None:
            manifest_data["experiment_status"] = "EXPERIMENTALLY VALIDATED"

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
        "config_sha256": config_sha256,
        "threshold_sha256": threshold_sha256,
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
    *,
    require_complete_provenance: bool = False,
) -> tuple[Any, dict[str, Any]]:
    """Fail-closed verified loader for Autoencoder artifact, sidecars, and manifest."""
    if not model_path.exists():
        raise FileNotFoundError(f"Autoencoder model artifact not found: {model_path}")
    if not manifest_path.exists():
        raise FileNotFoundError(f"Autoencoder companion manifest not found: {manifest_path}")

    try:
        with manifest_path.open("r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except Exception as exc:
        raise ValueError(f"Autoencoder manifest JSON unreadable: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ValueError("Autoencoder manifest must be a JSON object.")

    if manifest.get("artifact_type") != "autoencoder-anomaly-detector":
        raise ValueError(f"Unexpected artifact_type in manifest: {manifest.get('artifact_type')!r}")
    if manifest.get("schema_version") != "1.0":
        raise ValueError(f"Unsupported manifest schema_version: {manifest.get('schema_version')!r}")
    if manifest.get("feature_contract_version") != "nf-unsw-nb15-v3-baseline-47":
        raise ValueError(
            f"Unsupported feature_contract_version: {manifest.get('feature_contract_version')!r}"
        )

    model_file = manifest.get("model_file")
    if not _is_nonempty_str(model_file) or Path(model_file).name != model_file:
        raise ValueError(f"Manifest has invalid or unsafe model_file: {model_file!r}")
    if model_file != model_path.name:
        raise ValueError(
            f"Manifest model_file {model_file!r} does not match requested {model_path.name!r}."
        )

    expected_sha = manifest.get("model_sha256")
    if not _is_nonempty_str(expected_sha):
        raise ValueError("Manifest missing required field: model_sha256")

    actual_sha = sha256_file(model_path)
    if actual_sha != expected_sha:
        raise ValueError(
            f"Autoencoder artifact SHA-256 mismatch!\n"
            f"  expected: {expected_sha}\n"
            f"  actual:   {actual_sha}"
        )

    config_payload = _verify_safe_sidecar_file(
        manifest_path.parent, manifest, "config_file", "config_sha256", "config"
    )
    threshold_payload = _verify_safe_sidecar_file(
        manifest_path.parent, manifest, "threshold_file", "threshold_sha256", "threshold"
    )

    _validate_manifest_provenance(
        manifest=manifest,
        config_payload=config_payload,
        threshold_payload=threshold_payload,
        require_complete_provenance=require_complete_provenance,
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

    val_roc = f"{metrics_val['roc_auc']:.4f}" if metrics_val.get("roc_auc") is not None else "N/A"
    val_pr = f"{metrics_val['pr_auc']:.4f}" if metrics_val.get("pr_auc") is not None else "N/A"

    configured_unknown = (
        training_meta.get("unknown_attack_categories")
        if training_meta.get("unknown_attack_categories") is not None
        else threshold_meta.get("unknown_categories_excluded")
    )
    if configured_unknown is None:
        configured_unknown = sorted(DEFAULT_UNKNOWN_ATTACK_CATEGORIES)
    else:
        configured_unknown = sorted(str(c) for c in configured_unknown)
    part_hashes = training_meta.get("partition_indices_sha256") or {}

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
        ("- Configured unknown attack categories: " f"`{configured_unknown}`"),
        f"- Dataset SHA-256: `{training_meta.get('dataset_sha256', 'N/A')}`",
        f"- Split manifest SHA-256: `{training_meta.get('split_manifest_sha256', 'N/A')}`",
        f"- Train partition indices SHA-256: `{part_hashes.get('train', 'N/A')}`",
        f"- Validation partition indices SHA-256: `{part_hashes.get('validation', 'N/A')}`",
        f"- Preprocessor SHA-256: `{training_meta.get('preprocessor_sha256', 'N/A')}`",
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
        f"| False Negative Rate (FNR) | {metrics_val.get('fnr', 0.0):.4f} |",
        f"| True Negative Rate (TNR) | {metrics_val.get('tnr', 0.0):.4f} |",
        f"| ROC-AUC | {val_roc} |",
        f"| PR-AUC | {val_pr} |",
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
        test_roc = (
            f"{metrics_test['roc_auc']:.4f}" if metrics_test.get("roc_auc") is not None else "N/A"
        )
        test_pr = (
            f"{metrics_test['pr_auc']:.4f}" if metrics_test.get("pr_auc") is not None else "N/A"
        )
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
                f"| False Negative Rate (FNR) | {metrics_test.get('fnr', 0.0):.4f} |",
                f"| True Negative Rate (TNR) | {metrics_test.get('tnr', 0.0):.4f} |",
                f"| ROC-AUC | {test_roc} |",
                f"| PR-AUC | {test_pr} |",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "## 2. Test Performance",
                "",
                "> [!NOTE]",
                "> Held-out Test partition was LOCKED during this run (`--evaluate-test` not set).",
                "> When reading the unified CSV, Test rows were excluded at the chunk-mask",
                "> boundary (0 Test rows materialized, transformed, or used in training,",
                "> early stopping, or threshold calibration). Pass `--evaluate-test` to",
                "> evaluate Test only after model fitting and threshold freeze.",
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

    # 3. Stream & Extract Train/Validation Partitions ONLY (Held-out Test strictly deferred)
    print("[3/8] Loading and transforming Train/Validation partitions (Held-out Test locked)...")
    split_manifest_obj = split_res.get("manifest") or json.loads(
        Path(split_res["path"]).read_text(encoding="utf-8")
    )
    try:
        partitions = load_and_transform_partitions(
            raw_data_path=Path(dataset_res["path"]),
            indices_dir=args.indices_dir or INDICES_DIR_PATH,
            split_manifest=split_manifest_obj,
            preprocessor=preprocessor,
            include_test=False,
            sample_size=args.sample_size,
        )
    except Exception as exc:
        print(f"[BLOCKED] Failed to load partitions: {exc}")
        return 1

    if "test" in partitions:
        raise RuntimeError(
            "Held-out Test Lock violation: Test partition must not load prior to fit/calibration."
        )

    train_data = partitions["train"]
    val_data = partitions["validation"]

    print(f"  Train raw samples loaded: {len(train_data['y']):,}")
    print(f"  Validation raw samples loaded: {len(val_data['y']):,}")

    # 4. Leakage checks across Train and Validation partitions
    print("[4/8] Auditing Train/Validation feature matrices for target and metadata leakage...")
    for part_name, p_data in [("Train", train_data), ("Validation", val_data)]:
        leak_res = check_no_leakage_in_matrix(p_data["X_raw_df"])
        if leak_res["status"] != "PASS":
            print(f"FAILED: Data leakage in {part_name}: {leak_res['message']}")
            return 1
    print("  OK No leakage detected across Train and Validation partitions.")

    # 5. Schema and Finite checks for Train and Validation
    print("[5/8] Verifying Train/Validation feature schema and finite numeric values...")
    for part_name, p_data in [("Train", train_data), ("Validation", val_data)]:
        schema_res = check_feature_schema(p_data["X_raw_cols"])
        if schema_res["status"] != "PASS":
            print(f"FAILED: Feature schema mismatch in {part_name}: {schema_res['message']}")
            return 1
        fin_res = check_finite_values(p_data["X"], part_name)
        if fin_res["status"] != "PASS":
            print(f"FAILED: Non-finite values in {part_name}: {fin_res['message']}")
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
    known_cal_mask = ~np.isin(np.asarray(val_data["attack"], dtype=str), list(unknown_cats))
    cal_scores_for_norm = val_scores[known_cal_mask] if np.any(known_cal_mask) else val_scores
    score_norm = compute_score_normalization(cal_scores_for_norm)
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

    test_data: dict[str, Any] | None = None
    metrics_test = None
    if args.evaluate_test:
        # Unlock Test ONLY after Autoencoder fit and Validation threshold freeze
        verify_test_evaluation_lock(
            model=model,
            threshold_meta=threshold_meta,
            evaluate_test=args.evaluate_test,
        )
        print("  Loading, transforming, and evaluating held-out Test partition after lock...")
        try:
            test_data = load_and_transform_test_partition(
                raw_data_path=Path(dataset_res["path"]),
                indices_dir=args.indices_dir or INDICES_DIR_PATH,
                split_manifest=split_manifest_obj,
                preprocessor=preprocessor,
                model=model,
                threshold_meta=threshold_meta,
                evaluate_test=args.evaluate_test,
                sample_size=args.sample_size,
            )
        except Exception as exc:
            print(f"[BLOCKED] Failed to load held-out Test partition: {exc}")
            return 1

        print(f"  Test raw samples loaded: {len(test_data['y']):,}")
        leak_res = check_no_leakage_in_matrix(test_data["X_raw_df"])
        if leak_res["status"] != "PASS":
            print(f"FAILED: Data leakage in Test: {leak_res['message']}")
            return 1
        schema_res = check_feature_schema(test_data["X_raw_cols"])
        if schema_res["status"] != "PASS":
            print(f"FAILED: Feature schema mismatch in Test: {schema_res['message']}")
            return 1
        fin_res = check_finite_values(test_data["X"], "Test")
        if fin_res["status"] != "PASS":
            print(f"FAILED: Non-finite values in Test: {fin_res['message']}")
            return 1

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

    verified_idx = split_res.get("verified_indices") or {}
    train_idx_sha = (verified_idx.get("train") or {}).get("sha256")
    val_idx_sha = (verified_idx.get("validation") or {}).get("sha256")
    partition_indices_sha256: dict[str, Any] = {
        "train": train_idx_sha,
        "validation": val_idx_sha,
    }
    if args.evaluate_test and test_data is not None:
        test_idx_sha = (verified_idx.get("test") or {}).get("sha256")
        if test_idx_sha is not None:
            partition_indices_sha256["test"] = test_idx_sha

    prep_man_path = prep_res.get("manifest_path")
    prep_man_sha = (
        sha256_file(Path(prep_man_path)) if prep_man_path and Path(prep_man_path).exists() else None
    )

    test_lock_meta = {
        "contract": "held_out_test_lock_v1",
        "evaluate_test_flag": bool(args.evaluate_test),
        "test_evaluated": metrics_test is not None,
        "test_rows_materialized": len(test_data["y"]) if test_data is not None else 0,
        "test_excluded_from_fit_early_stopping_calibration": True,
        "threshold_frozen_before_test_eval": bool(threshold_meta.get("threshold_frozen")),
        "test_loaded_after_model_fit_and_threshold_freeze": True,
        "unified_csv_stream_bounded_to_loaded_partitions": True,
    }

    training_meta = {
        "model_type": "Autoencoder (MLPRegressor)",
        "hidden_layer_sizes": hidden_layers,
        "training_population": "benign-only (Label == 0)",
        "n_train_samples": n_train_benign,
        "n_val_samples": len(val_data["y"]),
        "n_test_samples": len(test_data["y"]) if test_data else 0,
        "unknown_attack_categories": sorted(unknown_cats),
        "dataset_sha256": dataset_res.get("sha256"),
        "split_manifest_sha256": split_res.get("manifest_sha256"),
        "partition_indices_sha256": partition_indices_sha256,
        "train_indices_sha256": train_idx_sha,
        "validation_indices_sha256": val_idx_sha,
        "preprocessor_sha256": prep_res.get("sha256"),
        "preprocessor_manifest_sha256": prep_man_sha,
        "preprocessor_source": "TrainOnlyPreprocessor.load_verified",
        "test_lock": test_lock_meta,
        "git_commit": git_commit,
        "elapsed_seconds": round(time.time() - start_time, 2),
    }

    art_res = save_artifacts(
        model=model,
        config=model_cfg,
        threshold_meta=threshold_meta,
        training_meta=training_meta,
        output_dir=output_dir,
        unknown_categories=unknown_cats,
        score_normalization=score_norm,
        evaluation_summary={"validation": metrics_val, "test": metrics_test},
    )
    print(f"  OK Artifacts saved to: {output_dir}")

    if output_dir.resolve() == DEFAULT_OUTPUT_DIR.resolve():
        DEFAULT_REPORT_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        with DEFAULT_REPORT_MANIFEST_PATH.open("w", encoding="utf-8") as fh:
            json.dump(art_res["manifest"], fh, indent=2)
        print(f"  OK Report manifest mirrored to: {DEFAULT_REPORT_MANIFEST_PATH}")

    sample_eval = val_data["X"][: min(100, len(val_data["X"]))]
    verify_res = verify_saved_model(
        model_path=Path(art_res["files"]["model"]),
        original_model=model,
        X_sample=sample_eval,
    )
    if verify_res["status"] != "PASS":
        print(f"FAILED: {verify_res['message']}")
        return 1

    load_verified_autoencoder(
        model_path=Path(art_res["files"]["model"]),
        manifest_path=Path(art_res["files"]["manifest"]),
        require_complete_provenance=True,
    )
    print("  OK Saved artifact, companion manifest, and provenance verified.")

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
