"""Independent held-out Test set evaluation for the Random Forest baseline (Issue #12).

Enforces fail-closed verification of dataset, split manifest, test partition indices,
train-only preprocessor artifact, and trained Random Forest model artifact before
executing post-training evaluation on the locked Test set.

Scientific Integrity Rules:
  - Test partition is evaluated strictly post-training (zero refitting, zero tuning,
    zero threshold optimization).
  - Preprocessor applies transform() only (fitted exclusively on Train).
  - Feature schema is strictly enforced (47 ML_FEATURE_COLUMNS in canonical order,
    excluding Label, Attack, and TRACE_METADATA_COLUMNS).
  - Evaluation artifacts are written with run-specific provenance and SHA-256 hashes.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
)
from network_anomaly.evaluation.metrics import (
    compute_attack_category_breakdown,
    compute_metrics,
)
from network_anomaly.models.random_forest import RandomForestModel
from network_anomaly.models.random_forest_protocol import (
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_CONTRACT_ID,
    PROTOCOL_IDENTIFIER,
    SPLIT_PROTOCOL_ID,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor

# Canonical default paths relative to repository root
DEFAULT_DATASET_CSV_PATH = Path("data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv")
DEFAULT_DATASET_MANIFEST_PATH = Path("data/NF_UNSW_NB15_V3_MANIFEST.json")
DEFAULT_SPLIT_MANIFEST_PATH = Path("reports/splits/nf_unsw_nb15_v3_split_manifest.json")
DEFAULT_TRAIN_INDICES_PATH = Path("data/processed/splits/train_indices.csv.gz")
DEFAULT_VAL_INDICES_PATH = Path("data/processed/splits/validation_indices.csv.gz")
DEFAULT_TEST_INDICES_PATH = Path("data/processed/splits/test_indices.csv.gz")
DEFAULT_PREPROCESSING_MANIFEST_PATH = Path(
    "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json"
)
DEFAULT_PREPROCESSOR_ARTIFACT_PATH = Path(
    "artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib"
)
DEFAULT_MODEL_MANIFEST_PATH = Path("reports/models/random_forest_manifest.json")
DEFAULT_MODEL_ARTIFACT_PATH = Path("artifacts/models/random_forest/random_forest_baseline.joblib")
DEFAULT_EVALUATION_OUTPUT_DIR = Path("reports/evaluation")

CANONICAL_DECISION_THRESHOLD: float = 0.5


def _sha256_file(path: Union[str, Path], chunk_bytes: int = 1024 * 1024) -> str:
    """Compute hex SHA-256 digest of a file."""
    p = Path(path)
    digest = hashlib.sha256()
    with p.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_bytes), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_git_commit() -> str:
    """Resolve current Git HEAD commit SHA or 'UNKNOWN' if unavailable."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        sha = res.stdout.strip()
        if sha:
            return sha
    except Exception:
        pass
    return "UNKNOWN"


def _is_valid_sha256_hex(val: Any) -> bool:
    """Return True if val is a valid 64-character hexadecimal SHA-256 string."""
    if not isinstance(val, str) or len(val) != 64:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in val)


def _load_indices_csv_gz(path: Union[str, Path]) -> np.ndarray:
    """Load integer row indices from a gzipped or plain CSV index file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Split index file not found: {p}")

    open_fn = gzip.open if p.suffix == ".gz" else open
    indices: List[int] = []
    with open_fn(p, mode="rt", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            raise ValueError(f"Split index file is empty: {p}")
        clean_header = [h.strip() for h in header]
        col_idx = 0
        if "source_row_index" in clean_header:
            col_idx = clean_header.index("source_row_index")
        elif "row_index" in clean_header:
            col_idx = clean_header.index("row_index")
        elif len(clean_header) == 1 and clean_header[0].isdigit():
            indices.append(int(clean_header[0]))
        else:
            raise ValueError(
                f"Unrecognized header {header!r} in split index file {p}; "
                f"expected 'source_row_index' or 'row_index'"
            )

        for line_num, row in enumerate(reader, start=2):
            if not row or all(not cell.strip() for cell in row):
                continue
            try:
                token = row[col_idx].strip()
                if not token or "." in token:
                    raise ValueError(f"Non-integer token {token!r}")
                val = int(token)
            except (ValueError, IndexError) as exc:
                raise ValueError(f"Malformed row index at line {line_num} in {p}: {row!r}") from exc
            if val < 0:
                raise ValueError(f"Negative row index {val} at line {line_num} in {p}")
            indices.append(val)

    if not indices:
        raise ValueError(f"No row indices loaded from {p}")

    arr = np.asarray(indices, dtype=np.int64)
    if len(np.unique(arr)) != len(arr):
        raise ValueError(f"Duplicate row indices detected in split index file: {p}")
    return arr


def compute_confusion_matrix_breakdown(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    labels: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    """Compute a detailed confusion matrix breakdown (TN, FP, FN, TP and rates)."""
    target_labels = list(labels) if labels is not None else [0, 1]
    cm = confusion_matrix(y_true, y_pred, labels=target_labels)
    tn = int(cm[0, 0])
    fp = int(cm[0, 1])
    fn = int(cm[1, 0])
    tp = int(cm[1, 1])
    total = tn + fp + fn + tp
    benign_total = tn + fp
    attack_total = tp + fn
    return {
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "total": total,
        "benign_total": benign_total,
        "attack_total": attack_total,
        "false_positive_rate": float(fp / benign_total) if benign_total > 0 else 0.0,
        "true_negative_rate": float(tn / benign_total) if benign_total > 0 else 0.0,
        "true_positive_rate": float(tp / attack_total) if attack_total > 0 else 0.0,
        "false_negative_rate": float(fn / attack_total) if attack_total > 0 else 0.0,
        "confusion_matrix": cm.tolist(),
    }


def compute_benign_false_positive_breakdown(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    attack_categories: Optional[Sequence[str]] = None,
) -> Dict[str, Union[int, float]]:
    """Compute Benign traffic false positive count, true negative count, and FPR."""
    if attack_categories is not None:
        cat_breakdown = compute_attack_category_breakdown(y_true, y_pred, attack_categories)
        if "Benign" in cat_breakdown:
            return dict(cat_breakdown["Benign"])
    cm_info = compute_confusion_matrix_breakdown(y_true, y_pred)
    return {
        "total": int(cm_info["benign_total"]),
        "false_positive": int(cm_info["fp"]),
        "true_negative": int(cm_info["tn"]),
        "false_positive_rate": float(cm_info["false_positive_rate"]),
    }


def verify_index_disjointness(
    train_indices_path: Union[str, Path, None] = DEFAULT_TRAIN_INDICES_PATH,
    val_indices_path: Union[str, Path, None] = DEFAULT_VAL_INDICES_PATH,
    test_indices_path: Union[str, Path, None] = DEFAULT_TEST_INDICES_PATH,
    split_manifest: Optional[Dict[str, Any]] = None,
    total_source_rows: Optional[int] = None,
) -> Tuple[bool, List[str]]:
    """Perform genuine set operations and bounds checking to verify partition index disjointness.

    Verifies:
      1. Train, Validation, and Test index files all exist on disk (fail-closed if missing).
      2. SHA-256 of each index file matches canonical split manifest 'index_sha256'.
      3. Partition row counts match split manifest 'row_count' when manifest is provided.
      4. No duplicate row indices exist within any partition.
      5. All row indices fall within [0, total_source_rows - 1].
      6. Genuine pairwise disjointness via set operations:
         - Train & Test == empty set
         - Validation & Test == empty set
         - Train & Validation == empty set

    Returns
    -------
    Tuple[bool, List[str]]
        (is_disjoint_verified, list_of_errors)
    """
    errors: List[str] = []

    paths = {
        "train": Path(train_indices_path) if train_indices_path is not None else None,
        "validation": Path(val_indices_path) if val_indices_path is not None else None,
        "test": Path(test_indices_path) if test_indices_path is not None else None,
    }

    missing = [name for name, p in paths.items() if p is None or not p.exists()]
    if missing:
        errors.append(
            f"Cannot verify index disjointness: missing partition index file(s) on disk: {missing}"
        )
        return False, errors

    # Check canonical index_sha256 if split_manifest is provided
    partitions_meta: Dict[str, Any] = {}
    if split_manifest is not None:
        raw_parts = split_manifest.get("partitions")
        if not isinstance(raw_parts, dict):
            errors.append("Split manifest missing required 'partitions' object")
        else:
            partitions_meta = raw_parts
            for name, p in paths.items():
                if p is None:
                    continue
                part_meta = partitions_meta.get(name)
                if not isinstance(part_meta, dict):
                    errors.append(
                        f"Split manifest missing required partition metadata for '{name}'"
                    )
                    continue
                expected_sha = part_meta.get("index_sha256")
                if (
                    not expected_sha
                    or not isinstance(expected_sha, str)
                    or not expected_sha.strip()
                ):
                    errors.append(
                        f"Split manifest partitions.{name} missing required 'index_sha256' key"
                    )
                else:
                    if not _is_valid_sha256_hex(expected_sha):
                        errors.append(
                            f"Split manifest partitions.{name} has malformed 'index_sha256': "
                            f"{expected_sha!r}"
                        )
                    actual_sha = _sha256_file(p)
                    if actual_sha.lower() != expected_sha.lower():
                        errors.append(
                            f"{name} index file SHA-256 mismatch: "
                            f"expected {expected_sha}, got {actual_sha}"
                        )

    # Load indices
    try:
        assert paths["train"] is not None
        assert paths["validation"] is not None
        assert paths["test"] is not None
        train_idx = _load_indices_csv_gz(paths["train"])
        val_idx = _load_indices_csv_gz(paths["validation"])
        test_idx = _load_indices_csv_gz(paths["test"])
    except Exception as exc:
        errors.append(f"Failed loading indices for disjointness check: {exc}")
        return False, errors

    # Verify partition row counts against split manifest when available
    if partitions_meta:
        for part_key, arr in [
            ("train", train_idx),
            ("validation", val_idx),
            ("test", test_idx),
        ]:
            part_meta = partitions_meta.get(part_key)
            if isinstance(part_meta, dict) and "row_count" in part_meta:
                exp_rows = part_meta.get("row_count")
                if (
                    isinstance(exp_rows, int)
                    and not isinstance(exp_rows, bool)
                    and len(arr) != exp_rows
                ):
                    errors.append(
                        f"{part_key} index row count ({len(arr)}) != "
                        f"split manifest expected row_count ({exp_rows})"
                    )

    # Check internal duplicates and bounds
    max_rows = total_source_rows
    if max_rows is None and split_manifest is not None:
        max_rows = split_manifest.get("total_source_rows")

    if max_rows is not None and (
        isinstance(max_rows, bool) or not isinstance(max_rows, int) or max_rows <= 0
    ):
        errors.append(f"Invalid total_source_rows in split manifest: {max_rows!r}")
        max_rows = None

    for name, arr in [("Train", train_idx), ("Validation", val_idx), ("Test", test_idx)]:
        if len(np.unique(arr)) != len(arr):
            errors.append(f"Internal duplicate row indices detected in {name} partition")
        if max_rows is not None:
            if np.any(arr < 0) or np.any(arr >= max_rows):
                errors.append(
                    f"{name} partition contains row indices outside valid range [0, {max_rows - 1}]"
                )

    # Genuine set operations
    train_set = set(int(x) for x in train_idx)
    val_set = set(int(x) for x in val_idx)
    test_set = set(int(x) for x in test_idx)

    overlap_train_val = train_set & val_set
    if overlap_train_val:
        errors.append(
            f"Data leakage detected: {len(overlap_train_val)} overlapping indices "
            f"between Train and Validation partitions!"
        )

    overlap_train_test = train_set & test_set
    if overlap_train_test:
        errors.append(
            f"Data leakage detected: {len(overlap_train_test)} overlapping indices "
            f"between Train and Test partitions!"
        )

    overlap_val_test = val_set & test_set
    if overlap_val_test:
        errors.append(
            f"Data leakage detected: {len(overlap_val_test)} overlapping indices "
            f"between Validation and Test partitions!"
        )

    is_verified = len(errors) == 0
    return is_verified, errors


@dataclass
class TestEvaluationPrerequisiteStatus:
    """Status container for fail-closed held-out test prerequisite verification."""

    __test__ = False

    ready: bool
    status: str
    missing_artifacts: List[str] = field(default_factory=list)
    verification_errors: List[str] = field(default_factory=list)
    verified_hashes: Dict[str, str] = field(default_factory=dict)
    expected_test_rows: Optional[int] = None
    expected_benign_rows: Optional[int] = None
    expected_attack_rows: Optional[int] = None
    expected_attack_distribution: Optional[Dict[str, int]] = None
    train_validation_disjoint_verified: bool = False
    partition_verification_status: str = "NOT_CHECKED"

    def to_dict(self) -> Dict[str, Any]:
        """Convert status to a serializable dictionary."""
        return asdict(self)


@dataclass
class TestPartitionData:
    """Extracted held-out test partition data and ground truth."""

    __test__ = False

    X_test_raw: pd.DataFrame
    y_test: np.ndarray
    attack_categories: np.ndarray
    row_indices: np.ndarray
    trace_metadata: Optional[pd.DataFrame] = None
    num_rows: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.X_test_raw, pd.DataFrame):
            raise ValueError("X_test_raw must be a pandas DataFrame")
        self.num_rows = len(self.X_test_raw)
        if self.row_indices is None:
            raise ValueError("row_indices must not be None")
        idx_arr = np.asarray(self.row_indices)
        if idx_arr.ndim != 1 or len(idx_arr) != self.num_rows:
            raise ValueError(
                f"row_indices must be 1D with length matching X_test_raw ({self.num_rows}), "
                f"got shape {idx_arr.shape}"
            )
        if idx_arr.dtype == bool or not np.issubdtype(idx_arr.dtype, np.integer):
            raise ValueError(f"row_indices must have integer dtype, got {idx_arr.dtype}")
        if np.any(idx_arr < 0):
            raise ValueError("row_indices must not contain negative values")
        if len(np.unique(idx_arr)) != len(idx_arr):
            raise ValueError("row_indices must not contain duplicate source row identifiers")
        if len(self.y_test) != self.num_rows or len(self.attack_categories) != self.num_rows:
            raise ValueError(
                "y_test and attack_categories must have identical length to X_test_raw"
            )


def check_test_evaluation_prerequisites(
    dataset_csv_path: Union[str, Path] = DEFAULT_DATASET_CSV_PATH,
    split_manifest_path: Union[str, Path] = DEFAULT_SPLIT_MANIFEST_PATH,
    test_indices_path: Union[str, Path] = DEFAULT_TEST_INDICES_PATH,
    train_indices_path: Union[str, Path, None] = DEFAULT_TRAIN_INDICES_PATH,
    val_indices_path: Union[str, Path, None] = DEFAULT_VAL_INDICES_PATH,
    preprocessing_manifest_path: Union[str, Path] = DEFAULT_PREPROCESSING_MANIFEST_PATH,
    preprocessor_artifact_path: Union[str, Path] = DEFAULT_PREPROCESSOR_ARTIFACT_PATH,
    model_manifest_path: Union[str, Path] = DEFAULT_MODEL_MANIFEST_PATH,
    model_artifact_path: Union[str, Path] = DEFAULT_MODEL_ARTIFACT_PATH,
    verify_dataset_hash: bool = True,
    fail_closed: bool = False,
) -> TestEvaluationPrerequisiteStatus:
    """Fail-closed prerequisite check for held-out Test evaluation.

    Parameters
    ----------
    dataset_csv_path : Path-like
        Path to raw NF-UNSW-NB15-v3.csv dataset.
    split_manifest_path : Path-like
        Path to split manifest JSON.
    test_indices_path : Path-like
        Path to test partition indices gzip CSV.
    train_indices_path : Path-like, optional
        Path to train partition indices gzip CSV.
    val_indices_path : Path-like, optional
        Path to validation partition indices gzip CSV.
    preprocessing_manifest_path : Path-like
        Path to preprocessing manifest JSON.
    preprocessor_artifact_path : Path-like
        Path to fitted TrainOnlyPreprocessor joblib artifact.
    model_manifest_path : Path-like
        Path to Random Forest training manifest JSON.
    model_artifact_path : Path-like
        Path to trained Random Forest model joblib artifact.
    verify_dataset_hash : bool, default True
        Whether to compute and verify SHA-256 of the raw dataset CSV.
    fail_closed : bool, default False
        If True, raises FileNotFoundError or ValueError immediately when any check fails.

    Returns
    -------
    TestEvaluationPrerequisiteStatus
        Structured prerequisite check status.
    """
    missing: List[str] = []
    errors: List[str] = []
    hashes: Dict[str, str] = {}

    ds_path = Path(dataset_csv_path)
    sm_path = Path(split_manifest_path)
    ti_path = Path(test_indices_path)
    tri_path = Path(train_indices_path) if train_indices_path is not None else None
    vi_path = Path(val_indices_path) if val_indices_path is not None else None
    pm_path = Path(preprocessing_manifest_path)
    pa_path = Path(preprocessor_artifact_path)
    mm_path = Path(model_manifest_path)
    ma_path = Path(model_artifact_path)

    for label, p in [
        ("dataset_csv", ds_path),
        ("split_manifest", sm_path),
        ("test_indices", ti_path),
        ("preprocessing_manifest", pm_path),
        ("preprocessor_artifact", pa_path),
        ("model_manifest", mm_path),
        ("model_artifact", ma_path),
    ]:
        if not p.exists():
            missing.append(f"{label}: {p.as_posix()}")

    for part_label, opt_p in [
        ("train_indices", tri_path),
        ("validation_indices", vi_path),
    ]:
        if opt_p is None or not opt_p.exists():
            p_str = opt_p.as_posix() if opt_p is not None else "None"
            missing.append(f"{part_label}: {p_str}")

    expected_test_rows: Optional[int] = None
    expected_benign_rows: Optional[int] = None
    expected_attack_rows: Optional[int] = None
    expected_attack_dist: Optional[Dict[str, int]] = None

    split_manifest: Optional[Dict[str, Any]] = None
    if sm_path.exists():
        try:
            hashes["split_manifest_sha256"] = _sha256_file(sm_path)
            with sm_path.open("r", encoding="utf-8") as f:
                split_manifest = json.load(f)
            if not isinstance(split_manifest, dict) or "partitions" not in split_manifest:
                errors.append(f"Split manifest {sm_path} missing required 'partitions' object")
                split_manifest = split_manifest if isinstance(split_manifest, dict) else {}
            test_info = split_manifest.get("partitions", {}).get("test", {})
            if isinstance(test_info, dict):
                expected_test_rows = test_info.get("row_count")
                lbl_dist = test_info.get("label_distribution", {})
                if isinstance(lbl_dist, dict):
                    expected_benign_rows = lbl_dist.get("0")
                    expected_attack_rows = lbl_dist.get("1")
                att_dist = test_info.get("attack_distribution")
                if isinstance(att_dist, dict):
                    expected_attack_dist = {str(k): int(v) for k, v in att_dist.items()}
        except Exception as exc:
            errors.append(f"Failed to parse split manifest {sm_path}: {exc}")

    prep_manifest: Optional[Dict[str, Any]] = None
    if pm_path.exists():
        try:
            hashes["preprocessing_manifest_sha256"] = _sha256_file(pm_path)
            with pm_path.open("r", encoding="utf-8") as f:
                prep_manifest = json.load(f)
            if not isinstance(prep_manifest, dict) or not prep_manifest:
                errors.append(f"Preprocessing manifest {pm_path} is empty or not a JSON object")
                prep_manifest = {}
            else:
                artifact_type = prep_manifest.get("artifact_type")
                if artifact_type != "nf-unsw-nb15-v3-train-only-preprocessor":
                    errors.append(
                        f"Preprocessing manifest must have "
                        f"artifact_type='nf-unsw-nb15-v3-train-only-preprocessor', "
                        f"got {artifact_type!r}"
                    )
                if "fit_partition" in prep_manifest:
                    fit_part = prep_manifest.get("fit_partition")
                    if fit_part not in ("train", "train_only"):
                        errors.append(
                            f"Preprocessing manifest fit_partition must be 'train' or 'train_only', "  # noqa: E501
                            f"got {fit_part!r}"
                        )
                pm_ds_sha = prep_manifest.get("dataset_sha256")
                if not _is_valid_sha256_hex(pm_ds_sha):
                    errors.append(
                        f"Preprocessing manifest missing or malformed 'dataset_sha256': {pm_ds_sha!r}"  # noqa: E501
                    )
                pm_sm_sha = prep_manifest.get("split_manifest_sha256")
                if not _is_valid_sha256_hex(pm_sm_sha):
                    errors.append(
                        f"Preprocessing manifest missing or malformed 'split_manifest_sha256': "
                        f"{pm_sm_sha!r}"
                    )
                pm_art_sha = prep_manifest.get("artifact_sha256")
                if not _is_valid_sha256_hex(pm_art_sha):
                    errors.append(
                        f"Preprocessing manifest missing or malformed 'artifact_sha256': "
                        f"{pm_art_sha!r}"
                    )
                pm_fc_ver = prep_manifest.get("feature_contract_version")
                if pm_fc_ver != FEATURE_CONTRACT_VERSION:
                    errors.append(
                        f"Preprocessing manifest feature_contract_version mismatch: "
                        f"expected {FEATURE_CONTRACT_VERSION!r}, got {pm_fc_ver!r}"
                    )
                pm_base_feats = prep_manifest.get("baseline_ml_features_in_order")
                if pm_base_feats != list(ML_FEATURE_COLUMNS):
                    errors.append(
                        "Preprocessing manifest 'baseline_ml_features_in_order' "
                        "does not match canonical ML_FEATURE_COLUMNS"
                    )
                pm_out_feats = prep_manifest.get("output_features_in_order")
                if pm_out_feats != list(ML_FEATURE_COLUMNS):
                    errors.append(
                        "Preprocessing manifest 'output_features_in_order' "
                        "does not match canonical ML_FEATURE_COLUMNS"
                    )
                pm_train_rows = prep_manifest.get("train_row_count")
                if (
                    isinstance(pm_train_rows, bool)
                    or not isinstance(pm_train_rows, int)
                    or pm_train_rows <= 0
                ):
                    errors.append(
                        f"Preprocessing manifest 'train_row_count' must be a positive integer, "
                        f"got {pm_train_rows!r}"
                    )
        except Exception as exc:
            errors.append(f"Failed to parse preprocessing manifest {pm_path}: {exc}")

    model_manifest: Optional[Dict[str, Any]] = None
    if mm_path.exists():
        try:
            hashes["model_manifest_sha256"] = _sha256_file(mm_path)
            with mm_path.open("r", encoding="utf-8") as f:
                model_manifest = json.load(f)
        except Exception as exc:
            errors.append(f"Failed to parse model manifest {mm_path}: {exc}")

    # Cross-check manifest lineage even when binary files are absent
    if split_manifest and prep_manifest:
        sm_sha = hashes.get("split_manifest_sha256")
        pm_sm_sha = prep_manifest.get("split_manifest_sha256")
        if sm_sha and pm_sm_sha and sm_sha.lower() != str(pm_sm_sha).lower():
            errors.append(
                f"Split manifest SHA-256 mismatch between {sm_path} ({sm_sha}) "
                f"and preprocessing manifest ({pm_sm_sha})"
            )
        sm_ds_sha = split_manifest.get("dataset_sha256")
        pm_ds_sha = prep_manifest.get("dataset_sha256")
        if sm_ds_sha and pm_ds_sha and str(sm_ds_sha).lower() != str(pm_ds_sha).lower():
            errors.append(
                f"Dataset SHA-256 mismatch between split manifest ({sm_ds_sha}) "
                f"and preprocessing manifest ({pm_ds_sha})"
            )
        sm_train_rows = (
            split_manifest.get("partitions", {}).get("train", {}).get("row_count")
            if isinstance(split_manifest.get("partitions"), dict)
            else None
        )
        pm_train_rows = prep_manifest.get("train_row_count")
        if (
            isinstance(sm_train_rows, int)
            and not isinstance(sm_train_rows, bool)
            and isinstance(pm_train_rows, int)
            and not isinstance(pm_train_rows, bool)
            and sm_train_rows != pm_train_rows
        ):
            errors.append(
                f"Train row count mismatch between split manifest ({sm_train_rows}) "
                f"and preprocessing manifest ({pm_train_rows})"
            )

    if split_manifest and model_manifest:
        sm_sha = hashes.get("split_manifest_sha256")
        mm_sm_sha = model_manifest.get("split_manifest_sha256")
        if sm_sha and mm_sm_sha and sm_sha.lower() != str(mm_sm_sha).lower():
            errors.append(
                f"Split manifest SHA-256 mismatch between {sm_path} ({sm_sha}) "
                f"and model manifest ({mm_sm_sha})"
            )
        sm_ds_sha = split_manifest.get("dataset_sha256")
        mm_ds_sha = model_manifest.get("dataset_sha256")
        if sm_ds_sha and mm_ds_sha and str(sm_ds_sha).lower() != str(mm_ds_sha).lower():
            errors.append(
                f"Dataset SHA-256 mismatch between split manifest ({sm_ds_sha}) "
                f"and model manifest ({mm_ds_sha})"
            )

    if prep_manifest and model_manifest:
        pm_prep_sha = prep_manifest.get("artifact_sha256")
        mm_prep_sha = model_manifest.get("preprocessor_artifact_sha256")
        if pm_prep_sha and mm_prep_sha and str(pm_prep_sha).lower() != str(mm_prep_sha).lower():
            errors.append(
                f"Preprocessor artifact SHA-256 mismatch between preprocessing manifest "
                f"({pm_prep_sha}) and model manifest ({mm_prep_sha})"
            )

    # Verify binary artifacts if present
    if ds_path.exists() and verify_dataset_hash:
        actual_ds_sha = _sha256_file(ds_path)
        hashes["dataset_sha256"] = actual_ds_sha
        expected_ds_sha = (model_manifest or {}).get("dataset_sha256") or (
            split_manifest or {}
        ).get("dataset_sha256")
        if expected_ds_sha and actual_ds_sha.lower() != str(expected_ds_sha).lower():
            errors.append(
                f"Dataset CSV SHA-256 mismatch: expected {expected_ds_sha}, got {actual_ds_sha}"
            )

    if ti_path.exists():
        try:
            actual_ti_sha = _sha256_file(ti_path)
            hashes["test_indices_sha256"] = actual_ti_sha
            test_part_meta = (
                (split_manifest or {}).get("partitions", {}).get("test", {})
                if isinstance((split_manifest or {}).get("partitions"), dict)
                else {}
            )
            expected_ti_sha = (
                test_part_meta.get("index_sha256") if isinstance(test_part_meta, dict) else None
            )
            if (
                not expected_ti_sha
                or not isinstance(expected_ti_sha, str)
                or not expected_ti_sha.strip()
            ):
                errors.append("Split manifest partitions.test missing required 'index_sha256' key")
            else:
                if not _is_valid_sha256_hex(expected_ti_sha):
                    errors.append(
                        f"Split manifest partitions.test has malformed 'index_sha256': "
                        f"{expected_ti_sha!r}"
                    )
                if actual_ti_sha.lower() != expected_ti_sha.lower():
                    errors.append(
                        f"test_indices SHA-256 mismatch: "
                        f"expected {expected_ti_sha}, got {actual_ti_sha}"
                    )
            test_idx = _load_indices_csv_gz(ti_path)
            if expected_test_rows is not None and len(test_idx) != int(expected_test_rows):
                errors.append(
                    f"test_indices row count ({len(test_idx)}) != "
                    f"split manifest expected row_count ({expected_test_rows})"
                )
        except Exception as exc:
            errors.append(f"Failed to verify test_indices at {ti_path}: {exc}")

    # Index disjointness verification (fail-closed if any partition indices missing)
    all_index_files_present = (
        tri_path is not None
        and tri_path.exists()
        and vi_path is not None
        and vi_path.exists()
        and ti_path.exists()
    )
    disjoint_verified, disjoint_errors = verify_index_disjointness(
        train_indices_path=train_indices_path,
        val_indices_path=val_indices_path,
        test_indices_path=test_indices_path,
        split_manifest=split_manifest,
        total_source_rows=(split_manifest or {}).get("total_source_rows"),
    )
    if not disjoint_verified:
        errors.extend(disjoint_errors)

    if not all_index_files_present:
        partition_status = "BLOCKED"
    elif disjoint_verified:
        partition_status = "VERIFIED"
    else:
        partition_status = "FAILED"

    if pa_path.exists():
        try:
            actual_pa_sha = _sha256_file(pa_path)
            hashes["preprocessor_artifact_sha256"] = actual_pa_sha
            expected_pa_sha = (prep_manifest or {}).get("artifact_sha256") or (
                model_manifest or {}
            ).get("preprocessor_artifact_sha256")
            if expected_pa_sha and actual_pa_sha.lower() != str(expected_pa_sha).lower():
                errors.append(
                    f"Preprocessor artifact SHA-256 mismatch: "
                    f"expected {expected_pa_sha}, got {actual_pa_sha}"
                )
            if pm_path.exists():
                expected_ds_for_prep = (prep_manifest or {}).get("dataset_sha256") or (
                    split_manifest or {}
                ).get("dataset_sha256")
                load_kwargs: Dict[str, Any] = {
                    "artifact_path": pa_path,
                    "manifest_path": pm_path,
                }
                if isinstance(expected_ds_for_prep, str) and expected_ds_for_prep:
                    load_kwargs["expected_dataset_sha256"] = expected_ds_for_prep
                preprocessor = TrainOnlyPreprocessor.load_verified(**load_kwargs)
            else:
                preprocessor = TrainOnlyPreprocessor.load(pa_path)
            if not getattr(preprocessor, "is_fitted_", getattr(preprocessor, "is_fitted", False)):
                errors.append(f"Preprocessor artifact at {pa_path} is not fitted.")
        except Exception as exc:
            errors.append(f"Failed to load/verify preprocessor artifact at {pa_path}: {exc}")

    if ma_path.exists() and mm_path.exists():
        try:
            actual_ma_sha = _sha256_file(ma_path)
            hashes["model_artifact_sha256"] = actual_ma_sha
            RandomForestModel.load_verified(
                model_path=ma_path,
                manifest_path=mm_path,
                expected_dataset_sha256=(split_manifest or {}).get("dataset_sha256"),
                expected_split_manifest_sha256=hashes.get("split_manifest_sha256"),
                expected_preprocessor_artifact_sha256=hashes.get("preprocessor_artifact_sha256"),
            )
        except Exception as exc:
            errors.append(f"Failed verified model load for {ma_path}: {exc}")

    ready = len(missing) == 0 and len(errors) == 0
    status_str = "READY" if ready else "BLOCKED"

    status = TestEvaluationPrerequisiteStatus(
        ready=ready,
        status=status_str,
        missing_artifacts=missing,
        verification_errors=errors,
        verified_hashes=hashes,
        expected_test_rows=expected_test_rows,
        expected_benign_rows=expected_benign_rows,
        expected_attack_rows=expected_attack_rows,
        expected_attack_distribution=expected_attack_dist,
        train_validation_disjoint_verified=disjoint_verified,
        partition_verification_status=partition_status,
    )

    if fail_closed and not ready:
        if missing:
            raise FileNotFoundError(
                f"Test evaluation blocked (fail-closed): missing required artifacts: {missing}. "
                f"Verification errors: {errors}"
            )
        raise ValueError(
            f"Test evaluation blocked (fail-closed): integrity verification failed: {errors}"
        )

    return status


def stream_test_partition_data(
    dataset_csv_path: Union[str, Path] = DEFAULT_DATASET_CSV_PATH,
    test_indices_path: Union[str, Path] = DEFAULT_TEST_INDICES_PATH,
    train_indices_path: Union[str, Path, None] = DEFAULT_TRAIN_INDICES_PATH,
    val_indices_path: Union[str, Path, None] = DEFAULT_VAL_INDICES_PATH,
    chunksize: int = 100_000,
    include_trace_metadata: bool = True,
) -> TestPartitionData:
    """Stream raw dataset CSV and extract exact rows belonging to the test partition."""
    ds_path = Path(dataset_csv_path)
    if not ds_path.exists():
        raise FileNotFoundError(f"Dataset CSV not found at {ds_path}")

    test_indices = _load_indices_csv_gz(test_indices_path)
    test_set = set(int(i) for i in test_indices)

    if train_indices_path is not None and Path(train_indices_path).exists():
        train_indices = _load_indices_csv_gz(train_indices_path)
        overlap = test_set & set(int(i) for i in train_indices)
        if overlap:
            raise ValueError(
                f"Data leakage error: Test indices overlap with Train indices ({len(overlap)} rows)"
            )

    if val_indices_path is not None and Path(val_indices_path).exists():
        val_indices = _load_indices_csv_gz(val_indices_path)
        overlap = test_set & set(int(i) for i in val_indices)
        if overlap:
            raise ValueError(
                f"Data leakage error: Test indices overlap with Validation indices "
                f"({len(overlap)} rows)"
            )

    if (
        train_indices_path is not None
        and Path(train_indices_path).exists()
        and val_indices_path is not None
        and Path(val_indices_path).exists()
    ):
        train_indices = _load_indices_csv_gz(train_indices_path)
        val_indices = _load_indices_csv_gz(val_indices_path)
        overlap_tv = set(int(i) for i in train_indices) & set(int(i) for i in val_indices)
        if overlap_tv:
            raise ValueError(
                f"Data leakage error: Train indices overlap with Validation indices "
                f"({len(overlap_tv)} rows)"
            )

    required_cols = list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS)
    feature_chunks: List[pd.DataFrame] = []
    target_chunks: List[pd.DataFrame] = []
    trace_chunks: List[pd.DataFrame] = []

    current_row_offset = 0
    matched_indices_set: set[int] = set()

    for chunk in pd.read_csv(ds_path, chunksize=chunksize, low_memory=False):
        if current_row_offset == 0:
            missing_cols = [c for c in required_cols if c not in chunk.columns]
            if missing_cols:
                raise ValueError(
                    f"Dataset CSV at {ds_path} is missing required columns: {missing_cols}"
                )

        chunk_len = len(chunk)
        chunk_row_ids = np.arange(
            current_row_offset, current_row_offset + chunk_len, dtype=np.int64
        )
        current_row_offset += chunk_len

        mask = np.isin(chunk_row_ids, test_indices)
        if not np.any(mask):
            continue

        selected_ids = chunk_row_ids[mask]
        matched_indices_set.update(int(x) for x in selected_ids)

        sub_chunk = chunk.iloc[np.flatnonzero(mask)].copy()
        sub_chunk.index = pd.Index(selected_ids, name="row_index")

        f_chunk = sub_chunk[list(ML_FEATURE_COLUMNS)].copy()
        validate_feature_selection(list(f_chunk.columns))
        feature_chunks.append(f_chunk)

        t_chunk = sub_chunk[list(TARGET_COLUMNS)].copy()
        target_chunks.append(t_chunk)

        if include_trace_metadata:
            trace_present = [c for c in TRACE_METADATA_COLUMNS if c in sub_chunk.columns]
            if trace_present:
                trace_chunks.append(sub_chunk[trace_present].copy())

    if len(matched_indices_set) != len(test_indices):
        missing_count = len(test_indices) - len(matched_indices_set)
        raise ValueError(
            f"Failed to match all test indices in {ds_path}: missing {missing_count} rows. "
            f"Dataset may be truncated or modified."
        )

    all_features = pd.concat(feature_chunks, axis=0)
    all_targets = pd.concat(target_chunks, axis=0)
    all_trace = pd.concat(trace_chunks, axis=0) if trace_chunks else None

    # Reorder strictly by original test_indices order
    all_features = all_features.loc[test_indices].reset_index(drop=True)
    all_targets = all_targets.loc[test_indices].reset_index(drop=True)
    if all_trace is not None:
        all_trace = all_trace.loc[test_indices].reset_index(drop=True)

    raw_labels = all_targets["Label"].tolist()
    validated_labels: List[int] = []
    for idx_pos, lbl_val in enumerate(raw_labels):
        if lbl_val is None or isinstance(lbl_val, (bool, np.bool_)):
            raise ValueError(
                f"Invalid Label value at test position {idx_pos}: {lbl_val!r} "
                f"(None/bool not allowed)"
            )
        if isinstance(lbl_val, (float, np.floating)):
            if not np.isfinite(lbl_val) or not float(lbl_val).is_integer():
                raise ValueError(
                    f"Invalid fractional or non-finite Label value at test position {idx_pos}: "
                    f"{lbl_val!r} (strict binary integer labels 0/1 required)"
                )
            int_lbl = int(lbl_val)
        elif isinstance(lbl_val, (int, np.integer)):
            int_lbl = int(lbl_val)
        else:
            raise ValueError(
                f"Invalid Label type at test position {idx_pos}: {lbl_val!r} "
                f"(strict binary integer labels 0/1 required)"
            )
        if int_lbl not in (0, 1):
            raise ValueError(
                f"Out-of-domain Label value at test position {idx_pos}: {int_lbl} "
                f"(expected 0 or 1)"
            )
        validated_labels.append(int_lbl)

    y_test = np.asarray(validated_labels, dtype=np.int64)
    attack_cats = all_targets["Attack"].to_numpy(dtype=object)
    for idx_pos, (int_lbl, cat_val) in enumerate(zip(validated_labels, attack_cats)):
        if cat_val is None or not isinstance(cat_val, str) or not cat_val.strip():
            raise ValueError(f"Invalid Attack category at test position {idx_pos}: {cat_val!r}")
        cat_clean = cat_val.strip()
        if int_lbl == 0 and cat_clean != "Benign":
            raise ValueError(
                f"Contradictory ground truth at test position {idx_pos}: "
                f"Label=0 but Attack={cat_clean!r} (expected 'Benign')"
            )
        if int_lbl == 1 and cat_clean == "Benign":
            raise ValueError(
                f"Contradictory ground truth at test position {idx_pos}: "
                f"Label=1 but Attack='Benign' (expected non-Benign attack category)"
            )

    return TestPartitionData(
        X_test_raw=all_features,
        y_test=y_test,
        attack_categories=attack_cats,
        row_indices=test_indices,
        trace_metadata=all_trace,
    )


def save_confusion_matrix_artifacts(
    cm: Sequence[Sequence[int]],
    output_csv_path: Union[str, Path],
    output_png_path: Union[str, Path],
    classes: Sequence[str] = ("Benign (0)", "Attack (1)"),
    title: str = "Random Forest Held-Out Test Confusion Matrix",
) -> Tuple[str, str]:
    """Save confusion matrix as CSV and publication-ready PNG."""
    csv_p = Path(output_csv_path)
    png_p = Path(output_png_path)
    csv_p.parent.mkdir(parents=True, exist_ok=True)
    png_p.parent.mkdir(parents=True, exist_ok=True)

    try:
        cm_arr = np.asarray(cm, dtype=np.int64)
    except Exception as exc:
        raise ValueError(f"Confusion matrix must be convertible to 2D int64 array: {exc}") from exc

    if cm_arr.ndim != 2 or cm_arr.shape != (2, 2):
        raise ValueError(f"Binary confusion matrix must have shape (2, 2), got {cm_arr.shape}")
    if np.any(cm_arr < 0):
        raise ValueError(f"Confusion matrix counts must be non-negative, got {cm_arr.tolist()}")
    if len(classes) != 2:
        raise ValueError(f"Expected 2 class labels for binary confusion matrix, got {classes!r}")

    cm_df = pd.DataFrame(
        cm_arr,
        index=[f"True_{c}" for c in classes],
        columns=[f"Pred_{c}" for c in classes],
    )
    cm_df.to_csv(csv_p, index=True)
    csv_sha = _sha256_file(csv_p)

    cell_tags = [["TN", "FP"], ["FN", "TP"]]
    fig = None
    try:
        fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
        im = ax.imshow(cm_arr, interpolation="nearest", cmap="Blues")
        ax.figure.colorbar(im, ax=ax)

        ax.set(
            xticks=np.arange(cm_arr.shape[1]),
            yticks=np.arange(cm_arr.shape[0]),
            xticklabels=list(classes),
            yticklabels=list(classes),
            title=title,
            ylabel="True Label",
            xlabel="Predicted Label",
        )
        plt.setp(ax.get_xticklabels(), rotation=0, ha="center")

        thresh = cm_arr.max() / 2.0 if cm_arr.max() > 0 else 0.5
        for i in range(cm_arr.shape[0]):
            row_sum = int(cm_arr[i, :].sum())
            for j in range(cm_arr.shape[1]):
                val = int(cm_arr[i, j])
                row_pct = (100.0 * val / row_sum) if row_sum > 0 else 0.0
                color = "white" if val > thresh else "black"
                tag = cell_tags[i][j]
                ax.text(
                    j,
                    i,
                    f"{tag}: {val:,}\n({row_pct:.2f}%)",
                    ha="center",
                    va="center",
                    color=color,
                    fontsize=10,
                    fontweight="bold",
                )

        fig.tight_layout()
        fig.savefig(png_p, bbox_inches="tight")
    except Exception as exc:
        raise RuntimeError(f"Failed to render confusion matrix PNG to {png_p}: {exc}") from exc
    finally:
        if fig is not None:
            plt.close(fig)

    if not png_p.exists() or png_p.stat().st_size == 0:
        raise RuntimeError(f"Confusion matrix PNG was not written or is empty: {png_p}")
    png_bytes = png_p.read_bytes()
    if not png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError(
            f"Generated confusion matrix file does not have a valid PNG header: {png_p}"
        )

    png_sha = _sha256_file(png_p)
    return csv_sha, png_sha


def save_predictions_csv(
    path: Union[str, Path],
    row_indices: Sequence[int],
    y_true: Sequence[int],
    y_pred: Sequence[int],
    prob_benign: Sequence[float],
    prob_attack: Sequence[float],
    attack_categories: Sequence[str],
) -> str:
    """Save test predictions CSV with row indices, probabilities, and attack categories."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    idx_arr = np.asarray(row_indices)
    if idx_arr.ndim != 1 or len(idx_arr) == 0:
        raise ValueError("row_indices must be a non-empty 1D sequence")
    if idx_arr.dtype == bool or not np.issubdtype(idx_arr.dtype, np.integer):
        raise ValueError(f"row_indices must have integer dtype, got {idx_arr.dtype}")
    if np.any(idx_arr < 0):
        raise ValueError("row_indices must be non-negative")
    if len(np.unique(idx_arr)) != len(idx_arr):
        raise ValueError("row_indices must not contain duplicate row identifiers")

    n_rows = len(idx_arr)
    if (
        len(y_true) != n_rows
        or len(y_pred) != n_rows
        or len(prob_benign) != n_rows
        or len(prob_attack) != n_rows
        or len(attack_categories) != n_rows
    ):
        raise ValueError("All prediction columns must have identical length matching row_indices")

    for seq_name, seq_vals in [("y_true", y_true), ("y_pred", y_pred)]:
        for pos, v in enumerate(seq_vals):
            if (
                isinstance(v, (bool, np.bool_))
                or not isinstance(v, (int, np.integer))
                or int(v) not in (0, 1)
            ):
                raise ValueError(
                    f"Invalid binary integer label in {seq_name} at index {pos}: {v!r}"
                )

    y_t = np.asarray(y_true, dtype=np.int64)
    y_p = np.asarray(y_pred, dtype=np.int64)
    p_ben = np.asarray(prob_benign, dtype=np.float64)
    p_att = np.asarray(prob_attack, dtype=np.float64)

    if not (np.all(np.isfinite(p_ben)) and np.all(np.isfinite(p_att))):
        raise ValueError("Predicted probabilities must be finite floats")
    if (
        np.any(p_ben < -1e-6)
        or np.any(p_ben > 1.0 + 1e-6)
        or np.any(p_att < -1e-6)
        or np.any(p_att > 1.0 + 1e-6)
    ):
        raise ValueError("Predicted probabilities must lie within [0.0, 1.0]")
    if not np.allclose(p_ben + p_att, 1.0, atol=1e-5):
        raise ValueError("prob_benign + prob_attack must sum to 1.0 for every sample")

    outcomes = []
    for yt, yp in zip(y_t, y_p):
        if yt == 0 and yp == 0:
            outcomes.append("TN")
        elif yt == 0 and yp == 1:
            outcomes.append("FP")
        elif yt == 1 and yp == 0:
            outcomes.append("FN")
        else:
            outcomes.append("TP")

    df = pd.DataFrame(
        {
            "row_index": idx_arr.astype(np.int64),
            "y_true": y_t,
            "y_pred": y_p,
            "prob_benign": p_ben,
            "prob_attack": p_att,
            "attack_category": np.asarray(attack_categories, dtype=object),
            "outcome": outcomes,
        }
    )
    df.to_csv(p, index=False)
    return _sha256_file(p)


def evaluate_loaded_random_forest_on_test(
    model: RandomForestModel,
    preprocessor: TrainOnlyPreprocessor,
    test_data: TestPartitionData,
    output_dir: Union[str, Path] = DEFAULT_EVALUATION_OUTPUT_DIR,
    run_id: Optional[str] = None,
    provenance_hashes: Optional[Dict[str, str]] = None,
    allow_overwrite: bool = False,
    disjoint_verified: bool = False,
) -> Dict[str, Any]:
    """Execute evaluation on a loaded RandomForestModel and TrainOnlyPreprocessor."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp_utc = datetime.now(timezone.utc).isoformat()
    effective_run_id = (
        run_id or f"rf-test-eval-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    )

    metrics_json_path = out_dir / "test_metrics.json"
    legacy_metrics_json_path = out_dir / "metrics.json"
    cm_csv_path = out_dir / "confusion_matrix.csv"
    cm_png_path = out_dir / "confusion_matrix.png"
    preds_csv_path = out_dir / "test_predictions.csv"
    legacy_preds_csv_path = out_dir / "predictions.csv"
    metadata_json_path = out_dir / "evaluation_metadata.json"

    if not allow_overwrite:
        for p in [
            metrics_json_path,
            legacy_metrics_json_path,
            cm_csv_path,
            cm_png_path,
            preds_csv_path,
            legacy_preds_csv_path,
            metadata_json_path,
        ]:
            if p.exists():
                raise FileExistsError(
                    f"Evaluation artifact already exists at {p}. "
                    f"Use allow_overwrite=True or a separate output directory."
                )

    # 0. Validate test_data invariants (feature schema, row_indices, y_test, model classes_)
    validate_feature_selection(list(test_data.X_test_raw.columns))
    if list(test_data.X_test_raw.columns) != list(ML_FEATURE_COLUMNS):
        raise ValueError(
            "test_data.X_test_raw columns must match canonical ML_FEATURE_COLUMNS order"
        )

    for idx_pos, val in enumerate(test_data.y_test):
        if isinstance(val, (bool, np.bool_)) or isinstance(val, (float, np.floating)):
            raise ValueError(
                f"Invalid non-integer label in test_data.y_test at index {idx_pos}: {val!r}"
            )
        if not isinstance(val, (int, np.integer)) or int(val) not in (0, 1):
            raise ValueError(
                f"Invalid binary label in test_data.y_test at index {idx_pos}: {val!r}"
            )

    est = getattr(model, "estimator", getattr(model, "_estimator", None))
    model_classes = getattr(model, "classes_", getattr(est, "classes_", None))
    if model_classes is not None:
        classes_list = [int(c) if isinstance(c, (int, np.integer)) else c for c in model_classes]
        if classes_list != [0, 1]:
            raise ValueError(
                f"Model classes_ must follow canonical binary ordering [0, 1], "
                f"got {classes_list!r}"
            )

    # 1. Transform features with train-only preprocessor
    X_test_trans = preprocessor.transform(test_data.X_test_raw)

    # 2. Predict probabilities and binary decisions
    probas = np.asarray(model.predict_proba(X_test_trans), dtype=np.float64)
    if probas.ndim != 2 or probas.shape != (test_data.num_rows, 2):
        raise ValueError(
            f"predict_proba output must have shape ({test_data.num_rows}, 2), "
            f"got {probas.shape}"
        )
    if not np.all(np.isfinite(probas)):
        raise ValueError("predict_proba output contains non-finite values (NaN or Inf)")
    if np.any(probas < -1e-6) or np.any(probas > 1.0 + 1e-6):
        raise ValueError(
            f"predict_proba output contains values outside [0.0, 1.0]: "
            f"min={probas.min()}, max={probas.max()}"
        )
    if not np.allclose(probas.sum(axis=1), 1.0, atol=1e-5):
        raise ValueError("predict_proba row probabilities do not sum to 1.0")

    prob_benign = probas[:, 0]
    prob_attack = probas[:, 1]
    # Locked canonical threshold = 0.5; tie at prob_attack == 0.5 resolves to positive class 1
    y_pred = (prob_attack >= CANONICAL_DECISION_THRESHOLD).astype(np.int64)
    y_true = np.asarray(test_data.y_test, dtype=np.int64)
    attack_cats = [str(c) for c in test_data.attack_categories]

    # 3. Compute metrics and breakdowns
    overall_metrics = compute_metrics(y_true=y_true, y_pred=y_pred, labels=[0, 1])
    cm_breakdown = compute_confusion_matrix_breakdown(y_true=y_true, y_pred=y_pred, labels=[0, 1])
    benign_breakdown = compute_benign_false_positive_breakdown(
        y_true=y_true, y_pred=y_pred, attack_categories=attack_cats
    )
    attack_breakdown = compute_attack_category_breakdown(
        y_true=y_true, y_pred=y_pred, attack_categories=attack_cats
    )

    # 4. Save artifacts
    cm_csv_sha, cm_png_sha = save_confusion_matrix_artifacts(
        cm=cm_breakdown["confusion_matrix"],
        output_csv_path=cm_csv_path,
        output_png_path=cm_png_path,
        classes=("Benign (0)", "Attack (1)"),
        title=f"RF Held-Out Test Confusion Matrix ({effective_run_id})",
    )

    preds_csv_sha = save_predictions_csv(
        path=preds_csv_path,
        row_indices=test_data.row_indices,
        y_true=y_true,
        y_pred=y_pred,
        prob_benign=prob_benign,
        prob_attack=prob_attack,
        attack_categories=attack_cats,
    )
    save_predictions_csv(
        path=legacy_preds_csv_path,
        row_indices=test_data.row_indices,
        y_true=y_true,
        y_pred=y_pred,
        prob_benign=prob_benign,
        prob_attack=prob_attack,
        attack_categories=attack_cats,
    )

    prov = dict(provenance_hashes) if provenance_hashes else {}
    metadata_payload: Dict[str, Any] = {
        "run_id": effective_run_id,
        "timestamp_utc": timestamp_utc,
        "issue_references": ["Issue #12", "Issue #13"],
        "evaluation_stage": "held_out_test_evaluation",
        "partition": "test",
        "model_type": model.model_type,
        "task": model.task,
        "target_column": model.target,
        "positive_class": model.positive_class,
        "configuration_id": model.config.configuration_id,
        "is_canonical_baseline": model.config.is_canonical_baseline,
        "protocol_version": (
            model.protocol.protocol_version if model.protocol is not None else PROTOCOL_IDENTIFIER
        ),
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "split_protocol_id": SPLIT_PROTOCOL_ID,
        "preprocessing_contract_id": PREPROCESSING_CONTRACT_ID,
        "feature_count": len(model.feature_names),
        "selected_features": list(model.feature_names),
        "hyperparameters": model.config.to_dict(),
        "decision_threshold": CANONICAL_DECISION_THRESHOLD,
        "test_row_count": int(test_data.num_rows),
        "benign_row_count": int(cm_breakdown["benign_total"]),
        "attack_row_count": int(cm_breakdown["attack_total"]),
        "partition_verification_status": "VERIFIED" if disjoint_verified else "UNVERIFIED",
        "test_lock_compliance": {
            "model_retrained_on_test": False,
            "preprocessor_refitted_on_test": False,
            "hyperparameters_tuned_on_test": False,
            "threshold_tuned_on_test": False,
            "train_validation_disjoint_verified": bool(disjoint_verified),
        },
        "provenance_hashes": prov,
        "generated_artifacts": {
            "metrics_json": {
                "path": metrics_json_path.as_posix(),
                "sha256": None,  # populated below
            },
            "confusion_matrix_csv": {
                "path": cm_csv_path.as_posix(),
                "sha256": cm_csv_sha,
            },
            "confusion_matrix_png": {
                "path": cm_png_path.as_posix(),
                "sha256": cm_png_sha,
            },
            "predictions_csv": {
                "path": preds_csv_path.as_posix(),
                "sha256": preds_csv_sha,
            },
        },
        "environment": {
            "git_commit": _resolve_git_commit(),
            "python_version": sys.version.split()[0],
        },
    }

    metrics_payload: Dict[str, Any] = {
        "run_id": effective_run_id,
        "timestamp_utc": timestamp_utc,
        "partition": "test",
        "sample_count": int(test_data.num_rows),
        "decision_threshold": CANONICAL_DECISION_THRESHOLD,
        "overall_metrics": overall_metrics,
        "confusion_matrix_breakdown": cm_breakdown,
        "benign_traffic_breakdown": benign_breakdown,
        "per_attack_category_breakdown": attack_breakdown,
    }

    with metrics_json_path.open("w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)
    with legacy_metrics_json_path.open("w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)
    metrics_json_sha = _sha256_file(metrics_json_path)

    metadata_payload["generated_artifacts"]["metrics_json"]["sha256"] = metrics_json_sha

    with metadata_json_path.open("w", encoding="utf-8") as f:
        json.dump(metadata_payload, f, indent=2)
    metadata_json_sha = _sha256_file(metadata_json_path)

    return {
        "run_id": effective_run_id,
        "output_dir": str(out_dir),
        "metrics": metrics_payload,
        "metadata": metadata_payload,
        "artifacts": {
            "metrics_json": {"path": str(metrics_json_path), "sha256": metrics_json_sha},
            "confusion_matrix_csv": {"path": str(cm_csv_path), "sha256": cm_csv_sha},
            "confusion_matrix_png": {"path": str(cm_png_path), "sha256": cm_png_sha},
            "predictions_csv": {"path": str(preds_csv_path), "sha256": preds_csv_sha},
            "metadata_json": {"path": str(metadata_json_path), "sha256": metadata_json_sha},
        },
        "X_test_transformed": X_test_trans,
        "y_true": y_true,
        "y_pred": y_pred,
        "prob_benign": prob_benign,
        "prob_attack": prob_attack,
        "attack_categories": attack_cats,
        "row_indices": test_data.row_indices,
    }


def evaluate_random_forest_on_test(
    dataset_csv_path: Union[str, Path] = DEFAULT_DATASET_CSV_PATH,
    split_manifest_path: Union[str, Path] = DEFAULT_SPLIT_MANIFEST_PATH,
    test_indices_path: Union[str, Path] = DEFAULT_TEST_INDICES_PATH,
    train_indices_path: Union[str, Path, None] = DEFAULT_TRAIN_INDICES_PATH,
    val_indices_path: Union[str, Path, None] = DEFAULT_VAL_INDICES_PATH,
    preprocessing_manifest_path: Union[str, Path] = DEFAULT_PREPROCESSING_MANIFEST_PATH,
    preprocessor_artifact_path: Union[str, Path] = DEFAULT_PREPROCESSOR_ARTIFACT_PATH,
    model_manifest_path: Union[str, Path] = DEFAULT_MODEL_MANIFEST_PATH,
    model_artifact_path: Union[str, Path] = DEFAULT_MODEL_ARTIFACT_PATH,
    output_dir: Union[str, Path] = DEFAULT_EVALUATION_OUTPUT_DIR,
    run_id: Optional[str] = None,
    allow_overwrite: bool = False,
    include_trace_metadata: bool = False,
) -> Dict[str, Any]:
    """End-to-end entrypoint: verify prerequisites fail-closed, load artifacts, and evaluate."""
    # 1. Fail-closed prerequisite check
    prereq = check_test_evaluation_prerequisites(
        dataset_csv_path=dataset_csv_path,
        split_manifest_path=split_manifest_path,
        test_indices_path=test_indices_path,
        train_indices_path=train_indices_path,
        val_indices_path=val_indices_path,
        preprocessing_manifest_path=preprocessing_manifest_path,
        preprocessor_artifact_path=preprocessor_artifact_path,
        model_manifest_path=model_manifest_path,
        model_artifact_path=model_artifact_path,
        verify_dataset_hash=True,
        fail_closed=True,
    )

    # 2. Load split manifest and verified preprocessor
    split_manifest: Dict[str, Any] = {}
    if Path(split_manifest_path).exists():
        with open(split_manifest_path, "r", encoding="utf-8") as f:
            split_manifest = json.load(f)

    expected_ds_sha = split_manifest.get("dataset_sha256")
    if Path(preprocessing_manifest_path).exists():
        load_kwargs: Dict[str, Any] = {
            "artifact_path": preprocessor_artifact_path,
            "manifest_path": preprocessing_manifest_path,
        }
        if isinstance(expected_ds_sha, str) and expected_ds_sha:
            load_kwargs["expected_dataset_sha256"] = expected_ds_sha
        preprocessor = TrainOnlyPreprocessor.load_verified(**load_kwargs)
    else:
        preprocessor = TrainOnlyPreprocessor.load(preprocessor_artifact_path)

    # 3. Load model with verified provenance check
    loaded_res = RandomForestModel.load_verified(
        model_path=model_artifact_path,
        manifest_path=model_manifest_path,
        expected_dataset_sha256=expected_ds_sha,
        expected_split_manifest_sha256=prereq.verified_hashes.get("split_manifest_sha256"),
        expected_preprocessor_artifact_sha256=prereq.verified_hashes.get(
            "preprocessor_artifact_sha256"
        ),
    )
    model = loaded_res[0] if isinstance(loaded_res, tuple) else loaded_res

    # 4. Stream and extract test partition rows
    test_data = stream_test_partition_data(
        dataset_csv_path=dataset_csv_path,
        test_indices_path=test_indices_path,
        train_indices_path=train_indices_path,
        val_indices_path=val_indices_path,
        include_trace_metadata=include_trace_metadata,
    )

    # 5. Evaluate and emit artifacts
    return evaluate_loaded_random_forest_on_test(
        model=model,
        preprocessor=preprocessor,
        test_data=test_data,
        output_dir=output_dir,
        run_id=run_id,
        provenance_hashes=prereq.verified_hashes,
        allow_overwrite=allow_overwrite,
        disjoint_verified=prereq.train_validation_disjoint_verified,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for Random Forest held-out test evaluation."""
    parser = argparse.ArgumentParser(
        description="Run fail-closed held-out Test evaluation for Random Forest (Issue #12)."
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Check and print prerequisite status without evaluating or writing output files",
    )
    parser.add_argument(
        "--dataset-csv",
        type=Path,
        default=DEFAULT_DATASET_CSV_PATH,
        help="Path to NF-UNSW-NB15-v3.csv",
    )
    parser.add_argument(
        "--split-manifest",
        type=Path,
        default=DEFAULT_SPLIT_MANIFEST_PATH,
        help="Path to split manifest JSON",
    )
    parser.add_argument(
        "--test-indices",
        type=Path,
        default=DEFAULT_TEST_INDICES_PATH,
        help="Path to test_indices.csv.gz",
    )
    parser.add_argument(
        "--train-indices",
        type=Path,
        default=DEFAULT_TRAIN_INDICES_PATH,
        help="Path to train_indices.csv.gz",
    )
    parser.add_argument(
        "--val-indices",
        type=Path,
        default=DEFAULT_VAL_INDICES_PATH,
        help="Path to validation_indices.csv.gz",
    )
    parser.add_argument(
        "--preprocessor-artifact",
        type=Path,
        default=DEFAULT_PREPROCESSOR_ARTIFACT_PATH,
        help="Path to fitted TrainOnlyPreprocessor joblib artifact",
    )
    parser.add_argument(
        "--model-manifest",
        type=Path,
        default=DEFAULT_MODEL_MANIFEST_PATH,
        help="Path to Random Forest training manifest JSON",
    )
    parser.add_argument(
        "--model-artifact",
        type=Path,
        default=DEFAULT_MODEL_ARTIFACT_PATH,
        help="Path to trained Random Forest model joblib artifact",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_EVALUATION_OUTPUT_DIR,
        help="Directory to write evaluation artifacts",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Optional explicit run identifier",
    )
    parser.add_argument(
        "--allow-overwrite",
        action="store_true",
        help="Allow overwriting existing evaluation artifacts in output-dir",
    )
    args = parser.parse_args(argv)

    status = check_test_evaluation_prerequisites(
        dataset_csv_path=args.dataset_csv,
        split_manifest_path=args.split_manifest,
        test_indices_path=args.test_indices,
        train_indices_path=args.train_indices,
        val_indices_path=args.val_indices,
        preprocessor_artifact_path=args.preprocessor_artifact,
        model_manifest_path=args.model_manifest,
        model_artifact_path=args.model_artifact,
        fail_closed=False,
    )

    if args.verify_only:
        print(json.dumps(status.to_dict(), indent=2))
        return 0 if status.ready else 2

    if not status.ready:
        print(json.dumps(status.to_dict(), indent=2), file=sys.stderr)
        return 2

    result = evaluate_random_forest_on_test(
        dataset_csv_path=args.dataset_csv,
        split_manifest_path=args.split_manifest,
        test_indices_path=args.test_indices,
        train_indices_path=args.train_indices,
        val_indices_path=args.val_indices,
        preprocessor_artifact_path=args.preprocessor_artifact,
        model_manifest_path=args.model_manifest,
        model_artifact_path=args.model_artifact,
        output_dir=args.output_dir,
        run_id=args.run_id,
        allow_overwrite=args.allow_overwrite,
    )
    print(
        json.dumps(
            {
                "status": "COMPLETED",
                "run_id": result["run_id"],
                "output_dir": result["output_dir"],
                "overall_metrics": result["metrics"]["overall_metrics"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
