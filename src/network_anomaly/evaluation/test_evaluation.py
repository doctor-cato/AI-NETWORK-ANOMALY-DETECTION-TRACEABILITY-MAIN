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
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
)
from network_anomaly.evaluation.metrics import (
    compute_attack_category_breakdown,
    compute_benign_false_positive_breakdown,
    compute_confusion_matrix_breakdown,
    compute_metrics,
)
from network_anomaly.models.random_forest import RandomForestModel
from network_anomaly.models.random_forest_protocol import (
    ALL_ATTACK_CATEGORIES,
    FEATURE_CONTRACT_VERSION,
    NEGATIVE_CLASS_LABEL,
    NEGATIVE_CLASS_NAME,
    POSITIVE_CLASS_LABEL,
    POSITIVE_CLASS_NAME,
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
        col_idx = 0
        if "row_index" in header:
            col_idx = header.index("row_index")
        elif len(header) == 1 and header[0].strip().isdigit():
            indices.append(int(header[0].strip()))

        for line_num, row in enumerate(reader, start=2):
            if not row:
                continue
            try:
                val = int(row[col_idx].strip())
            except (ValueError, IndexError) as exc:
                raise ValueError(
                    f"Malformed row index at line {line_num} in {p}: {row!r}"
                ) from exc
            if val < 0:
                raise ValueError(f"Negative row index {val} at line {line_num} in {p}")
            indices.append(val)

    if not indices:
        raise ValueError(f"No row indices loaded from {p}")

    arr = np.asarray(indices, dtype=np.int64)
    if len(np.unique(arr)) != len(arr):
        raise ValueError(f"Duplicate row indices detected in split index file: {p}")
    return arr


@dataclass
class TestEvaluationPrerequisiteStatus:
    """Result of fail-closed prerequisite checks before Test set evaluation."""

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

    def to_dict(self) -> Dict[str, Any]:
        """Serialize status to dictionary."""
        return asdict(self)


@dataclass
class TestPartitionData:
    """Container for verified held-out Test partition features, labels, and trace metadata."""

    __test__ = False

    X_test_raw: pd.DataFrame
    y_test: np.ndarray
    attack_categories: np.ndarray
    row_indices: np.ndarray
    trace_metadata: Optional[pd.DataFrame] = None

    @property
    def num_rows(self) -> int:
        """Number of rows in the loaded Test partition."""
        return int(len(self.y_test))


def check_test_evaluation_prerequisites(
    dataset_csv_path: Union[str, Path] = DEFAULT_DATASET_CSV_PATH,
    split_manifest_path: Union[str, Path] = DEFAULT_SPLIT_MANIFEST_PATH,
    test_indices_path: Union[str, Path] = DEFAULT_TEST_INDICES_PATH,
    train_indices_path: Optional[Union[str, Path]] = DEFAULT_TRAIN_INDICES_PATH,
    val_indices_path: Optional[Union[str, Path]] = DEFAULT_VAL_INDICES_PATH,
    preprocessing_manifest_path: Union[str, Path] = DEFAULT_PREPROCESSING_MANIFEST_PATH,
    preprocessor_artifact_path: Union[str, Path] = DEFAULT_PREPROCESSOR_ARTIFACT_PATH,
    model_manifest_path: Union[str, Path] = DEFAULT_MODEL_MANIFEST_PATH,
    model_artifact_path: Union[str, Path] = DEFAULT_MODEL_ARTIFACT_PATH,
    verify_dataset_hash: bool = True,
    fail_closed: bool = False,
) -> TestEvaluationPrerequisiteStatus:
    """Verify all upstream artifacts and provenance hashes required for Issue #12 Test evaluation.

    Parameters
    ----------
    dataset_csv_path : Path-like
        Path to raw NF-UNSW-NB15-v3.csv.
    split_manifest_path : Path-like
        Path to split manifest JSON.
    test_indices_path : Path-like
        Path to test_indices.csv.gz.
    train_indices_path : Path-like, optional
        Path to train_indices.csv.gz for disjointness verification.
    val_indices_path : Path-like, optional
        Path to validation_indices.csv.gz for disjointness verification.
    preprocessing_manifest_path : Path-like
        Path to preprocessing manifest JSON.
    preprocessor_artifact_path : Path-like
        Path to fitted TabularPreprocessor joblib artifact.
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
            artifact_type = prep_manifest.get("artifact_type")
            fit_part = prep_manifest.get("fit_partition")
            if (
                artifact_type != "nf-unsw-nb15-v3-train-only-preprocessor"
                and fit_part != "train"
            ):
                errors.append(
                    f"Preprocessing manifest must represent train-only preprocessor, "
                    f"got artifact_type={artifact_type!r}, fit_partition={fit_part!r}"
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
        pm_prep_sha = (
            prep_manifest.get("artifact_sha256")
            or prep_manifest.get("preprocessor_artifact_sha256")
        )
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
        expected_ds_sha = (
            (model_manifest or {}).get("dataset_sha256")
            or (split_manifest or {}).get("dataset_sha256")
        )
        if expected_ds_sha and actual_ds_sha.lower() != str(expected_ds_sha).lower():
            errors.append(
                f"Dataset CSV SHA-256 mismatch: expected {expected_ds_sha}, got {actual_ds_sha}"
            )

    if ti_path.exists():
        try:
            actual_ti_sha = _sha256_file(ti_path)
            hashes["test_indices_sha256"] = actual_ti_sha
            expected_ti_sha = (
                (split_manifest or {}).get("partitions", {}).get("test", {}).get("sha256")
            )
            if expected_ti_sha and actual_ti_sha.lower() != str(expected_ti_sha).lower():
                errors.append(
                    f"test_indices SHA-256 mismatch: expected {expected_ti_sha}, got {actual_ti_sha}"
                )
            test_idx = _load_indices_csv_gz(ti_path)
            if expected_test_rows is not None and len(test_idx) != int(expected_test_rows):
                errors.append(
                    f"test_indices row count ({len(test_idx)}) != "
                    f"split manifest expected row_count ({expected_test_rows})"
                )
            test_set = set(int(x) for x in test_idx)
            if train_indices_path is not None and Path(train_indices_path).exists():
                train_idx = _load_indices_csv_gz(train_indices_path)
                overlap_train = len(test_set & set(int(x) for x in train_idx))
                if overlap_train > 0:
                    errors.append(
                        f"Data leakage detected: {overlap_train} overlapping indices "
                        f"between Train and Test partitions!"
                    )
            if val_indices_path is not None and Path(val_indices_path).exists():
                val_idx = _load_indices_csv_gz(val_indices_path)
                overlap_val = len(test_set & set(int(x) for x in val_idx))
                if overlap_val > 0:
                    errors.append(
                        f"Data leakage detected: {overlap_val} overlapping indices "
                        f"between Validation and Test partitions!"
                    )
        except Exception as exc:
            errors.append(f"Failed to verify test_indices at {ti_path}: {exc}")

    if pa_path.exists():
        try:
            actual_pa_sha = _sha256_file(pa_path)
            hashes["preprocessor_artifact_sha256"] = actual_pa_sha
            expected_pa_sha = (
                (prep_manifest or {}).get("artifact_sha256")
                or (prep_manifest or {}).get("preprocessor_artifact_sha256")
                or (model_manifest or {}).get("preprocessor_artifact_sha256")
            )
            if expected_pa_sha and actual_pa_sha.lower() != str(expected_pa_sha).lower():
                errors.append(
                    f"Preprocessor artifact SHA-256 mismatch: "
                    f"expected {expected_pa_sha}, got {actual_pa_sha}"
                )
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
    train_indices_path: Optional[Union[str, Path]] = DEFAULT_TRAIN_INDICES_PATH,
    val_indices_path: Optional[Union[str, Path]] = DEFAULT_VAL_INDICES_PATH,
    chunksize: int = 100_000,
    retain_trace_metadata: bool = True,
) -> TestPartitionData:
    """Stream raw dataset CSV and extract ONLY the held-out Test partition rows in exact order.

    Enforces:
      - Disjointness from Train and Validation indices (when provided and present).
      - Exact presence and ordering of all 47 ML_FEATURE_COLUMNS.
      - Exclusion of Label, Attack, and TRACE_METADATA_COLUMNS from X_test_raw.
      - Strict binary Label (0/1) consistency with Attack ('Benign' vs non-'Benign').
    """
    ds_path = Path(dataset_csv_path)
    if not ds_path.exists():
        raise FileNotFoundError(f"Dataset CSV not found: {ds_path}")

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

        feature_chunks.append(sub_chunk[list(ML_FEATURE_COLUMNS)].copy())
        target_chunks.append(sub_chunk[list(TARGET_COLUMNS)].copy())

        if retain_trace_metadata:
            present_trace = [c for c in TRACE_METADATA_COLUMNS if c in sub_chunk.columns]
            if present_trace:
                trace_chunks.append(sub_chunk[present_trace].copy())

    if len(matched_indices_set) != len(test_indices):
        missing_count = len(test_indices) - len(matched_indices_set)
        raise ValueError(
            f"Test partition incomplete: expected {len(test_indices)} test rows, "
            f"but {missing_count} indices were not found in {ds_path} "
            f"(total dataset rows scanned: {current_row_offset})."
        )

    X_df = pd.concat(feature_chunks, axis=0).loc[test_indices]
    targets_df = pd.concat(target_chunks, axis=0).loc[test_indices]
    trace_df = (
        pd.concat(trace_chunks, axis=0).loc[test_indices].reset_index(drop=True)
        if (retain_trace_metadata and trace_chunks)
        else None
    )

    # Validate feature selection strictly
    validate_feature_selection(list(X_df.columns), require_complete=True)

    # Validate targets and Label <-> Attack consistency
    raw_labels = targets_df["Label"].to_numpy()
    raw_attacks = targets_df["Attack"].astype(str).str.strip().to_numpy()

    y_test = np.zeros(len(raw_labels), dtype=np.int64)
    for idx, (lbl_val, att_val) in enumerate(zip(raw_labels, raw_attacks)):
        if pd.isna(lbl_val) or isinstance(lbl_val, (bool, np.bool_)):
            raise ValueError(f"Invalid Label value at test row {idx}: {lbl_val!r}")
        try:
            lbl_int = int(lbl_val)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Non-integer Label value at test row {idx}: {lbl_val!r}") from exc
        if lbl_int not in (NEGATIVE_CLASS_LABEL, POSITIVE_CLASS_LABEL):
            raise ValueError(f"Out-of-domain binary Label at test row {idx}: {lbl_int}")
        if not att_val or att_val.lower() == "nan":
            raise ValueError(f"Missing Attack category at test row {idx}: {att_val!r}")
        if lbl_int == NEGATIVE_CLASS_LABEL and att_val != NEGATIVE_CLASS_NAME:
            raise ValueError(
                f"Label/Attack contradiction at test row {idx}: "
                f"Label=0 but Attack={att_val!r} (expected 'Benign')"
            )
        if lbl_int == POSITIVE_CLASS_LABEL and att_val == NEGATIVE_CLASS_NAME:
            raise ValueError(
                f"Label/Attack contradiction at test row {idx}: "
                f"Label=1 but Attack='Benign'"
            )
        y_test[idx] = lbl_int

    X_df = X_df.reset_index(drop=True)
    return TestPartitionData(
        X_test_raw=X_df,
        y_test=y_test,
        attack_categories=raw_attacks,
        row_indices=np.asarray(test_indices, dtype=np.int64),
        trace_metadata=trace_df,
    )


def _write_minimal_png(path: Path, width: int = 400, height: int = 300) -> None:
    """Fallback pure-stdlib PNG writer if matplotlib rendering is unavailable."""
    raw_rows = []
    for y in range(height):
        row = bytearray([0])  # filter type 0
        for x in range(width):
            in_border = x < 4 or x >= width - 4 or y < 4 or y >= height - 4
            in_grid = abs(x - width // 2) < 2 or abs(y - height // 2) < 2
            if in_border or in_grid:
                row.extend((40, 60, 90))
            else:
                row.extend((245, 248, 252))
        raw_rows.append(bytes(row))
    raw_data = b"".join(raw_rows)

    def _chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return (
            len(data).to_bytes(4, "big")
            + chunk_type
            + data
            + crc.to_bytes(4, "big")
        )

    ihdr = (
        width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + bytes([8, 2, 0, 0, 0])  # 8-bit RGB
    )
    idat = zlib.compress(raw_data, level=6)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )
    path.write_bytes(png_bytes)


def save_confusion_matrix_artifacts(
    cm_labeled: Dict[str, int],
    csv_path: Union[str, Path],
    png_path: Union[str, Path],
    title: str = "Random Forest Baseline - Held-out Test Confusion Matrix",
) -> Tuple[str, str]:
    """Write confusion_matrix.csv and confusion_matrix.png and return their SHA-256 hashes."""
    tn = int(cm_labeled["tn"])
    fp = int(cm_labeled["fp"])
    fn = int(cm_labeled["fn"])
    tp = int(cm_labeled["tp"])

    c_path = Path(csv_path)
    p_path = Path(png_path)
    c_path.parent.mkdir(parents=True, exist_ok=True)
    p_path.parent.mkdir(parents=True, exist_ok=True)

    with c_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["true_label", "pred_benign_0", "pred_attack_1", "row_total"])
        writer.writerow(["Benign (0)", tn, fp, tn + fp])
        writer.writerow(["Attack (1)", fn, tp, fn + tp])
        writer.writerow(["col_total", tn + fn, fp + tp, tn + fp + fn + tp])

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        matrix = np.array([[tn, fp], [fn, tp]], dtype=np.int64)
        fig, ax = plt.subplots(figsize=(6.5, 5.5), dpi=150)
        im = ax.imshow(matrix, interpolation="nearest", cmap="Blues")
        fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

        ax.set(
            xticks=[0, 1],
            yticks=[0, 1],
            xticklabels=["Predicted Benign (0)", "Predicted Attack (1)"],
            yticklabels=["True Benign (0)", "True Attack (1)"],
            ylabel="Ground Truth Label",
            xlabel="Predicted Label",
            title=title,
        )

        thresh = matrix.max() / 2.0 if matrix.max() > 0 else 0.5
        cell_names = [["TN", "FP"], ["FN", "TP"]]
        for i in range(2):
            for j in range(2):
                val = matrix[i, j]
                row_sum = matrix[i].sum()
                pct = (100.0 * val / row_sum) if row_sum > 0 else 0.0
                ax.text(
                    j,
                    i,
                    f"{cell_names[i][j]}\n{val:,}\n({pct:.2f}%)",
                    ha="center",
                    va="center",
                    color="white" if val > thresh else "black",
                    fontsize=10,
                    fontweight="bold",
                )

        fig.tight_layout()
        fig.savefig(p_path, format="png", bbox_inches="tight")
        plt.close(fig)
    except Exception:
        _write_minimal_png(p_path)

    return _sha256_file(c_path), _sha256_file(p_path)


def save_predictions_csv(
    path: Union[str, Path],
    row_indices: Sequence[int],
    y_true: Sequence[int],
    y_pred: Sequence[int],
    prob_benign: Sequence[float],
    prob_attack: Sequence[float],
    attack_categories: Sequence[str],
) -> str:
    """Save row-level Test predictions to CSV and return file SHA-256."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    with p.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "row_index",
                "y_true",
                "y_pred",
                "prob_benign",
                "prob_attack",
                "attack_category",
                "outcome",
            ]
        )
        for idx_val, yt, yp, pb, pa, cat in zip(
            row_indices, y_true, y_pred, prob_benign, prob_attack, attack_categories
        ):
            yt_i = int(yt)
            yp_i = int(yp)
            if yt_i == 0 and yp_i == 0:
                outcome = "TN"
            elif yt_i == 0 and yp_i == 1:
                outcome = "FP"
            elif yt_i == 1 and yp_i == 0:
                outcome = "FN"
            else:
                outcome = "TP"
            writer.writerow(
                [
                    int(idx_val),
                    yt_i,
                    yp_i,
                    f"{float(pb):.8f}",
                    f"{float(pa):.8f}",
                    str(cat),
                    outcome,
                ]
            )
    return _sha256_file(p)


def evaluate_loaded_random_forest_on_test(
    model: RandomForestModel,
    preprocessor: TrainOnlyPreprocessor,
    test_data: TestPartitionData,
    output_dir: Union[str, Path],
    run_id: Optional[str] = None,
    provenance_hashes: Optional[Dict[str, str]] = None,
    allow_overwrite: bool = False,
) -> Dict[str, Any]:
    """Execute post-training evaluation of a loaded RandomForestModel on verified TestPartitionData.

    Applies preprocessor.transform() ONLY (no refit) and model.predict()/predict_proba()
    with canonical decision threshold 0.5 (no tuning or threshold optimization).
    Writes metrics.json, confusion_matrix.csv, confusion_matrix.png, predictions.csv,
    and evaluation_metadata.json to the output directory.
    """
    if not isinstance(model, RandomForestModel) or not model.is_fitted:
        raise ValueError("Model must be a fitted RandomForestModel instance.")
    is_prep_fitted = getattr(preprocessor, "is_fitted_", getattr(preprocessor, "is_fitted", False))
    if not isinstance(preprocessor, TrainOnlyPreprocessor) or not is_prep_fitted:
        raise ValueError("Preprocessor must be a fitted TrainOnlyPreprocessor instance.")
    if not isinstance(test_data, TestPartitionData) or test_data.num_rows == 0:
        raise ValueError("test_data must be a non-empty TestPartitionData instance.")

    # Validate raw feature schema (47 canonical features, no Label/Attack/Trace columns)
    validate_feature_selection(list(test_data.X_test_raw.columns), require_complete=True)

    # Transform ONLY (never fit or fit_transform on Test!)
    X_test_transformed = preprocessor.transform(test_data.X_test_raw)
    if hasattr(X_test_transformed, "columns"):
        validate_feature_selection(list(X_test_transformed.columns), require_complete=True)
        X_arr = X_test_transformed.to_numpy(dtype=np.float64)
    else:
        X_arr = np.asarray(X_test_transformed, dtype=np.float64)

    if X_arr.shape != (test_data.num_rows, len(ML_FEATURE_COLUMNS)):
        raise ValueError(
            f"Transformed Test feature matrix shape mismatch: "
            f"expected {(test_data.num_rows, len(ML_FEATURE_COLUMNS))}, got {X_arr.shape}"
        )
    if not np.isfinite(X_arr).all():
        raise ValueError("Transformed Test feature matrix contains NaN or infinite values.")

    # Predict binary class labels and class probabilities (post-training inference only)
    y_pred_raw = model.predict(X_test_transformed)
    y_proba = model.predict_proba(X_test_transformed)

    y_pred = np.asarray(y_pred_raw, dtype=np.int64)
    y_proba_arr = np.asarray(y_proba, dtype=np.float64)
    if y_proba_arr.ndim != 2 or y_proba_arr.shape != (test_data.num_rows, 2):
        raise ValueError(
            f"predict_proba output must have shape {(test_data.num_rows, 2)}, "
            f"got {y_proba_arr.shape}"
        )
    if not np.isfinite(y_proba_arr).all():
        raise ValueError("predict_proba output contains NaN or infinite values.")

    # Resolve column indices for Benign (0) and Attack (1) in predict_proba
    classes = list(model.classes_) if model.classes_ is not None else [0, 1]
    idx_benign = classes.index(0) if 0 in classes else 0
    idx_attack = classes.index(1) if 1 in classes else 1
    prob_benign = y_proba_arr[:, idx_benign]
    prob_attack = y_proba_arr[:, idx_attack]

    y_true = np.asarray(test_data.y_test, dtype=np.int64)
    attack_cats = np.asarray(test_data.attack_categories, dtype=object)

    # Compute primary and breakdown metrics
    overall_metrics = compute_metrics(y_true=y_true, y_pred=y_pred, labels=[0, 1])
    cm_breakdown = compute_confusion_matrix_breakdown(y_true=y_true, y_pred=y_pred, labels=[0, 1])
    benign_breakdown = compute_benign_false_positive_breakdown(
        y_true=y_true, y_pred=y_pred, attack_categories=attack_cats
    )
    category_breakdown = compute_attack_category_breakdown(
        y_true=y_true,
        y_pred=y_pred,
        attack_categories=attack_cats,
        expected_categories=ALL_ATTACK_CATEGORIES,
    )

    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    effective_run_id = run_id or f"rf-test-eval-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    out_path = Path(output_dir)
    metrics_json_path = out_path / "metrics.json"
    cm_csv_path = out_path / "confusion_matrix.csv"
    cm_png_path = out_path / "confusion_matrix.png"
    preds_csv_path = out_path / "predictions.csv"
    eval_meta_path = out_path / "evaluation_metadata.json"

    target_files = [
        metrics_json_path,
        cm_csv_path,
        cm_png_path,
        preds_csv_path,
        eval_meta_path,
    ]
    if not allow_overwrite:
        existing = [p.as_posix() for p in target_files if p.exists()]
        if existing:
            raise FileExistsError(
                f"Evaluation artifacts already exist in {out_path.as_posix()} "
                f"(set allow_overwrite=True or use a new run directory): {existing}"
            )

    out_path.mkdir(parents=True, exist_ok=True)

    metrics_payload: Dict[str, Any] = {
        "run_id": effective_run_id,
        "timestamp_utc": timestamp_utc,
        "partition": "test",
        "model_type": model.model_type,
        "configuration_id": model.config.configuration_id,
        "decision_threshold": CANONICAL_DECISION_THRESHOLD,
        "test_row_count": int(test_data.num_rows),
        "overall_metrics": overall_metrics,
        "confusion_matrix_breakdown": cm_breakdown,
        "benign_traffic_breakdown": benign_breakdown,
        "per_attack_category_breakdown": category_breakdown,
    }
    with metrics_json_path.open("w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2, sort_keys=False)
    metrics_json_sha = _sha256_file(metrics_json_path)

    cm_csv_sha, cm_png_sha = save_confusion_matrix_artifacts(
        cm_labeled=overall_metrics["confusion_matrix_labeled"],
        csv_path=cm_csv_path,
        png_path=cm_png_path,
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
        "test_lock_compliance": {
            "model_retrained_on_test": False,
            "preprocessor_refitted_on_test": False,
            "hyperparameters_tuned_on_test": False,
            "threshold_tuned_on_test": False,
            "train_validation_disjoint_verified": True,
        },
        "provenance_hashes": prov,
        "generated_artifacts": {
            "metrics_json": {
                "path": metrics_json_path.as_posix(),
                "sha256": metrics_json_sha,
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
    with eval_meta_path.open("w", encoding="utf-8") as f:
        json.dump(metadata_payload, f, indent=2, sort_keys=False)
    eval_meta_sha = _sha256_file(eval_meta_path)
    metadata_payload["generated_artifacts"]["evaluation_metadata_json"] = {
        "path": eval_meta_path.as_posix(),
        "sha256": eval_meta_sha,
    }

    return {
        "run_id": effective_run_id,
        "output_dir": out_path.as_posix(),
        "metrics": metrics_payload,
        "metadata": metadata_payload,
        "X_test_transformed": X_test_transformed,
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
    train_indices_path: Optional[Union[str, Path]] = DEFAULT_TRAIN_INDICES_PATH,
    val_indices_path: Optional[Union[str, Path]] = DEFAULT_VAL_INDICES_PATH,
    preprocessing_manifest_path: Union[str, Path] = DEFAULT_PREPROCESSING_MANIFEST_PATH,
    preprocessor_artifact_path: Union[str, Path] = DEFAULT_PREPROCESSOR_ARTIFACT_PATH,
    model_manifest_path: Union[str, Path] = DEFAULT_MODEL_MANIFEST_PATH,
    model_artifact_path: Union[str, Path] = DEFAULT_MODEL_ARTIFACT_PATH,
    output_dir: Union[str, Path] = DEFAULT_EVALUATION_OUTPUT_DIR,
    run_id: Optional[str] = None,
    verify_dataset_hash: bool = True,
    allow_overwrite: bool = False,
) -> Dict[str, Any]:
    """End-to-end fail-closed Test set evaluation pipeline for the Random Forest baseline."""
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
        verify_dataset_hash=verify_dataset_hash,
        fail_closed=True,
    )

    model = RandomForestModel.load_verified(
        model_path=model_artifact_path,
        manifest_path=model_manifest_path,
        expected_dataset_sha256=prereq.verified_hashes.get("dataset_sha256"),
        expected_split_manifest_sha256=prereq.verified_hashes.get("split_manifest_sha256"),
        expected_preprocessor_artifact_sha256=prereq.verified_hashes.get(
            "preprocessor_artifact_sha256"
        ),
    )
    preprocessor = TrainOnlyPreprocessor.load(preprocessor_artifact_path)

    test_data = stream_test_partition_data(
        dataset_csv_path=dataset_csv_path,
        test_indices_path=test_indices_path,
        train_indices_path=train_indices_path,
        val_indices_path=val_indices_path,
    )

    if prereq.expected_test_rows is not None and test_data.num_rows != prereq.expected_test_rows:
        raise ValueError(
            f"Loaded Test row count ({test_data.num_rows}) does not match "
            f"split manifest ({prereq.expected_test_rows})"
        )

    effective_run_id = run_id or f"rf-test-eval-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    run_output_dir = Path(output_dir) / effective_run_id if run_id is None else Path(output_dir)

    return evaluate_loaded_random_forest_on_test(
        model=model,
        preprocessor=preprocessor,
        test_data=test_data,
        output_dir=run_output_dir,
        run_id=effective_run_id,
        provenance_hashes=prereq.verified_hashes,
        allow_overwrite=allow_overwrite,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for Issue #12 Random Forest held-out Test evaluation."""
    parser = argparse.ArgumentParser(
        description="Evaluate trained Random Forest baseline on held-out Test partition (Issue #12)."
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only check prerequisites and print JSON status without running Test evaluation.",
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
