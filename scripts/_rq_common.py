"""Shared real-data loading, environment, provenance, and metric helpers for RQ1-RQ6.

All helpers fail closed or return explicit BLOCKED status when required raw datasets
or verified model artifacts are absent. No synthetic numbers are ever substituted for
empirical dataset benchmarks.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from network_anomaly.config import RANDOM_SEED  # noqa: E402
from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

RAW_DATA_PATH = PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
DATA_MANIFEST_PATH = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json"
SPLIT_MANIFEST_PATH = PROJECT_ROOT / "data" / "processed" / "nf_unsw_nb15_v3_split_manifest.json"
INDICES_DIR_PATH = PROJECT_ROOT / "data" / "processed" / "splits"
PREPROCESSOR_ARTIFACT_PATH = (
    PROJECT_ROOT / "artifacts" / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
)
PREPROCESSOR_MANIFEST_PATH = (
    PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _detect_total_ram_gb() -> Optional[float]:
    if sys.platform == "win32":

        class _MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = _MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return round(stat.ullTotalPhys / (1024**3), 2)
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return round(kb / (1024**2), 2)
    return None


def collect_environment_metadata() -> Dict[str, Any]:
    """Capture actual runtime OS, CPU, RAM, Python, and library versions."""
    import cryptography
    import joblib
    import sklearn
    import xgboost

    return {
        "os": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
        "total_ram_gb": _detect_total_ram_gb(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "packages": {
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "joblib": joblib.__version__,
            "cryptography": cryptography.__version__,
        },
        "random_seed": RANDOM_SEED,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def check_nf_unsw_prerequisites() -> Tuple[bool, List[str]]:
    missing: List[str] = []
    for path in (
        RAW_DATA_PATH,
        DATA_MANIFEST_PATH,
        SPLIT_MANIFEST_PATH,
        INDICES_DIR_PATH / "train_indices.csv.gz",
        INDICES_DIR_PATH / "validation_indices.csv.gz",
        INDICES_DIR_PATH / "test_indices.csv.gz",
        PREPROCESSOR_ARTIFACT_PATH,
        PREPROCESSOR_MANIFEST_PATH,
    ):
        if not path.is_file():
            missing.append(str(path))
    return len(missing) == 0, missing


def dataset_provenance_summary() -> Dict[str, Any]:
    data_manifest: Dict[str, Any] = {}
    if DATA_MANIFEST_PATH.is_file():
        data_manifest = json.loads(DATA_MANIFEST_PATH.read_text(encoding="utf-8"))
    split_manifest: Dict[str, Any] = {}
    if SPLIT_MANIFEST_PATH.is_file():
        split_manifest = json.loads(SPLIT_MANIFEST_PATH.read_text(encoding="utf-8"))
    official_source = data_manifest.get("official_source", {})
    csv_sha256 = split_manifest.get("dataset_sha256")
    if not csv_sha256:
        for entry in data_manifest.get("files", []):
            if str(entry.get("file", "")).endswith("NF-UNSW-NB15-v3.csv"):
                csv_sha256 = entry.get("sha256")
                break
    return {
        "dataset_id": data_manifest.get("dataset", "NF-UNSW-NB15-v3"),
        "dataset_version": str(data_manifest.get("release_year", "v3")),
        "doi": official_source.get("doi") or "10.48610/6E0EDA1",
        "source_url": official_source.get("landing_page")
        or "https://staff.itee.uq.edu.au/marius/NIDS_datasets/",
        "dataset_sha256": csv_sha256,
        "split_protocol": split_manifest.get("split_protocol_version"),
        "split_manifest_sha256": (
            sha256_file(SPLIT_MANIFEST_PATH) if SPLIT_MANIFEST_PATH.is_file() else None
        ),
        "preprocessor_sha256": (
            sha256_file(PREPROCESSOR_ARTIFACT_PATH)
            if PREPROCESSOR_ARTIFACT_PATH.is_file()
            else None
        ),
    }


def load_verified_preprocessor() -> TrainOnlyPreprocessor:
    return TrainOnlyPreprocessor.load_verified(
        artifact_path=PREPROCESSOR_ARTIFACT_PATH,
        manifest_path=PREPROCESSOR_MANIFEST_PATH,
        split_manifest_path=SPLIT_MANIFEST_PATH,
        dataset_path=RAW_DATA_PATH,
    )


def load_partition_raw(
    partition_name: str,
    max_rows: Optional[int] = None,
    chunk_size: int = 200_000,
) -> Tuple[pd.DataFrame, np.ndarray, pd.Series]:
    """Load raw feature DataFrame (47 cols), binary Label array, and Attack series."""
    idx_path = INDICES_DIR_PATH / f"{partition_name}_indices.csv.gz"
    if not idx_path.is_file():
        raise FileNotFoundError(f"Missing partition index file: {idx_path}")
    idx_df = pd.read_csv(idx_path, compression="gzip")
    indices = idx_df["source_row_index"].to_numpy(dtype=np.int64)
    if max_rows is not None and len(indices) > max_rows:
        # Stratified-friendly evenly spaced slice across chronological partition
        step = max(1, len(indices) // max_rows)
        indices = indices[::step][:max_rows]
    target_set = set(indices.tolist())
    max_idx = int(indices.max()) if len(indices) else -1

    usecols = list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS)
    collected_frames: List[pd.DataFrame] = []
    row_offset = 0
    for chunk in pd.read_csv(
        RAW_DATA_PATH, usecols=usecols, chunksize=chunk_size, low_memory=False
    ):
        chunk_end = row_offset + len(chunk)
        if row_offset > max_idx:
            break
        mask = [idx in target_set for idx in range(row_offset, chunk_end)]
        if any(mask):
            collected_frames.append(chunk.loc[mask].copy())
        row_offset = chunk_end

    if not collected_frames:
        raise ValueError(f"Loaded 0 rows for partition '{partition_name}'")

    df = pd.concat(collected_frames, axis=0, ignore_index=True)
    X_df = df[list(ML_FEATURE_COLUMNS)].copy()
    y_bin = df["Label"].to_numpy(dtype=np.int64)
    attack_series = df["Attack"].astype(str).fillna("Benign")
    return X_df, y_bin, attack_series


def compute_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_score: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred = np.asarray(y_pred, dtype=np.int64)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    if y_score is not None and len(np.unique(y_true)) == 2:
        finite = np.isfinite(y_score)
        if np.all(finite):
            roc_auc = float(roc_auc_score(y_true, y_score))
            pr_auc = float(average_precision_score(y_true, y_score))

    return {
        "sample_count": int(len(y_true)),
        "positive_count": int(np.sum(y_true == 1)),
        "negative_count": int(np.sum(y_true == 0)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "false_positive_rate": float(fpr),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "confusion_matrix_labeled": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }
