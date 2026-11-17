"""Held-out evaluation and partition disjointness verification for NetFlow Sentinel v2."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, roc_auc_score

from network_anomaly.data.v2_schema import FEATURE_CONTRACT_ID, ML_FEATURE_COLUMNS
from network_anomaly.evaluation.metrics import (
    compute_attack_category_breakdown,
    compute_metrics,
)

DEFAULT_SPLIT_MANIFEST_PATH = Path("reports/splits/v2_split_manifest.json")
DEFAULT_PREPROCESSING_MANIFEST_PATH = Path(
    "reports/preprocessing/v2_flow_preprocessing_manifest.json"
)
DEFAULT_PREPROCESSOR_ARTIFACT_PATH = Path("artifacts/preprocessing/v2_flow_preprocessor.joblib")
CANONICAL_DECISION_THRESHOLD: float = 0.5


def _sha256_file(path: Union[str, Path], chunk_bytes: int = 1024 * 1024) -> str:
    """Compute hex SHA-256 digest of a file."""
    p = Path(path)
    digest = hashlib.sha256()
    with p.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_bytes), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_indices_csv_gz(path: Union[str, Path]) -> np.ndarray:
    """Load integer row indices from a gzipped CSV or plain text CSV."""
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" or p.name.endswith(".csv.gz") else open
    indices: List[int] = []
    with opener(p, "rt", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            token = row[0].strip()
            if not token or token in {"row_index", "index", "row_id"}:
                continue
            indices.append(int(token))
    return np.asarray(indices, dtype=np.int64)


def verify_index_disjointness(
    train_indices_path: Union[str, Path, None],
    val_indices_path: Union[str, Path, None],
    test_indices_path: Union[str, Path, None],
    split_manifest: Optional[Dict[str, Any]] = None,
    total_source_rows: Optional[int] = None,
) -> Tuple[bool, List[str]]:
    """Verify Train/Validation/Test partition index disjointness via set intersections."""
    errors: List[str] = []
    paths = {
        "train": Path(train_indices_path) if train_indices_path is not None else None,
        "validation": Path(val_indices_path) if val_indices_path is not None else None,
        "test": Path(test_indices_path) if test_indices_path is not None else None,
    }
    missing = [name for name, p in paths.items() if p is None or not p.exists()]
    if missing:
        errors.append(f"Missing partition index file(s): {missing}")
        return False, errors

    loaded: Dict[str, np.ndarray] = {}
    sets: Dict[str, set[int]] = {}
    for name, p in paths.items():
        assert p is not None
        arr = _load_indices_csv_gz(p)
        if len(arr) != len(set(arr.tolist())):
            errors.append(f"Duplicate row indices found inside '{name}' partition.")
        if total_source_rows is not None and len(arr) > 0:
            if int(arr.min()) < 0 or int(arr.max()) >= int(total_source_rows):
                errors.append(
                    f"Partition '{name}' contains out-of-bounds indices outside [0, {total_source_rows - 1}]."
                )
        if split_manifest is not None:
            part_meta = (split_manifest.get("partitions") or {}).get(name)
            if isinstance(part_meta, dict):
                expected_sha = part_meta.get("index_sha256")
                if expected_sha and _sha256_file(p).lower() != str(expected_sha).lower():
                    errors.append(f"Index SHA-256 mismatch for partition '{name}'.")
                expected_cnt = part_meta.get("row_count")
                if expected_cnt is not None and len(arr) != int(expected_cnt):
                    errors.append(
                        f"Row count mismatch for '{name}': expected {expected_cnt}, got {len(arr)}."
                    )
        loaded[name] = arr
        sets[name] = set(arr.tolist())

    for a, b in (("train", "validation"), ("train", "test"), ("validation", "test")):
        overlap = sets[a] & sets[b]
        if overlap:
            errors.append(f"Partition leakage: {len(overlap)} overlapping rows between {a} and {b}.")

    return len(errors) == 0, errors


def save_confusion_matrix_artifacts(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    output_dir: Union[str, Path],
    prefix: str = "confusion_matrix",
) -> Dict[str, str]:
    """Save JSON confusion matrix summary without requiring GUI display."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))
    json_path = out / f"{prefix}.json"
    json_path.write_text(
        json.dumps(
            {
                "labels": ["Benign (0)", "Attack (1)"],
                "matrix": [[tn, fp], [fn, tp]],
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"json": str(json_path)}


def evaluate_v2_partition(
    *,
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    attack_categories: Optional[Sequence[str]] = None,
    latency_seconds: float = 0.0,
) -> Dict[str, Any]:
    """Compute full v2 evaluation suite (Precision, Recall, F1, Macro/Weighted F1, PR-AUC, ROC-AUC, FPR, per-class)."""
    y_true_arr = np.asarray(y_true, dtype=np.int64)
    scores_arr = np.asarray(scores, dtype=np.float64)
    y_pred = (scores_arr >= float(threshold)).astype(np.int64)

    base = compute_metrics(y_true_arr, y_pred, labels=[0, 1])
    macro_f1 = float(f1_score(y_true_arr, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true_arr, y_pred, average="weighted", zero_division=0))

    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    if len(np.unique(y_true_arr)) > 1:
        roc_auc = float(roc_auc_score(y_true_arr, scores_arr))
        pr_auc = float(average_precision_score(y_true_arr, scores_arr))

    breakdown = {}
    if attack_categories is not None:
        breakdown = compute_attack_category_breakdown(y_true_arr, y_pred, list(attack_categories))

    n_rows = int(len(y_true_arr))
    latency_us_per_row = (latency_seconds * 1e6 / max(1, n_rows)) if latency_seconds > 0 else None

    return {
        "feature_contract_version": FEATURE_CONTRACT_ID,
        "feature_count": len(ML_FEATURE_COLUMNS),
        "threshold": float(threshold),
        "total_rows": n_rows,
        "accuracy": float(base["accuracy"]),
        "precision": float(base["precision"]),
        "recall": float(base["recall"]),
        "f1": float(base["f1"]),
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "false_positive_rate": float(base["false_positive_rate"]),
        "true_negative_rate": float(base["true_negative_rate"]),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": base["confusion_matrix_labeled"],
        "per_attack_category": breakdown,
        "inference_latency_seconds": round(float(latency_seconds), 4),
        "inference_latency_us_per_row": (
            round(float(latency_us_per_row), 4) if latency_us_per_row is not None else None
        ),
    }


__all__ = [
    "CANONICAL_DECISION_THRESHOLD",
    "DEFAULT_PREPROCESSING_MANIFEST_PATH",
    "DEFAULT_PREPROCESSOR_ARTIFACT_PATH",
    "DEFAULT_SPLIT_MANIFEST_PATH",
    "evaluate_v2_partition",
    "save_confusion_matrix_artifacts",
    "verify_index_disjointness",
]
