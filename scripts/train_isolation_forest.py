#!/usr/bin/env python3
"""Isolation Forest training and evaluation pipeline — Issue #11, C4.

Executes a complete, reproducible anomaly-detection experiment using
NF-UNSW-NB15-v3.  The script fails closed if any prerequisite is missing or
invalid; it never substitutes mock data or silently bypasses checks.

Exit codes
----------
0  All steps completed (or dataset absent and step was SKIPPED with clear report).
1  Prerequisite check failed or a required step could not complete.
2  Invalid command-line arguments (argparse default).

Usage
-----
Typical real-data run (requires NF-UNSW-NB15-v3.csv in data/raw/NF-UNSW-NB15-v3/data/):
    python scripts/train_isolation_forest.py

Dry-run / CI smoke check (no dataset required):
    python scripts/train_isolation_forest.py --check-prereqs-only

BLOCKED conditions (exits 1)
-----------------------------
- Dataset file absent (--check-prereqs-only exits 0 with BLOCKED status logged).
- SHA-256 checksum mismatch.
- Feature schema incorrect (count or order).
- NaN / Inf values detected post-preprocessing.
- Target columns present in feature matrix.
- Threshold calibration incomplete before test evaluation.
- Artifact save/load verification fails.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# ---------------------------------------------------------------------------
# Module-level constants (paths, contracts, expected sizes)
# ---------------------------------------------------------------------------

DATASET_CSV = PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
SPLIT_MANIFEST_PATH = PROJECT_ROOT / "data" / "processed" / "nf_unsw_nb15_v3_split_manifest.json"
PREPROCESSOR_ARTIFACT_PATH = PROJECT_ROOT / "artifacts" / "preprocessing" / "preprocessor.joblib"
PREPROCESSOR_MANIFEST_PATH = (
    PROJECT_ROOT / "artifacts" / "preprocessing" / "preprocessor_manifest.json"
)
MODEL_ARTIFACT_DIR = PROJECT_ROOT / "artifacts" / "models" / "isolation_forest"
REPORT_DIR = PROJECT_ROOT / "reports" / "experiments" / "isolation_forest"

# Published NF-UNSW-NB15-v3 SHA-256 (BagIt member file checksum from PR #36).
DATASET_SHA256 = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

# Expected partition sizes from the chronological split (PR #41 protocol).
EXPECTED_TRAIN_ROWS = 1_655_797
EXPECTED_VAL_ROWS = 345_371
EXPECTED_TEST_ROWS = 345_953

# Expected 47-feature baseline contract (PR #36 migration).
EXPECTED_N_FEATURES = 47

# Attack categories in NF-UNSW-NB15-v3.
ATTACK_CATEGORIES = (
    "Benign",
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
)

# Unknown categories held out from threshold calibration.
# Pre-registered before any test evaluation per leakage-safe protocol.
# Choice rationale: Worms is rare and constitutes a distinct, low-prevalence
# attack type; Backdoor is also low-prevalence and differs in network signature
# from high-volume categories.  These two are excluded from validation-based
# threshold selection to simulate genuinely unseen attack types at test time.
UNKNOWN_ATTACK_CATEGORIES = frozenset({"Worms", "Backdoor"})
KNOWN_ATTACK_CATEGORIES = frozenset(
    c for c in ATTACK_CATEGORIES if c != "Benign" and c not in UNKNOWN_ATTACK_CATEGORIES
)

CHUNK_BYTES = 8 * 1024 * 1024  # 8 MiB for streaming SHA-256


# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    """Return lower-case hex SHA-256 of the file at *path*."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_dataset(skip_checksum: bool = False) -> dict:
    """Return a status dict for the dataset prerequisite.

    Returns
    -------
    dict with keys:
        status  : "PASS" | "BLOCKED"
        message : human-readable explanation
        path    : str path checked
    """
    rel_path = DATASET_CSV.relative_to(PROJECT_ROOT).as_posix()
    if not DATASET_CSV.exists():
        return {
            "status": "BLOCKED",
            "message": (
                f"NF-UNSW-NB15-v3 CSV not found at {rel_path}. "
                "Run: python scripts/fetch_nf_unsw_nb15_v3.py"
            ),
            "path": rel_path,
        }
    if skip_checksum:
        return {
            "status": "PASS",
            "message": "Dataset file present (checksum skipped by --skip-checksum).",
            "path": rel_path,
        }
    print("  Computing SHA-256 of dataset (577 MB) …", flush=True)
    actual = sha256_file(DATASET_CSV)
    if actual != DATASET_SHA256:
        return {
            "status": "BLOCKED",
            "message": (
                f"Dataset SHA-256 mismatch.\n"
                f"  expected: {DATASET_SHA256}\n"
                f"  actual  : {actual}\n"
                "Re-fetch with: python scripts/fetch_nf_unsw_nb15_v3.py"
            ),
            "path": rel_path,
            "expected_sha256": DATASET_SHA256,
            "actual_sha256": actual,
        }
    return {
        "status": "PASS",
        "message": "Dataset SHA-256 verified.",
        "path": rel_path,
        "sha256": actual,
    }


def check_split_manifest() -> dict:
    """Verify the split manifest produced by PR #41."""
    if not SPLIT_MANIFEST_PATH.exists():
        return {
            "status": "BLOCKED",
            "message": (
                f"Split manifest not found at {SPLIT_MANIFEST_PATH}. "
                "Run the chronological split script from PR #41."
            ),
            "path": str(SPLIT_MANIFEST_PATH),
        }
    try:
        with SPLIT_MANIFEST_PATH.open() as fh:
            manifest = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "BLOCKED",
            "message": f"Split manifest unreadable: {exc}",
            "path": str(SPLIT_MANIFEST_PATH),
        }
    required_keys = {"train_rows", "validation_rows", "test_rows", "dataset_sha256"}
    missing = required_keys - set(manifest)
    if missing:
        return {
            "status": "BLOCKED",
            "message": f"Split manifest missing required keys: {sorted(missing)}",
            "path": str(SPLIT_MANIFEST_PATH),
        }
    issues = []
    if manifest.get("train_rows") != EXPECTED_TRAIN_ROWS:
        issues.append(f"train_rows {manifest['train_rows']} != expected {EXPECTED_TRAIN_ROWS}")
    if manifest.get("validation_rows") != EXPECTED_VAL_ROWS:
        issues.append(
            f"validation_rows {manifest['validation_rows']} != expected {EXPECTED_VAL_ROWS}"
        )
    if manifest.get("test_rows") != EXPECTED_TEST_ROWS:
        issues.append(f"test_rows {manifest['test_rows']} != expected {EXPECTED_TEST_ROWS}")
    if issues:
        return {
            "status": "BLOCKED",
            "message": "Split manifest row counts do not match expected: " + "; ".join(issues),
            "path": str(SPLIT_MANIFEST_PATH),
        }
    return {
        "status": "PASS",
        "message": "Split manifest verified.",
        "path": str(SPLIT_MANIFEST_PATH),
        "manifest": manifest,
    }


def check_preprocessor_artifact() -> dict:
    """Verify the fitted preprocessor artifact produced by PR #42."""
    if not PREPROCESSOR_ARTIFACT_PATH.exists():
        return {
            "status": "BLOCKED",
            "message": (
                f"Preprocessor artifact not found at {PREPROCESSOR_ARTIFACT_PATH}. "
                "Run the preprocessing pipeline from PR #42."
            ),
            "path": str(PREPROCESSOR_ARTIFACT_PATH),
        }
    if not PREPROCESSOR_MANIFEST_PATH.exists():
        return {
            "status": "BLOCKED",
            "message": (f"Preprocessor manifest not found at {PREPROCESSOR_MANIFEST_PATH}."),
            "path": str(PREPROCESSOR_MANIFEST_PATH),
        }
    try:
        with PREPROCESSOR_MANIFEST_PATH.open() as fh:
            pp_manifest = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "BLOCKED",
            "message": f"Preprocessor manifest unreadable: {exc}",
            "path": str(PREPROCESSOR_MANIFEST_PATH),
        }
    # Verify the preprocessor artifact SHA-256 against the companion manifest.
    expected_pp_sha256 = pp_manifest.get("artifact_sha256")
    if expected_pp_sha256:
        actual_pp_sha256 = sha256_file(PREPROCESSOR_ARTIFACT_PATH)
        if actual_pp_sha256 != expected_pp_sha256:
            return {
                "status": "BLOCKED",
                "message": (
                    f"Preprocessor artifact SHA-256 mismatch.\n"
                    f"  expected: {expected_pp_sha256}\n"
                    f"  actual  : {actual_pp_sha256}"
                ),
                "path": str(PREPROCESSOR_ARTIFACT_PATH),
            }
    return {
        "status": "PASS",
        "message": "Preprocessor artifact and manifest verified.",
        "path": str(PREPROCESSOR_ARTIFACT_PATH),
        "manifest": pp_manifest,
    }


def check_feature_schema(columns) -> dict:
    """Verify feature columns match the 47-feature baseline contract."""
    from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS, TARGET_COLUMNS

    columns = list(columns)
    # Check no target or metadata leakage
    forbidden_present = [c for c in columns if c in set(TARGET_COLUMNS)]
    if forbidden_present:
        return {
            "status": "FAIL",
            "message": f"Target columns found in feature matrix: {forbidden_present}",
        }
    if len(columns) != EXPECTED_N_FEATURES:
        return {
            "status": "FAIL",
            "message": (
                f"Feature count mismatch: expected {EXPECTED_N_FEATURES}, got {len(columns)}. "
                f"Columns: {columns}"
            ),
        }
    expected = list(ML_FEATURE_COLUMNS)
    if columns != expected:
        mismatch = [(i, e, a) for i, (e, a) in enumerate(zip(expected, columns)) if e != a]
        ellipsis_marker = "..." if len(mismatch) > 5 else ""
        return {
            "status": "FAIL",
            "message": f"Feature order mismatch at positions: {mismatch[:5]}{ellipsis_marker}",
        }
    return {
        "status": "PASS",
        "message": f"Feature schema matches {EXPECTED_N_FEATURES}-feature contract.",
    }


def check_no_leakage_in_matrix(X_df) -> dict:
    """Confirm no target or metadata columns leaked into the feature matrix."""
    from network_anomaly.data.nf_unsw_nb15_v3 import TARGET_COLUMNS, TRACE_METADATA_COLUMNS

    all_forbidden = set(TARGET_COLUMNS) | set(TRACE_METADATA_COLUMNS)
    found = [c for c in X_df.columns if c in all_forbidden]
    if found:
        return {
            "status": "FAIL",
            "message": f"Leakage detected — forbidden columns in X: {found}",
        }
    return {"status": "PASS", "message": "No target or metadata leakage detected."}


def check_finite_values(X_array, partition_name: str) -> dict:
    """Confirm no NaN or Inf in the feature matrix."""
    import numpy as np

    if not np.isfinite(X_array).all():
        n_bad = (~np.isfinite(X_array)).sum()
        return {
            "status": "FAIL",
            "message": (
                f"{partition_name}: {n_bad} non-finite values (NaN/Inf) detected. "
                "The preprocessor must handle these before training."
            ),
        }
    return {"status": "PASS", "message": f"{partition_name}: all values finite."}


# ---------------------------------------------------------------------------
# Data loading helpers (chunked / streaming to manage memory)
# ---------------------------------------------------------------------------


def load_partition_csv(path: Path, label: str) -> Any:
    """Load a partition CSV and return a DataFrame with all columns."""
    import pandas as pd

    print(f"  Loading {label} partition from {path} …", flush=True)
    df = pd.read_csv(path, low_memory=False)
    print(f"    {len(df):,} rows, {df.shape[1]} columns", flush=True)
    return df


def apply_preprocessor(preprocessor, X_df: Any) -> Any:
    """Apply the fitted preprocessor transform (never fit on val/test)."""
    return preprocessor.transform(X_df)


# ---------------------------------------------------------------------------
# Threshold calibration
# ---------------------------------------------------------------------------


def calibrate_threshold(
    scores_benign_val,
    scores_attack_val,
    scores_unknown_val=None,
    fpr_target: float | None = None,
) -> dict:
    """Select anomaly threshold on validation data.

    Protocol
    --------
    - Use only known-attack validation scores for threshold selection.
    - Unknown-attack scores are reported but not used to select the threshold.
    - If fpr_target is given, select the threshold that achieves that FPR on
      benign validation traffic.  Otherwise select the threshold that maximises
      F1 on known attacks vs. benign validation traffic.
    - The selected threshold is frozen before test evaluation.

    Returns a dict with the selected threshold, operating-point metrics and
    calibration rationale.
    """
    import numpy as np

    scores_benign_val = np.asarray(scores_benign_val, dtype=np.float64)
    scores_attack_val = np.asarray(scores_attack_val, dtype=np.float64)

    all_scores = np.concatenate([scores_benign_val, scores_attack_val])
    all_labels = np.concatenate([np.zeros(len(scores_benign_val)), np.ones(len(scores_attack_val))])

    # Candidate thresholds: sorted unique score values
    candidates = np.unique(all_scores)
    if len(candidates) > 10_000:
        # Sample 10 000 evenly-spaced candidates for speed
        idx = np.linspace(0, len(candidates) - 1, 10_000, dtype=int)
        candidates = candidates[idx]

    best_thresh = None
    best_metric = -1.0
    best_stats = {}

    for thresh in candidates:
        preds = (all_scores >= thresh).astype(int)
        tp = int(((preds == 1) & (all_labels == 1)).sum())
        tn = int(((preds == 0) & (all_labels == 0)).sum())
        fp = int(((preds == 1) & (all_labels == 0)).sum())
        fn = int(((preds == 0) & (all_labels == 1)).sum())
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        if fpr_target is not None:
            # Select highest recall that keeps FPR <= fpr_target
            if fpr <= fpr_target and recall > best_metric:
                best_metric = recall
                best_thresh = thresh
                best_stats = {
                    "tp": tp,
                    "tn": tn,
                    "fp": fp,
                    "fn": fn,
                    "precision": precision,
                    "recall": recall,
                    "f1": f1,
                    "fpr": fpr,
                }
        else:
            # Maximise F1
            if f1 > best_metric:
                best_metric = f1
                best_thresh = thresh
                best_stats = {
                    "tp": tp,
                    "tn": tn,
                    "fp": fp,
                    "fn": fn,
                    "precision": precision,
                    "recall": recall,
                    "f1": f1,
                    "fpr": fpr,
                }

    if best_thresh is None:
        # Fallback: use 95th percentile of benign scores
        best_thresh = float(np.percentile(scores_benign_val, 95))
        best_stats = {"fallback": "95th-percentile-benign"}

    policy = "max-F1-on-known-attacks" if fpr_target is None else f"max-recall-at-FPR<={fpr_target}"

    result = {
        "threshold": float(best_thresh),
        "policy": policy,
        "validation_stats": best_stats,
    }

    if scores_unknown_val is not None:
        scores_unknown_val = np.asarray(scores_unknown_val, dtype=np.float64)
        detected_unknown = int((scores_unknown_val >= best_thresh).sum())
        result["unknown_validation_detection"] = {
            "n_samples": len(scores_unknown_val),
            "n_detected": detected_unknown,
            "detection_rate": detected_unknown / len(scores_unknown_val)
            if len(scores_unknown_val) > 0
            else 0.0,
            "note": "Unknown attack scores observed but NOT used to select threshold.",
        }

    return result


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def compute_full_metrics(y_true, y_pred, scores) -> dict:
    """Compute all required binary-classification metrics."""
    import numpy as np
    from sklearn.metrics import (
        average_precision_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    scores = np.asarray(scores, dtype=np.float64)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    n = len(y_true)
    accuracy = (tp + tn) / n if n > 0 else 0.0
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    roc_auc = float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) > 1 else None
    pr_auc = float(average_precision_score(y_true, scores)) if len(np.unique(y_true)) > 1 else None

    return {
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "accuracy": accuracy,
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": fpr,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": cm.tolist(),
        "n_samples": n,
    }


def compute_per_category_metrics(y_true, y_pred, scores, attack_col) -> dict:
    """Detection rate per attack category."""
    import numpy as np

    results = {}
    attack_col = list(attack_col)
    y_pred = np.asarray(y_pred, dtype=int)
    scores = np.asarray(scores, dtype=np.float64)

    unique_cats = sorted(set(attack_col))
    for cat in unique_cats:
        mask = [i for i, c in enumerate(attack_col) if c == cat]
        if not mask:
            continue
        cat_true = np.asarray([y_true[i] for i in mask], dtype=int)
        cat_pred = y_pred[mask]
        n = len(cat_true)
        n_detected = int((cat_pred == 1).sum())
        detection_rate = n_detected / n if n > 0 else 0.0
        results[cat] = {
            "n_samples": n,
            "n_detected": n_detected,
            "detection_rate": detection_rate,
            "is_known": cat not in UNKNOWN_ATTACK_CATEGORIES and cat != "Benign",
            "is_unknown": cat in UNKNOWN_ATTACK_CATEGORIES,
        }
    return results


# ---------------------------------------------------------------------------
# Artifact save/load
# ---------------------------------------------------------------------------


def save_artifacts(
    model,
    config: dict,
    threshold: float,
    training_meta: dict,
    output_dir: Path,
) -> dict:
    """Save model, config, threshold and metadata; return artifact checksums."""
    import joblib

    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "isolation_forest.joblib"
    config_path = output_dir / "model_config.json"
    threshold_path = output_dir / "threshold.json"
    meta_path = output_dir / "training_metadata.json"

    joblib.dump(model, model_path)
    with config_path.open("w") as fh:
        json.dump(config, fh, indent=2)
    with threshold_path.open("w") as fh:
        json.dump({"threshold": threshold}, fh, indent=2)
    with meta_path.open("w") as fh:
        json.dump(training_meta, fh, indent=2, default=str)

    checksums = {}
    for artifact_path in [model_path, config_path, threshold_path, meta_path]:
        checksums[artifact_path.name] = sha256_file(artifact_path)

    return {
        "directory": str(output_dir),
        "files": {
            "model": str(model_path),
            "config": str(config_path),
            "threshold": str(threshold_path),
            "metadata": str(meta_path),
        },
        "checksums": checksums,
    }


def verify_saved_model(model_path: Path, original_model, X_sample) -> dict:
    """Reload saved model and verify it produces equivalent scores."""
    import joblib
    import numpy as np

    from network_anomaly.models.isolation_forest import anomaly_scores

    loaded_model = joblib.load(model_path)
    original_scores = anomaly_scores(original_model, X_sample)
    loaded_scores = anomaly_scores(loaded_model, X_sample)

    if not np.allclose(original_scores, loaded_scores, rtol=1e-6, atol=1e-10):
        max_diff = float(np.abs(original_scores - loaded_scores).max())
        return {
            "status": "FAIL",
            "message": f"Reloaded model scores differ from original (max diff: {max_diff})",
        }
    return {
        "status": "PASS",
        "message": "Reloaded model produces equivalent anomaly scores.",
        "n_samples_checked": len(X_sample),
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def save_reports(
    metrics: dict,
    threshold_calibration: dict,
    per_attack_metrics: dict,
    run_metadata: dict,
    training_meta: dict,
    report_dir: Path,
) -> None:
    """Write machine-readable JSON reports and a markdown evaluation report."""
    report_dir.mkdir(parents=True, exist_ok=True)

    with (report_dir / "metrics.json").open("w") as fh:
        json.dump(metrics, fh, indent=2, default=str)
    with (report_dir / "threshold_calibration.json").open("w") as fh:
        json.dump(threshold_calibration, fh, indent=2, default=str)
    with (report_dir / "per_attack_metrics.json").open("w") as fh:
        json.dump(per_attack_metrics, fh, indent=2, default=str)
    with (report_dir / "run_metadata.json").open("w") as fh:
        json.dump(run_metadata, fh, indent=2, default=str)

    _write_evaluation_report(
        metrics, threshold_calibration, per_attack_metrics, run_metadata, training_meta, report_dir
    )


def _write_evaluation_report(
    metrics, threshold_calibration, per_attack_metrics, run_metadata, training_meta, report_dir
):
    lines = [
        "# Isolation Forest Evaluation Report",
        "",
        f"Run ID: {run_metadata.get('run_id', 'N/A')}",
        f"Timestamp: {run_metadata.get('timestamp', 'N/A')}",
        f"Git commit: {run_metadata.get('git_commit', 'N/A')}",
        "Issue: #11 — C4 Isolation Forest real-data experiment",
        "",
        "## Status",
        "",
        f"- Training: {training_meta.get('status', 'N/A')}",
        f"- Threshold calibration: {threshold_calibration.get('policy', 'N/A')}",
        f"- Test evaluation: {metrics.get('status', 'COMPLETED') if metrics else 'NOT EXECUTED'}",
        "",
        "## Training",
        "",
        "- Model: IsolationForest (scikit-learn)",
        "- Training population: benign-only (Label == 0) from Train partition",
        f"- n_train_benign: {training_meta.get('n_train_benign', 'N/A'):,}"
        if isinstance(training_meta.get("n_train_benign"), int)
        else f"- n_train_benign: {training_meta.get('n_train_benign', 'N/A')}",
        f"- Training duration: {training_meta.get('training_duration_seconds', 'N/A')} s",
        f"- Random seed: {training_meta.get('random_state', 'N/A')}",
        "",
        "## Hyperparameters",
        "",
    ]
    for k, v in training_meta.get("hyperparameters", {}).items():
        lines.append(f"- {k}: {v}")

    lines += [
        "",
        "## Threshold Calibration (Validation)",
        "",
        f"- Policy: {threshold_calibration.get('policy', 'N/A')}",
        f"- Selected threshold: {threshold_calibration.get('threshold', 'N/A')}",
        f"- Unknown attack categories (pre-registered, excluded from calibration): "
        f"{sorted(UNKNOWN_ATTACK_CATEGORIES)}",
        "",
        "### Validation operating-point metrics",
        "",
    ]
    val_stats = threshold_calibration.get("validation_stats", {})
    for k, v in val_stats.items():
        lines.append(f"- {k}: {v}")

    unknown_val = threshold_calibration.get("unknown_validation_detection", {})
    if unknown_val:
        lines += [
            "",
            "### Unknown attack detection on validation (observational only)",
            "",
            f"- n_samples: {unknown_val.get('n_samples', 'N/A')}",
            f"- n_detected: {unknown_val.get('n_detected', 'N/A')}",
            f"- detection_rate: {unknown_val.get('detection_rate', 'N/A'):.4f}"
            if isinstance(unknown_val.get("detection_rate"), float)
            else f"- detection_rate: {unknown_val.get('detection_rate', 'N/A')}",
            f"- Note: {unknown_val.get('note', '')}",
        ]

    if metrics:
        lines += [
            "",
            "## Test Evaluation",
            "",
            f"- TP: {metrics.get('tp', 'N/A')}",
            f"- TN: {metrics.get('tn', 'N/A')}",
            f"- FP: {metrics.get('fp', 'N/A')}",
            f"- FN: {metrics.get('fn', 'N/A')}",
            f"- Accuracy: {metrics.get('accuracy', 0):.6f}"
            if isinstance(metrics.get("accuracy"), float)
            else f"- Accuracy: {metrics.get('accuracy', 'N/A')}",
            f"- Precision: {metrics.get('precision', 0):.6f}"
            if isinstance(metrics.get("precision"), float)
            else f"- Precision: {metrics.get('precision', 'N/A')}",
            f"- Recall / Detection Rate: {metrics.get('recall', 0):.6f}"
            if isinstance(metrics.get("recall"), float)
            else f"- Recall: {metrics.get('recall', 'N/A')}",
            f"- F1: {metrics.get('f1', 0):.6f}"
            if isinstance(metrics.get("f1"), float)
            else f"- F1: {metrics.get('f1', 'N/A')}",
            f"- FPR: {metrics.get('fpr', 0):.6f}"
            if isinstance(metrics.get("fpr"), float)
            else f"- FPR: {metrics.get('fpr', 'N/A')}",
            f"- ROC-AUC: {metrics.get('roc_auc', 'N/A')}",
            f"- PR-AUC: {metrics.get('pr_auc', 'N/A')}",
            "",
            "### Confusion matrix (rows=actual, cols=predicted, labels=[benign, attack])",
            "",
            "```",
            str(metrics.get("confusion_matrix", [])),
            "```",
        ]

    if per_attack_metrics:
        lines += [
            "",
            "## Per-Attack Detection Rates (Test)",
            "",
            "| Category | Known/Unknown | N | Detected | Detection Rate |",
            "|---|---|---|---|---|",
        ]
        for cat, stats in per_attack_metrics.items():
            if cat == "Benign":
                continue
            kind = "UNKNOWN" if stats.get("is_unknown") else "known"
            lines.append(
                f"| {cat} | {kind} | {stats['n_samples']} | "
                f"{stats['n_detected']} | {stats['detection_rate']:.4f} |"
            )

    lines += [
        "",
        "## Limitations",
        "",
        "- Isolation Forest is trained on benign-only traffic; unsupervised threshold "
        "calibration uses known attack categories only.",
        "- Unknown attack detection rate reflects generalization, not a zero-day capability claim.",
        "- Temporal holdout tests chronological ordering within Jan–Feb 2015 capture only.",
        "- Session grouping uses a 5-minute heuristic bucket; residual flow adjacency is possible.",
        "- Results are valid only for the exact dataset version, split, preprocessor "
        "and random seed recorded in run_metadata.json.",
        "",
        "## Traceability",
        "",
        "Issue #11 → C4 → `src/network_anomaly/models/isolation_forest.py` "
        "→ `scripts/train_isolation_forest.py` → this report",
        "",
        f"Status: {training_meta.get('experiment_status', 'IMPLEMENTED')}",
    ]

    with (report_dir / "evaluation_report.md").open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Run-metadata helpers
# ---------------------------------------------------------------------------


def collect_run_metadata(args) -> dict:
    """Collect reproducibility metadata for the current run."""
    import subprocess

    run_id = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    try:
        git_commit = (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=str(PROJECT_ROOT),
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
    except Exception:  # noqa: BLE001
        git_commit = "NOT_AVAILABLE"

    try:
        pip_freeze = (
            subprocess.check_output(
                [sys.executable, "-m", "pip", "freeze"],
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
    except Exception:  # noqa: BLE001
        pip_freeze = "NOT_AVAILABLE"

    try:
        script_path = Path(__file__).resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        script_path = str(Path(__file__).name)

    return {
        "run_id": run_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "git_commit": git_commit,
        "python_version": sys.version,
        "platform": sys.platform,
        "pip_freeze": pip_freeze,
        "script": script_path,
        "args": vars(args),
        "issue": "#11",
        "checkpoint": "C4",
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run_pipeline(args) -> int:
    """Execute the complete Isolation Forest pipeline.  Returns exit code."""
    import numpy as np

    run_meta = collect_run_metadata(args)
    run_id = run_meta["run_id"]
    print(f"[train_isolation_forest] Run ID: {run_id}", flush=True)
    print(f"[train_isolation_forest] Git commit: {run_meta['git_commit']}", flush=True)

    # ------------------------------------------------------------------
    # Step 1 — prerequisite checks
    # ------------------------------------------------------------------
    print("\n[Step 1] Prerequisite checks", flush=True)

    print("  Checking dataset …", flush=True)
    dataset_check = check_dataset(skip_checksum=args.skip_checksum)
    print(f"    {dataset_check['status']}: {dataset_check['message']}", flush=True)

    if dataset_check["status"] == "BLOCKED":
        print(
            "\n[BLOCKED] NF-UNSW-NB15-v3 dataset not available.\n"
            "Real-data training and evaluation: NOT VERIFIED.\n"
            "Synthetic unit/integration tests remain valid.\n"
            "To proceed: run `python scripts/fetch_nf_unsw_nb15_v3.py` then retry.",
            flush=True,
        )
        # Save a BLOCKED status report so CI can inspect it
        _save_blocked_report(run_meta, dataset_check)
        if args.check_prereqs_only:
            return 0  # Expected blocked state is not a script failure for CI
        return 1

    print("  Checking split manifest …", flush=True)
    split_check = check_split_manifest()
    print(f"    {split_check['status']}: {split_check['message']}", flush=True)
    if split_check["status"] == "BLOCKED":
        print(f"\n[BLOCKED] {split_check['message']}", flush=True)
        return 1

    print("  Checking preprocessor artifact …", flush=True)
    pp_check = check_preprocessor_artifact()
    print(f"    {pp_check['status']}: {pp_check['message']}", flush=True)
    if pp_check["status"] == "BLOCKED":
        print(f"\n[BLOCKED] {pp_check['message']}", flush=True)
        return 1

    if args.check_prereqs_only:
        print("\n[Step 1] All prerequisites PASS. --check-prereqs-only: stopping here.", flush=True)
        return 0

    # ------------------------------------------------------------------
    # Step 2 — load data and apply fitted preprocessor
    # ------------------------------------------------------------------
    print("\n[Step 2] Load partitions and apply preprocessor", flush=True)

    import joblib

    print("  Loading fitted preprocessor …", flush=True)
    preprocessor = joblib.load(PREPROCESSOR_ARTIFACT_PATH)

    split_manifest = split_check["manifest"]
    train_path = Path(split_manifest["train_path"])
    val_path = Path(split_manifest["validation_path"])
    test_path = Path(split_manifest["test_path"])

    df_train = load_partition_csv(train_path, "Train")
    df_val = load_partition_csv(val_path, "Validation")
    df_test = load_partition_csv(test_path, "Test")

    # Verify row counts
    for name, df, expected in [
        ("Train", df_train, EXPECTED_TRAIN_ROWS),
        ("Validation", df_val, EXPECTED_VAL_ROWS),
        ("Test", df_test, EXPECTED_TEST_ROWS),
    ]:
        if len(df) != expected:
            print(
                f"[BLOCKED] {name} row count {len(df):,} != expected {expected:,}",
                flush=True,
            )
            return 1

    # Extract labels before feature matrix construction
    y_train = df_train["Label"].values
    y_val = df_val["Label"].values
    y_test = df_test["Label"].values
    attack_val = df_val["Attack"].tolist()
    attack_test = df_test["Attack"].tolist()

    # Build feature matrices — exclude target + metadata columns
    from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS

    feature_cols = list(ML_FEATURE_COLUMNS)

    X_train_raw = df_train[feature_cols]
    X_val_raw = df_val[feature_cols]
    X_test_raw = df_test[feature_cols]

    # Validate feature schema
    schema_check = check_feature_schema(feature_cols)
    print(f"  Feature schema: {schema_check['status']} — {schema_check['message']}", flush=True)
    if schema_check["status"] != "PASS":
        return 1

    # Apply fitted preprocessor (transform only — never fit on val/test)
    print("  Applying fitted preprocessor to Train …", flush=True)
    X_train = apply_preprocessor(preprocessor, X_train_raw)
    print("  Applying fitted preprocessor to Validation …", flush=True)
    X_val = apply_preprocessor(preprocessor, X_val_raw)
    print("  Applying fitted preprocessor to Test …", flush=True)
    X_test = apply_preprocessor(preprocessor, X_test_raw)

    # Check for NaN/Inf post-preprocessing
    for name, X in [("Train", X_train), ("Validation", X_val), ("Test", X_test)]:
        finite_check = check_finite_values(X, name)
        print(f"  Finite check {name}: {finite_check['status']}", flush=True)
        if finite_check["status"] != "PASS":
            print(f"[BLOCKED] {finite_check['message']}", flush=True)
            return 1

    # ------------------------------------------------------------------
    # Step 3 — train Isolation Forest on benign-only Train samples
    # ------------------------------------------------------------------
    print("\n[Step 3] Train Isolation Forest (benign-only)", flush=True)

    from network_anomaly.config import ISOLATION_FOREST_DEFAULTS, RANDOM_SEED
    from network_anomaly.models.isolation_forest import (
        anomaly_scores,
        build_model,
        fit_model,
    )

    # Filter to benign-only training samples
    benign_mask = y_train == 0
    X_train_benign = X_train[benign_mask]
    n_train_benign = int(benign_mask.sum())
    n_train_total = len(y_train)
    print(
        f"  Training population: {n_train_benign:,} benign samples "
        f"(of {n_train_total:,} total train rows)",
        flush=True,
    )

    # Build model with explicit hyperparameters (documented overrides on top of defaults)
    model_config = dict(ISOLATION_FOREST_DEFAULTS)
    # For large datasets, limit max_samples to 10_000 for memory efficiency.
    # The contamination parameter is used internally by scikit-learn for the
    # offset_ attribute; threshold selection uses the validation protocol, not
    # the contamination-based offset.
    model_config.update(
        {
            "n_estimators": args.n_estimators,
            "max_samples": args.max_samples if args.max_samples != "auto" else "auto",
            "contamination": args.contamination,
            "max_features": args.max_features,
            "bootstrap": args.bootstrap,
            "random_state": RANDOM_SEED,
            "n_jobs": args.n_jobs,
        }
    )
    model = build_model(model_config)

    print(f"  Effective hyperparameters: {model_config}", flush=True)
    t0 = time.monotonic()
    fit_model(model, X_train_benign)
    training_duration = time.monotonic() - t0
    print(f"  Training complete in {training_duration:.1f} s", flush=True)

    training_meta = {
        "n_train_total": n_train_total,
        "n_train_benign": n_train_benign,
        "training_population": "benign-only (Label == 0)",
        "training_duration_seconds": round(training_duration, 2),
        "random_state": RANDOM_SEED,
        "hyperparameters": model_config,
        "dataset_sha256": dataset_check.get("sha256", "NOT_VERIFIED"),
        "split_manifest": str(SPLIT_MANIFEST_PATH),
        "preprocessor_artifact": str(PREPROCESSOR_ARTIFACT_PATH),
        "feature_columns": feature_cols,
        "n_features": len(feature_cols),
        "experiment_status": "IMPLEMENTED",
    }

    # ------------------------------------------------------------------
    # Step 4 — threshold calibration on Validation
    # ------------------------------------------------------------------
    print("\n[Step 4] Threshold calibration on Validation", flush=True)

    print("  Scoring validation partition …", flush=True)
    scores_val = anomaly_scores(model, X_val)

    # Separate validation scores by known/unknown/benign
    val_benign_mask = y_val == 0
    scores_val_benign = scores_val[val_benign_mask]

    # Known attacks: exclude UNKNOWN_ATTACK_CATEGORIES from calibration
    known_mask_val = np.array(
        [
            (y_val[i] == 1 and attack_val[i] not in UNKNOWN_ATTACK_CATEGORIES)
            for i in range(len(y_val))
        ]
    )
    unknown_mask_val = np.array(
        [(y_val[i] == 1 and attack_val[i] in UNKNOWN_ATTACK_CATEGORIES) for i in range(len(y_val))]
    )
    scores_val_known_attack = scores_val[known_mask_val]
    scores_val_unknown_attack = scores_val[unknown_mask_val]

    print(
        f"  Validation — benign: {len(scores_val_benign):,}, "
        f"known attack: {len(scores_val_known_attack):,}, "
        f"unknown attack: {len(scores_val_unknown_attack):,}",
        flush=True,
    )
    print(
        f"  Unknown categories (pre-registered): {sorted(UNKNOWN_ATTACK_CATEGORIES)}",
        flush=True,
    )

    threshold_result = calibrate_threshold(
        scores_val_benign,
        scores_val_known_attack,
        scores_val_unknown_attack,
        fpr_target=args.fpr_target,
    )
    threshold = threshold_result["threshold"]
    print(
        f"  Selected threshold: {threshold:.6f} (policy: {threshold_result['policy']})",
        flush=True,
    )

    # THRESHOLD IS NOW FROZEN — test evaluation may begin
    print("  Threshold frozen. Test evaluation will proceed.", flush=True)

    # ------------------------------------------------------------------
    # Step 5 — final evaluation on Test (threshold frozen)
    # ------------------------------------------------------------------
    print("\n[Step 5] Final evaluation on Test (frozen threshold)", flush=True)

    print("  Scoring test partition …", flush=True)
    scores_test = anomaly_scores(model, X_test)
    y_pred_test = (scores_test >= threshold).astype(int)

    test_metrics = compute_full_metrics(y_test, y_pred_test, scores_test)
    print(
        f"  Test TP={test_metrics['tp']:,} TN={test_metrics['tn']:,} "
        f"FP={test_metrics['fp']:,} FN={test_metrics['fn']:,}",
        flush=True,
    )
    print(
        f"  Test Accuracy={test_metrics['accuracy']:.4f} "
        f"Precision={test_metrics['precision']:.4f} "
        f"Recall={test_metrics['recall']:.4f} "
        f"F1={test_metrics['f1']:.4f}",
        flush=True,
    )
    print(
        f"  Test FPR={test_metrics['fpr']:.4f} "
        f"ROC-AUC={test_metrics['roc_auc']} "
        f"PR-AUC={test_metrics['pr_auc']}",
        flush=True,
    )

    per_attack = compute_per_category_metrics(y_test, y_pred_test, scores_test, attack_test)
    print("\n  Per-attack detection rates on Test:", flush=True)
    for cat, stats in per_attack.items():
        if cat == "Benign":
            continue
        kind = "UNKNOWN" if stats["is_unknown"] else "known "
        print(
            f"    [{kind}] {cat}: {stats['n_detected']}/{stats['n_samples']} "
            f"({stats['detection_rate']:.4f})",
            flush=True,
        )

    # Known vs unknown summary
    known_cats = [c for c, s in per_attack.items() if s.get("is_known")]
    unknown_cats = [c for c, s in per_attack.items() if s.get("is_unknown")]
    if known_cats:
        known_n = sum(per_attack[c]["n_samples"] for c in known_cats)
        known_det = sum(per_attack[c]["n_detected"] for c in known_cats)
        print(
            f"  Known attack detection rate: {known_det}/{known_n} = {known_det / known_n:.4f}"
            if known_n
            else "  No known attack samples in test.",
            flush=True,
        )
    if unknown_cats:
        unk_n = sum(per_attack[c]["n_samples"] for c in unknown_cats)
        unk_det = sum(per_attack[c]["n_detected"] for c in unknown_cats)
        print(
            f"  Unknown attack detection rate: {unk_det}/{unk_n} = {unk_det / unk_n:.4f}"
            if unk_n
            else "  No unknown attack samples in test.",
            flush=True,
        )

    training_meta["experiment_status"] = "EXPERIMENTALLY VALIDATED"

    # ------------------------------------------------------------------
    # Step 6 — save artifacts
    # ------------------------------------------------------------------
    print("\n[Step 6] Save artifacts", flush=True)
    MODEL_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    pp_artifact_sha256 = sha256_file(PREPROCESSOR_ARTIFACT_PATH)
    training_meta["preprocessor_artifact_sha256"] = pp_artifact_sha256

    artifacts_info = save_artifacts(
        model=model,
        config=model_config,
        threshold=threshold,
        training_meta=training_meta,
        output_dir=MODEL_ARTIFACT_DIR,
    )
    print(f"  Artifacts saved to: {artifacts_info['directory']}", flush=True)
    for name, path in artifacts_info["files"].items():
        sha = artifacts_info["checksums"].get(Path(path).name, "N/A")
        print(f"    {name}: {Path(path).name} (sha256: {sha})", flush=True)

    # ------------------------------------------------------------------
    # Step 7 — verify saved model
    # ------------------------------------------------------------------
    print("\n[Step 7] Verify saved model", flush=True)
    X_verify = X_test[: min(1000, len(X_test))]
    verify_result = verify_saved_model(
        Path(artifacts_info["files"]["model"]),
        model,
        X_verify,
    )
    print(f"  {verify_result['status']}: {verify_result['message']}", flush=True)
    if verify_result["status"] != "PASS":
        print("[BLOCKED] Model save/load verification failed.", flush=True)
        return 1

    # ------------------------------------------------------------------
    # Step 8 — save reports
    # ------------------------------------------------------------------
    print("\n[Step 8] Save reports", flush=True)

    run_meta["artifacts"] = artifacts_info
    run_meta["dataset_sha256"] = dataset_check.get("sha256", "NOT_VERIFIED")
    run_meta["preprocessor_sha256"] = pp_artifact_sha256
    run_meta["threshold"] = threshold
    run_meta["threshold_policy"] = threshold_result["policy"]
    run_meta["unknown_attack_categories"] = sorted(UNKNOWN_ATTACK_CATEGORIES)
    run_meta["known_attack_categories"] = sorted(KNOWN_ATTACK_CATEGORIES)
    run_meta["n_train_benign"] = n_train_benign
    run_meta["feature_contract_version"] = "nf-unsw-nb15-v3-baseline-47"
    run_meta["feature_columns"] = feature_cols

    save_reports(
        metrics=test_metrics,
        threshold_calibration=threshold_result,
        per_attack_metrics=per_attack,
        run_metadata=run_meta,
        training_meta=training_meta,
        report_dir=REPORT_DIR,
    )
    print(f"  Reports saved to: {REPORT_DIR}", flush=True)

    print("\n[COMPLETE] Isolation Forest experiment EXPERIMENTALLY VALIDATED.", flush=True)
    print(
        f"  Artifacts: {MODEL_ARTIFACT_DIR}\n  Reports  : {REPORT_DIR}",
        flush=True,
    )
    return 0


def _save_blocked_report(run_meta: dict, dataset_check: dict) -> None:
    """Write a minimal BLOCKED status report when the dataset is absent."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    blocked = {
        "status": "BLOCKED",
        "reason": dataset_check["message"],
        "run_metadata": run_meta,
        "experiment_status": "IMPLEMENTED — NOT EXPERIMENTALLY VALIDATED",
        "instructions": (
            "Run `python scripts/fetch_nf_unsw_nb15_v3.py` to acquire the dataset, "
            "then run the chronological split (PR #41) and the preprocessing pipeline "
            "(PR #42) before re-running this script."
        ),
    }
    with (REPORT_DIR / "blocked_status.json").open("w") as fh:
        json.dump(blocked, fh, indent=2, default=str)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Train and evaluate Isolation Forest on NF-UNSW-NB15-v3."
    )
    parser.add_argument(
        "--check-prereqs-only",
        action="store_true",
        help="Only check prerequisites; do not train or evaluate.",
    )
    parser.add_argument(
        "--skip-checksum",
        action="store_true",
        help=(
            "Skip the dataset SHA-256 verification (faster but less safe). "
            "Use only when checksum has been verified in the current session."
        ),
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of isolation trees (default: 100).",
    )
    parser.add_argument(
        "--max-samples",
        default="auto",
        help="Max samples per tree: 'auto', int or float (default: auto).",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.1,
        help=(
            "contamination parameter passed to IsolationForest. "
            "This affects the offset_ attribute only; the actual anomaly "
            "threshold is selected on the validation set (default: 0.1)."
        ),
    )
    parser.add_argument(
        "--max-features",
        type=float,
        default=1.0,
        help="Fraction of features per tree (default: 1.0 = all features).",
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        default=False,
        help="Enable bootstrap sampling (default: False).",
    )
    parser.add_argument(
        "--n-jobs",
        type=int,
        default=-1,
        help="Parallel jobs for scikit-learn (default: -1 = all cores).",
    )
    parser.add_argument(
        "--fpr-target",
        type=float,
        default=None,
        help=(
            "Target FPR for threshold calibration. If None, the threshold "
            "maximising F1 on known-attack validation samples is selected."
        ),
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    # Validate --max-samples early
    ms = args.max_samples
    if ms != "auto":
        try:
            v = float(ms)
            args.max_samples = int(v) if v == int(v) else v
        except ValueError:
            print(f"[ERROR] --max-samples must be 'auto', an integer or a float, got: {ms!r}")
            return 2

    try:
        return run_pipeline(args)
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Training cancelled by user.", flush=True)
        return 1
    except Exception:  # noqa: BLE001
        print("\n[ERROR] Unhandled exception in pipeline:", flush=True)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
