"""Shared v2 data loading, validation calibration, shortcut audit, and evaluation helpers."""

from __future__ import annotations

import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from network_anomaly.data.split import _sha256_file, verify_split_artifacts  # noqa: E402
from network_anomaly.data.v2_schema import (  # noqa: E402
    ML_FEATURE_COLUMNS,
)
from network_anomaly.evaluation.test_evaluation import evaluate_v2_partition  # noqa: E402
from network_anomaly.models.provenance import collect_git_provenance  # noqa: E402
from network_anomaly.preprocessing.pipeline import (  # noqa: E402
    TrainOnlyPreprocessor,
    verify_preprocessing_artifact,
)

PROCESSED_V2_DIR = PROJECT_ROOT / "data" / "processed" / "v2"
SPLITS_DIR = PROCESSED_V2_DIR / "splits"
SPLIT_MANIFEST_PATH = PROJECT_ROOT / "reports" / "splits" / "v2_split_manifest.json"
PREPROC_ARTIFACT_PATH = PROJECT_ROOT / "artifacts" / "preprocessing" / "v2_flow_preprocessor.joblib"
PREPROC_MANIFEST_PATH = (
    PROJECT_ROOT / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
)


def check_v2_training_prerequisites(
    *,
    split_manifest_path: Path = SPLIT_MANIFEST_PATH,
    indices_dir: Path = SPLITS_DIR,
    preproc_artifact: Path = PREPROC_ARTIFACT_PATH,
    preproc_manifest: Path = PREPROC_MANIFEST_PATH,
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Fail-closed audit of split manifest, indices, processed datasets, and preprocessor."""
    errors: List[str] = []
    required_files = [
        PROCESSED_V2_DIR / "ait_train.csv.gz",
        PROCESSED_V2_DIR / "ait_val.csv.gz",
        PROCESSED_V2_DIR / "ait_test.csv.gz",
        PROCESSED_V2_DIR / "ctu_echo.csv.gz",
        PROCESSED_V2_DIR / "ctu_windows7ad.csv.gz",
    ]
    for rf in required_files:
        if not rf.is_file():
            errors.append(f"Missing processed v2 dataset file: {rf}")

    sm_res = verify_split_artifacts(split_manifest_path, indices_dir=indices_dir)
    if sm_res["status"] != "PASS":
        errors.extend(sm_res.get("errors", []))

    prep_res = verify_preprocessing_artifact(
        artifact_path=preproc_artifact,
        manifest_path=preproc_manifest,
        split_manifest_path=split_manifest_path,
    )
    if prep_res["status"] != "PASS":
        errors.extend(prep_res.get("errors", []))

    return (
        len(errors) == 0,
        errors,
        {
            "split_manifest": sm_res.get("manifest", {}),
            "split_manifest_sha256": (
                _sha256_file(split_manifest_path) if split_manifest_path.is_file() else None
            ),
            "preprocessor_sha256": (
                _sha256_file(preproc_artifact) if preproc_artifact.is_file() else None
            ),
        },
    )


def _read_partition_csv(path: Path) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    usecols = list(ML_FEATURE_COLUMNS) + ["label_binary", "attack_category"]
    dtypes: Dict[str, Any] = {col: np.float32 for col in ML_FEATURE_COLUMNS}
    dtypes["label_binary"] = np.int64
    dtypes["attack_category"] = str
    df = pd.read_csv(path, usecols=usecols, dtype=dtypes)
    X_raw = df[list(ML_FEATURE_COLUMNS)]
    y = df["label_binary"].to_numpy(dtype=np.int64)
    cats = df["attack_category"].to_numpy(dtype=object)
    return X_raw, y, cats


def load_v2_partitions(
    preproc: TrainOnlyPreprocessor,
    *,
    include_test: bool = True,
    include_ctu: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """Load canonical v2 partitions and transform with frozen TrainOnlyPreprocessor."""
    partitions: Dict[str, Dict[str, Any]] = {}
    items: List[Tuple[str, Path, str]] = [
        ("ait_train", PROCESSED_V2_DIR / "ait_train.csv.gz", "train"),
        ("ait_val", PROCESSED_V2_DIR / "ait_val.csv.gz", "validation"),
    ]
    if include_test:
        items.append(("ait_test", PROCESSED_V2_DIR / "ait_test.csv.gz", "test"))
    if include_ctu:
        items.append(("ctu_echo", PROCESSED_V2_DIR / "ctu_echo.csv.gz", "external_ctu_echo"))
        items.append(
            (
                "ctu_windows7ad",
                PROCESSED_V2_DIR / "ctu_windows7ad.csv.gz",
                "external_ctu_windows7ad",
            )
        )

    for key, csv_path, part_label in items:
        X_raw, y, cats = _read_partition_csv(csv_path)
        X_t = preproc.transform(X_raw, partition_name=part_label)
        partitions[key] = {
            "X": X_t,
            "y": y,
            "categories": cats,
            "csv_sha256": _sha256_file(csv_path),
            "row_count": int(len(y)),
        }
    return partitions


def audit_feature_shortcuts(
    X_val: pd.DataFrame,
    y_val: np.ndarray,
    feature_importances: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """Audit single-feature AUC on Validation and top-feature concentration to flag shortcuts."""
    single_auc: Dict[str, float] = {}
    for col in ML_FEATURE_COLUMNS:
        vals = X_val[col].to_numpy(dtype=np.float64)
        if np.std(vals) < 1e-12 or len(np.unique(y_val)) < 2:
            auc = 0.5
        else:
            raw_auc = float(roc_auc_score(y_val, vals))
            auc = max(raw_auc, 1.0 - raw_auc)
        single_auc[col] = round(auc, 6)

    sorted_auc = sorted(single_auc.items(), key=lambda kv: kv[1], reverse=True)
    max_single_feat, max_single_auc = sorted_auc[0]
    flagged_shortcuts = [k for k, v in sorted_auc if v >= 0.98]

    top_imp = []
    top2_share = None
    if feature_importances:
        sorted_imp = sorted(feature_importances.items(), key=lambda kv: kv[1], reverse=True)
        total_imp = sum(max(0.0, v) for _, v in sorted_imp) or 1.0
        top_imp = [{"feature": k, "importance": round(float(v), 6)} for k, v in sorted_imp]
        top2_share = round(sum(v for _, v in sorted_imp[:2]) / total_imp, 6)

    return {
        "evaluated_on": "ait_val (russellmitchell)",
        "single_feature_abs_auc_top5": [
            {"feature": k, "auc_symmetric": v} for k, v in sorted_auc[:5]
        ],
        "max_single_feature": max_single_feat,
        "max_single_feature_auc": max_single_auc,
        "single_feature_shortcut_flags_gte_0_98": flagged_shortcuts,
        "feature_importance_ranking": top_imp,
        "top2_importance_share": top2_share,
    }


def calibrate_unsupervised_threshold_on_validation(
    scores_val: np.ndarray,
    y_val: np.ndarray,
    *,
    target_fpr: float = 0.05,
) -> Tuple[float, Dict[str, Any], Dict[str, Any]]:
    """Select threshold strictly on Validation benign scores and build percentile curve."""
    benign_scores = np.sort(np.asarray(scores_val[y_val == 0], dtype=np.float64))
    if len(benign_scores) < 10:
        raise ValueError("Insufficient Validation benign rows for threshold calibration")

    # Guarantee empirical_val_fpr <= target_fpr under the >= threshold decision rule
    max_fp = int(np.floor(target_fpr * len(benign_scores)))
    if max_fp <= 0:
        threshold = float(np.nextafter(benign_scores[-1], np.inf))
    else:
        idx = len(benign_scores) - max_fp
        while idx < len(benign_scores) and idx > 0 and benign_scores[idx] <= benign_scores[idx - 1]:
            idx += 1
        if idx >= len(benign_scores):
            threshold = float(np.nextafter(benign_scores[-1], np.inf))
        else:
            threshold = float(benign_scores[idx])
    empirical_val_fpr = float(np.mean(benign_scores >= threshold))
    grid = [round(i / 100.0, 2) for i in range(101)]
    values = [float(np.quantile(benign_scores, q)) for q in grid]
    # Guarantee exact monotonicity against float rounding noise
    for i in range(1, len(values)):
        if values[i] < values[i - 1]:
            values[i] = values[i - 1]

    score_norm = {
        "calibration_partition": "validation",
        "score_direction": "higher_is_more_anomalous",
        "quantile_grid": grid,
        "score_values": values,
    }

    sweep = []
    for q in (0.90, 0.95, 0.97, 0.99):
        th_q = float(np.quantile(benign_scores, q))
        m_q = evaluate_v2_partition(y_true=y_val, scores=scores_val, threshold=th_q)
        sweep.append(
            {
                "benign_quantile": q,
                "threshold": th_q,
                "val_fpr": round(float(m_q["false_positive_rate"]), 6),
                "val_recall": round(float(m_q["recall"]), 6),
                "val_f1": round(float(m_q["f1"]), 6),
            }
        )

    cal_info = {
        "selected_on": "validation",
        "calibration_partition": "validation",
        "test_touched": False,
        "target_fpr": target_fpr,
        "empirical_val_fpr": empirical_val_fpr,
        "threshold": threshold,
        "threshold_frozen": True,
        "benign_val_count": int(len(benign_scores)),
        "benign_score_summary": {
            "min": float(benign_scores[0]),
            "p50": float(np.quantile(benign_scores, 0.50)),
            "p95": float(np.quantile(benign_scores, 0.95)),
            "p99": float(np.quantile(benign_scores, 0.99)),
            "max": float(benign_scores[-1]),
        },
        "quantile_sweep": sweep,
    }
    return threshold, cal_info, score_norm


def evaluate_all_splits(
    score_fn: Callable[[pd.DataFrame], np.ndarray],
    partitions: Dict[str, Dict[str, Any]],
    threshold: float,
) -> Dict[str, Any]:
    """Run timed scoring and full metrics across Validation, AIT Test, and CTU external benchmarks."""
    results: Dict[str, Any] = {}
    for key in ("ait_val", "ait_test", "ctu_echo", "ctu_windows7ad"):
        part = partitions.get(key)
        if part is None:
            continue
        t0 = time.perf_counter()
        scores = np.asarray(score_fn(part["X"]), dtype=np.float64)
        dt = time.perf_counter() - t0
        results[key] = evaluate_v2_partition(
            y_true=part["y"],
            scores=scores,
            threshold=threshold,
            attack_categories=part["categories"],
            latency_seconds=dt,
        )
        results[key]["csv_sha256"] = part["csv_sha256"]
    return results


def build_environment_block() -> Dict[str, Any]:
    git_prov = collect_git_provenance(PROJECT_ROOT)
    return {
        "python_version": platform.python_version(),
        "os": platform.platform(),
        "scikit_learn": sklearn.__version__,
        "pandas": pd.__version__,
        "numpy": np.__version__,
        "git_commit": git_prov.get("git_commit"),
        "git_dirty": git_prov.get("git_dirty"),
        "git": git_prov,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def make_run_id(model_slug: str) -> str:
    return f"v2-{model_slug}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
