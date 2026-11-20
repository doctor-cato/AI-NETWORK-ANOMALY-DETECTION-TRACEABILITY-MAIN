#!/usr/bin/env python3
"""Read-only Cross-Source Probability & Threshold Calibration Diagnostic (Phase 3 Option B).

Inspects frozen E0 RandomForest & XGBoost probability distributions across AIT-Val,
AIT-Test, CTU-SME-11, and UWF-ZeekData24 (when local raw CSVs exist) without retraining
or modifying E0 artifacts. Quantifies why ROC-AUC remains high cross-source while F1
at fixed 0.50 drops due to posterior probability shift.
"""

from __future__ import annotations

import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = PROJECT_ROOT / "src"
_SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(_SRC_DIR), str(_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from _v2_train_common import (  # noqa: E402
    PREPROC_ARTIFACT_PATH,
    PREPROC_MANIFEST_PATH,
    PROCESSED_V2_DIR,
)

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.ingestion.adapters.uwf_zeek import parse_uwf_zeek_row  # noqa: E402
from network_anomaly.models.registry import ModelRegistry  # noqa: E402
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

OUT_JSON = (
    PROJECT_ROOT / "reports" / "experiments" / "ml" / "cross_source_calibration_diagnostic.json"
)
OUT_MD = PROJECT_ROOT / "docs" / "experiments" / "CROSS_SOURCE_CALIBRATION_DIAGNOSTIC.md"

RAW_UWF_DIR = PROJECT_ROOT / "data" / "raw" / "uwf_zeekdata24"
UWF_SUBSETS = (
    "Benign",
    "Credential_Access",
    "Defense_Evasion",
    "Exfiltration",
    "Initial_Access",
    "Persistence",
    "Privilege_Escalation",
    "Reconnaissance",
)


def _metrics_at_threshold(y_true: np.ndarray, probs: np.ndarray, th: float) -> Dict[str, Any]:
    pred = probs >= th
    tp = int(np.sum((y_true == 1) & pred))
    fp = int(np.sum((y_true == 0) & pred))
    fn = int(np.sum((y_true == 1) & (~pred)))
    tn = int(np.sum((y_true == 0) & (~pred)))
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "threshold": round(float(th), 6),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }


def _prob_quantiles(arr: np.ndarray) -> Dict[str, float]:
    if arr.size == 0:
        return {}
    return {
        "p10": round(float(np.percentile(arr, 10)), 5),
        "median": round(float(np.percentile(arr, 50)), 5),
        "p90": round(float(np.percentile(arr, 90)), 5),
        "p95": round(float(np.percentile(arr, 95)), 5),
        "mean": round(float(np.mean(arr)), 5),
    }


def _load_uwf_dataframe() -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for subset in UWF_SUBSETS:
        fpath = RAW_UWF_DIR / f"{subset}.csv"
        if not fpath.is_file():
            return pd.DataFrame()
        with fpath.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            for raw_row in csv.DictReader(fh):
                try:
                    parsed = parse_uwf_zeek_row(
                        raw_row, allow_zeek_unset_zero=True, subset_name=subset
                    )
                except Exception:
                    continue
                if parsed["label_binary"] is None:
                    continue
                rec = {col: float(parsed[col]) for col in ML_FEATURE_COLUMNS}
                rec["label_binary"] = int(parsed["label_binary"])
                rows.append(rec)
    return pd.DataFrame(rows)


def main() -> int:
    t0 = time.perf_counter()
    preproc = TrainOnlyPreprocessor.load(PREPROC_ARTIFACT_PATH)
    registry = ModelRegistry(
        preprocessor_path=PREPROC_ARTIFACT_PATH,
        preprocessor_manifest_path=PREPROC_MANIFEST_PATH,
        warmup=True,
    )

    datasets: List[tuple[str, pd.DataFrame]] = []
    for key, fname in (
        ("ait_val", "ait_val.csv.gz"),
        ("ait_test", "ait_test.csv.gz"),
        ("ctu_echo", "ctu_echo.csv.gz"),
        ("ctu_windows7ad", "ctu_windows7ad.csv.gz"),
    ):
        fpath = PROCESSED_V2_DIR / fname
        df = pd.read_csv(
            fpath, usecols=list(ML_FEATURE_COLUMNS) + ["label_binary"], low_memory=False
        )
        datasets.append((key, df))

    uwf_df = _load_uwf_dataframe()
    if len(uwf_df) > 0:
        datasets.append(("uwf_zeekdata24", uwf_df))

    # Pre-transform once
    transformed: Dict[str, tuple[np.ndarray, np.ndarray]] = {}
    for dname, df in datasets:
        X_s = preproc.transform(df[list(ML_FEATURE_COLUMNS)], partition_name=dname).to_numpy(
            dtype=np.float64
        )
        y = df["label_binary"].to_numpy(dtype=np.int64)
        transformed[dname] = (X_s, y)

    per_model: Dict[str, Any] = {}
    for model_key in ("random_forest", "xgboost"):
        # Compute AIT-Val Youden J & benign p95 threshold strictly on validation
        X_val, y_val = transformed["ait_val"]
        p_val, _ = registry.score_batch(model_key, X_val)
        fpr_c, tpr_c, th_c = roc_curve(y_val, p_val)
        youden_idx = int(np.argmax(tpr_c - fpr_c))
        val_youden_th = float(th_c[youden_idx])
        val_ben_p95_th = float(np.percentile(p_val[y_val == 0], 95))

        d_results: Dict[str, Any] = {}
        for dname, (X_np, y_np) in transformed.items():
            probs, _ = registry.score_batch(model_key, X_np)
            auc = float(roc_auc_score(y_np, probs)) if len(np.unique(y_np)) == 2 else None
            # Diagnostic-only target benign p95 quantile (never claimed as zero-shot)
            target_ben_p95 = float(np.percentile(probs[y_np == 0], 95))
            d_results[dname] = {
                "row_count": int(len(y_np)),
                "roc_auc": round(auc, 4) if auc is not None else None,
                "prob_distribution_benign": _prob_quantiles(probs[y_np == 0]),
                "prob_distribution_attack": _prob_quantiles(probs[y_np == 1]),
                "zero_shot_default_0_50": _metrics_at_threshold(y_np, probs, 0.50),
                "zero_shot_ait_val_youden": _metrics_at_threshold(y_np, probs, val_youden_th),
                "zero_shot_ait_val_benign_p95": _metrics_at_threshold(y_np, probs, val_ben_p95_th),
                "diagnostic_target_benign_p95_non_zeroshot": _metrics_at_threshold(
                    y_np, probs, target_ben_p95
                ),
            }
        per_model[model_key] = {
            "ait_val_youden_threshold": round(val_youden_th, 6),
            "ait_val_benign_p95_threshold": round(val_ben_p95_th, 6),
            "datasets": d_results,
        }

    report = {
        "diagnostic_id": "DIAG-CALIBRATION-XSRC-01",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.perf_counter() - t0, 2),
        "read_only_e0": True,
        "models": per_model,
        "limitations": [
            "target_benign_p95 uses unlabeled/benign quantile on the destination distribution purely as a diagnostic upper bound for threshold sensitivity; it MUST NOT be reported as zero-shot.",
            "E0 threshold manifests remain untouched.",
        ],
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")

    md_lines = [
        "# Cross-Source Probability Shift & Threshold Calibration Diagnostic (Read-Only `E0`)",
        "",
        f"- **Executed At (UTC):** `{report['executed_at_utc']}` | **Elapsed:** `{report['elapsed_seconds']}s`",
        "",
        "| Model | Dataset | ROC-AUC | Attack Prob Median | F1 @ `0.50` (Zero-Shot) | F1 @ `AIT-Val Youden` (Zero-Shot) | F1 @ `Target Benign P95` (Diagnostic) |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for mkey, mdata in per_model.items():
        for dname, dstats in mdata["datasets"].items():
            atk_med = dstats["prob_distribution_attack"].get("median", 0.0)
            f1_def = dstats["zero_shot_default_0_50"]["f1"]
            f1_youd = dstats["zero_shot_ait_val_youden"]["f1"]
            f1_diag = dstats["diagnostic_target_benign_p95_non_zeroshot"]["f1"]
            md_lines.append(
                f"| `{mkey}` | `{dname}` | {dstats['roc_auc']:.4f} | {atk_med:.4f} | {f1_def:.4f} | {f1_youd:.4f} | {f1_diag:.4f} |"
            )
    md_lines.extend(["", "## Limitations", *[f"- {lim}" for lim in report["limitations"]]])
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
    print(f"[done] Cross-source calibration diagnostic written: {OUT_JSON} and {OUT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
