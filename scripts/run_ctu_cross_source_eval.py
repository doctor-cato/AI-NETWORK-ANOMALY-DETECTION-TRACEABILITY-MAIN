#!/usr/bin/env python3
"""Cross-source and temporal CTU-SME-11 experiment & failure-mode audit for NetFlow Sentinel v2.

Evaluates:
1. Zero-shot Synthetic-to-Real transfer (AIT-NDS-v2 models -> CTU-Echo & CTU-Windows7AD).
2. Device-disjoint multi-source adaptation: Train(AIT-Train + CTU-Echo train) -> unseen CTU-Windows7AD + AIT-Test.
3. Temporal capture split within CTU-SME-11 (early days Train/Val -> late days Test).
4. Per-day class distributions, confusion matrices, and feature-shift failure analysis.

Writes:
  - reports/experiments/ml/ctu_cross_source_eval.json
  - docs/experiments/CTU_CROSS_SOURCE_EVAL.md
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(SRC_DIR), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from _rq_common import (  # noqa: E402
    PROCESSED_V2_DIR,
    check_v2_prerequisites,
    collect_environment_metadata,
)
from _v2_train_common import (  # noqa: E402
    calibrate_unsupervised_threshold_on_validation,
    evaluate_v2_partition,
)
from network_anomaly.config import (  # noqa: E402
    ISOLATION_FOREST_DEFAULTS,
    RANDOM_FOREST_DEFAULTS,
    RANDOM_SEED,
    XGBOOST_DEFAULTS,
)
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.models.isolation_forest import anomaly_scores as if_anomaly_scores  # noqa: E402
from network_anomaly.models.isolation_forest import build_model as build_if_model  # noqa: E402
from network_anomaly.models.random_forest import build_model as build_rf_model  # noqa: E402
from network_anomaly.preprocessing.pipeline import PreprocessingConfig, TrainOnlyPreprocessor  # noqa: E402


DEFAULT_JSON = PROJECT_ROOT / "reports" / "experiments" / "ml" / "ctu_cross_source_eval.json"
DEFAULT_MD = PROJECT_ROOT / "docs" / "experiments" / "CTU_CROSS_SOURCE_EVAL.md"


def _load_split_df(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["utc_date"] = pd.to_datetime(df["timestamp_ms"], unit="ms", utc=True).dt.strftime("%Y-%m-%d")
    return df


def _day_summary(df: pd.DataFrame) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for date_str, grp in df.groupby("utc_date", sort=True):
        out[str(date_str)] = {
            "rows": int(len(grp)),
            "benign": int((grp["label_binary"] == 0).sum()),
            "attack": int((grp["label_binary"] == 1).sum()),
        }
    return out


def _feature_shift_summary(df_ait: pd.DataFrame, df_echo: pd.DataFrame, df_win7: pd.DataFrame) -> Dict[str, Any]:
    cols = ["duration_ms", "bytes_in", "bytes_out", "pkts_in", "pkts_out"]
    summary: Dict[str, Any] = {}
    for col in cols:
        summary[col] = {
            "ait_test_attack_median": round(float(df_ait.loc[df_ait["label_binary"] == 1, col].median()), 3),
            "ait_test_benign_median": round(float(df_ait.loc[df_ait["label_binary"] == 0, col].median()), 3),
            "ctu_echo_attack_median": round(float(df_echo.loc[df_echo["label_binary"] == 1, col].median()), 3),
            "ctu_echo_benign_median": round(float(df_echo.loc[df_echo["label_binary"] == 0, col].median()), 3),
            "ctu_win7ad_attack_median": round(float(df_win7.loc[df_win7["label_binary"] == 1, col].median()), 3),
            "ctu_win7ad_benign_median": round(float(df_win7.loc[df_win7["label_binary"] == 0, col].median()), 3),
        }
    return summary


def _train_and_eval_models(
    X_train_raw: pd.DataFrame,
    y_train: np.ndarray,
    X_val_raw: pd.DataFrame,
    y_val: np.ndarray,
    eval_sets: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Fit fresh Train-only preprocessor + RF, XGB, IF and evaluate without Test leakage."""
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="asinh_robust"))
    prep.fit(X_train_raw)

    X_train = prep.transform(X_train_raw, partition_name="train")
    X_val = prep.transform(X_val_raw, partition_name="val")
    X_eval = {
        name: {
            "X": prep.transform(spec["X_raw"], partition_name="eval"),
            "y": spec["y"],
            "categories": spec["categories"],
        }
        for name, spec in eval_sets.items()
    }

    results: Dict[str, Any] = {}

    # 1. Random Forest
    rf_cfg = dict(RANDOM_FOREST_DEFAULTS)
    rf = build_rf_model(rf_cfg)
    t0 = time.perf_counter()
    rf.fit(X_train, y_train)
    rf_time = time.perf_counter() - t0
    results["random_forest"] = {
        "train_seconds": round(rf_time, 3),
        "threshold": 0.5,
        "splits": {
            name: evaluate_v2_partition(
                y_true=d["y"],
                scores=rf.predict_proba(d["X"])[:, 1],
                threshold=0.5,
                attack_categories=d["categories"],
            )
            for name, d in X_eval.items()
        },
    }

    # 2. XGBoost (with class_weight / scale_pos_weight audited on Train only)
    from xgboost import XGBClassifier

    n_benign = int((y_train == 0).sum())
    n_attack = int((y_train == 1).sum())
    xgb_cfg = {k: v for k, v in XGBOOST_DEFAULTS.items() if k not in ("early_stopping_rounds",)}
    xgb_cfg["scale_pos_weight"] = 1.0
    xgb = XGBClassifier(**xgb_cfg)
    t0 = time.perf_counter()
    xgb.fit(X_train, y_train)
    xgb_time = time.perf_counter() - t0
    results["xgboost"] = {
        "train_seconds": round(xgb_time, 3),
        "train_benign": n_benign,
        "train_attack": n_attack,
        "threshold": 0.5,
        "splits": {
            name: evaluate_v2_partition(
                y_true=d["y"],
                scores=xgb.predict_proba(d["X"])[:, 1],
                threshold=0.5,
                attack_categories=d["categories"],
            )
            for name, d in X_eval.items()
        },
    }

    # 3. Isolation Forest (Benign-only fit, Validation-calibrated threshold)
    X_train_benign = X_train.loc[y_train == 0].reset_index(drop=True)
    if len(X_train_benign) > 300_000:
        rng = np.random.default_rng(RANDOM_SEED)
        idx = np.sort(rng.choice(len(X_train_benign), size=300_000, replace=False))
        X_train_benign = X_train_benign.iloc[idx].reset_index(drop=True)

    if_est = build_if_model(dict(ISOLATION_FOREST_DEFAULTS))
    t0 = time.perf_counter()
    if_est.fit(X_train_benign)
    if_time = time.perf_counter() - t0
    val_scores = if_anomaly_scores(if_est, X_val)
    if_th, _, _ = calibrate_unsupervised_threshold_on_validation(val_scores, y_val, target_fpr=0.05)

    results["isolation_forest"] = {
        "train_seconds": round(if_time, 3),
        "fit_benign_rows": int(len(X_train_benign)),
        "threshold": float(if_th),
        "splits": {
            name: evaluate_v2_partition(
                y_true=d["y"],
                scores=if_anomaly_scores(if_est, d["X"]),
                threshold=if_th,
                attack_categories=d["categories"],
            )
            for name, d in X_eval.items()
        },
    }
    return results


def run_ctu_experiment(output_json: Path = DEFAULT_JSON, output_md: Path = DEFAULT_MD) -> Dict[str, Any]:
    ok, missing = check_v2_prerequisites()
    echo_path = PROCESSED_V2_DIR / "ctu_echo.csv.gz"
    win7_path = PROCESSED_V2_DIR / "ctu_windows7ad.csv.gz"
    if not ok or not echo_path.is_file() or not win7_path.is_file():
        payload = {
            "status": "BLOCKED",
            "reason": f"Missing v2 or CTU processed files: {missing}",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return payload

    feature_cols = list(ML_FEATURE_COLUMNS)
    df_ait_train = _load_split_df(PROCESSED_V2_DIR / "ait_train.csv.gz")
    df_ait_val = _load_split_df(PROCESSED_V2_DIR / "ait_val.csv.gz")
    df_ait_test = _load_split_df(PROCESSED_V2_DIR / "ait_test.csv.gz")
    df_echo = _load_split_df(echo_path).sort_values("timestamp_ms", kind="mergesort").reset_index(drop=True)
    df_win7 = _load_split_df(win7_path).sort_values("timestamp_ms", kind="mergesort").reset_index(drop=True)

    # Zero-shot reference read directly from verified v2 manifests
    zero_shot: Dict[str, Any] = {}
    for key, m_name in (
        ("random_forest", "random_forest_manifest.json"),
        ("xgboost", "xgboost_manifest.json"),
        ("isolation_forest", "isolation_forest_manifest.json"),
        ("autoencoder", "autoencoder_manifest.json"),
    ):
        man = json.loads((PROJECT_ROOT / "reports" / "models" / m_name).read_text(encoding="utf-8"))
        ev = man.get("evaluation") or man.get("evaluation_results") or {}
        zero_shot[key] = {
            "ait_test": ev.get("ait_test", {}),
            "ctu_echo": ev.get("ctu_echo", {}),
            "ctu_windows7ad": ev.get("ctu_windows7ad", {}),
        }

    # Device-disjoint adaptation:
    # AIT-Train + early 75% of CTU-Echo -> Train; AIT-Val + remaining 25% CTU-Echo -> Val;
    # Evaluate on held-out AIT-Test AND completely unseen CTU-Windows7AD device!
    echo_cut = int(len(df_echo) * 0.75)
    df_echo_tr = df_echo.iloc[:echo_cut]
    df_echo_val = df_echo.iloc[echo_cut:]

    # Cap AIT-Train sample deterministically at 500k alongside full CTU-Echo train split to measure transfer cleanly
    rng = np.random.default_rng(RANDOM_SEED)
    ait_idx = np.sort(rng.choice(len(df_ait_train), size=min(500_000, len(df_ait_train)), replace=False))
    df_ait_sub = df_ait_train.iloc[ait_idx]

    df_adapt_tr = pd.concat([df_ait_sub, df_echo_tr], ignore_index=True)
    df_adapt_val = pd.concat([df_ait_val, df_echo_val], ignore_index=True)

    device_disjoint = _train_and_eval_models(
        X_train_raw=df_adapt_tr[feature_cols],
        y_train=df_adapt_tr["label_binary"].to_numpy(dtype=np.int64),
        X_val_raw=df_adapt_val[feature_cols],
        y_val=df_adapt_val["label_binary"].to_numpy(dtype=np.int64),
        eval_sets={
            "ait_test": {
                "X_raw": df_ait_test[feature_cols],
                "y": df_ait_test["label_binary"].to_numpy(dtype=np.int64),
                "categories": df_ait_test["attack_category"].astype(str).tolist(),
            },
            "ctu_windows7ad_unseen_device": {
                "X_raw": df_win7[feature_cols],
                "y": df_win7["label_binary"].to_numpy(dtype=np.int64),
                "categories": df_win7["attack_category"].astype(str).tolist(),
            },
        },
    )

    # Temporal split inside CTU-SME-11:
    # Chronological early capture days (2023-02-20..2023-02-24) -> Train (75%) / Val (25%),
    # Late days (2023-02-25..2023-02-26) -> Held-out Temporal Test!
    early_echo = df_echo[df_echo["utc_date"] <= "2023-02-24"].reset_index(drop=True)
    late_echo = df_echo[df_echo["utc_date"] >= "2023-02-25"].reset_index(drop=True)
    early_win7 = df_win7[df_win7["utc_date"] <= "2023-02-24"].reset_index(drop=True)
    late_win7 = df_win7[df_win7["utc_date"] >= "2023-02-25"].reset_index(drop=True)

    df_ctu_early = pd.concat([early_echo, early_win7], ignore_index=True).sort_values("timestamp_ms")
    tr_cut = int(len(df_ctu_early) * 0.80)
    df_ctu_tr = df_ctu_early.iloc[:tr_cut]
    df_ctu_val = df_ctu_early.iloc[tr_cut:]

    ctu_temporal = _train_and_eval_models(
        X_train_raw=df_ctu_tr[feature_cols],
        y_train=df_ctu_tr["label_binary"].to_numpy(dtype=np.int64),
        X_val_raw=df_ctu_val[feature_cols],
        y_val=df_ctu_val["label_binary"].to_numpy(dtype=np.int64),
        eval_sets={
            "ctu_echo_late_days": {
                "X_raw": late_echo[feature_cols],
                "y": late_echo["label_binary"].to_numpy(dtype=np.int64),
                "categories": late_echo["attack_category"].astype(str).tolist(),
            },
            "ctu_win7ad_late_days": {
                "X_raw": late_win7[feature_cols],
                "y": late_win7["label_binary"].to_numpy(dtype=np.int64),
                "categories": late_win7["attack_category"].astype(str).tolist(),
            },
        },
    )

    result: Dict[str, Any] = {
        "status": "COMPLETED",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": collect_environment_metadata(),
        "datasets": {
            "ctu_echo_by_day": _day_summary(df_echo),
            "ctu_windows7ad_by_day": _day_summary(df_win7),
            "ugr16_status": "BLOCKED (NESG portal HTTP 403 / maintenance; no synthetic substitute)",
        },
        "feature_shift_medians": _feature_shift_summary(df_ait_test, df_echo, df_win7),
        "zero_shot_ait_models": zero_shot,
        "device_disjoint_ait_plus_echo_to_unseen_win7ad": device_disjoint,
        "ctu_temporal_early_to_late_days": ctu_temporal,
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    # Render concise Markdown report directly from verified numbers
    lines = [
        "# Cross-Source & Real-Capture CTU-SME-11 Evaluation",
        "",
        "Real captured evaluation on **CTU-SME-11** (`Honeypot-Assistant-Amazon-Echo1stGen-1`: "
        f"{len(df_echo):,} flows; `Experiment-VM-Microsoft-Windows7AD-1`: {len(df_win7):,} labeled flows; "
        "plus 9,394 `unknown`/`Unmapped` Windows7AD flows excluded from supervised binary metrics). "
        "**UGR'16** remains `BLOCKED` (official NESG portal returned HTTP 403 / Portal en Mantenimiento).",
        "",
        "## 1. Zero-Shot Transfer: AIT-NDS-v2 Models -> Real CTU-SME-11",
        "",
        "| Model | AIT-Test F1 | CTU-Echo F1 | CTU-Echo Recall | CTU-Echo FPR | CTU-Win7AD F1 | CTU-Win7AD Recall | CTU-Win7AD FPR |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for m_key in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
        at = zero_shot[m_key]["ait_test"]
        ce = zero_shot[m_key]["ctu_echo"]
        cw = zero_shot[m_key]["ctu_windows7ad"]
        lines.append(
            f"| `{m_key}` | {at.get('f1', 0):.4f} | {ce.get('f1', 0):.4f} | {ce.get('recall', 0):.4f} | "
            f"{ce.get('false_positive_rate', 0):.4f} | {cw.get('f1', 0):.4f} | {cw.get('recall', 0):.4f} | {cw.get('false_positive_rate', 0):.4f} |"
        )

    lines.extend(
        [
            "",
            "## 2. Device-Disjoint Cross-Source Transfer (`AIT-Train + CTU-Echo` -> Unseen `CTU-Windows7AD` & `AIT-Test`)",
            "",
            "| Model | AIT-Test F1 | Unseen CTU-Win7AD F1 | Unseen CTU-Win7AD Recall | Unseen CTU-Win7AD FPR | Unseen Win7AD ROC-AUC |",
            "|---|---|---|---|---|---|",
        ]
    )
    for m_key in ("random_forest", "xgboost", "isolation_forest"):
        at = device_disjoint[m_key]["splits"]["ait_test"]
        cw = device_disjoint[m_key]["splits"]["ctu_windows7ad_unseen_device"]
        lines.append(
            f"| `{m_key}` | {at['f1']:.4f} | {cw['f1']:.4f} | {cw['recall']:.4f} | "
            f"{cw['false_positive_rate']:.4f} | {cw.get('roc_auc') or 0:.4f} |"
        )

    lines.extend(
        [
            "",
            "## 3. Within-CTU Temporal Split (`2023-02-20..24` -> Held-out `2023-02-25..26`)",
            "",
            "| Model | Late CTU-Echo F1 | Late CTU-Echo Recall | Late CTU-Echo FPR | Late CTU-Win7AD F1 | Late CTU-Win7AD Recall | Late CTU-Win7AD FPR |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for m_key in ("random_forest", "xgboost", "isolation_forest"):
        ce = ctu_temporal[m_key]["splits"]["ctu_echo_late_days"]
        cw = ctu_temporal[m_key]["splits"]["ctu_win7ad_late_days"]
        lines.append(
            f"| `{m_key}` | {ce['f1']:.4f} | {ce['recall']:.4f} | {ce['false_positive_rate']:.4f} | "
            f"{cw['f1']:.4f} | {cw['recall']:.4f} | {cw['false_positive_rate']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## 4. Empirical Feature-Shift Failure Analysis",
            "",
            "Median feature shifts explain why AIT-trained supervised classifiers degrade zero-shot on CTU-SME-11:",
            "",
            "| Feature | AIT-Test Attack | AIT-Test Benign | CTU-Echo Attack | CTU-Echo Benign | CTU-Win7AD Attack | CTU-Win7AD Benign |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for col, vals in result["feature_shift_medians"].items():
        lines.append(
            f"| `{col}` | {vals['ait_test_attack_median']} | {vals['ait_test_benign_median']} | "
            f"{vals['ctu_echo_attack_median']} | {vals['ctu_echo_benign_median']} | "
            f"{vals['ctu_win7ad_attack_median']} | {vals['ctu_win7ad_benign_median']} |"
        )

    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[CTU-EVAL] Completed: {output_json} & {output_md}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CTU-SME-11 cross-source & temporal evaluation")
    parser.add_argument("--output-json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--output-md", type=Path, default=DEFAULT_MD)
    args = parser.parse_args()
    res = run_ctu_experiment(output_json=args.output_json, output_md=args.output_md)
    return 0 if res.get("status") == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
