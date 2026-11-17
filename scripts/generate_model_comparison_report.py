#!/usr/bin/env python3
"""Empirical 4-Model Comparison Report Generator (RQ1 / Issue #105).

Evaluates the four verified model artifacts (Random Forest, XGBoost, Isolation
Forest, Autoencoder) on the same NF-UNSW-NB15-v3 test partition using the same
train-only preprocessor. Fails closed to BLOCKED status if raw data or model
artifacts are missing; never outputs hardcoded performance metrics.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

_SCRIPTS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPTS_DIR.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from _rq_common import (  # noqa: E402
    check_nf_unsw_prerequisites,
    collect_environment_metadata,
    compute_binary_metrics,
    dataset_provenance_summary,
    load_partition_raw,
    load_verified_preprocessor,
)

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.models.registry import MODEL_KEYS, ModelRegistry  # noqa: E402

OUTPUT_JSON = Path("reports/experiments/ml/model_comparison_report.json")
OUTPUT_MD = Path("docs/experiments/FOUR_MODEL_COMPARISON.md")


def _extract_top_features(model_key: str, model_obj: Any, top_k: int = 5) -> List[Dict[str, Any]]:
    if model_obj is None:
        return []
    importances = getattr(model_obj, "feature_importances_", None)
    if importances is None and hasattr(model_obj, "estimator"):
        importances = getattr(model_obj.estimator, "feature_importances_", None)
    if importances is None:
        return []
    arr = np.asarray(importances, dtype=float)
    if len(arr) != len(ML_FEATURE_COLUMNS):
        return []
    order = np.argsort(arr)[::-1][:top_k]
    return [
        {
            "feature": ML_FEATURE_COLUMNS[int(idx)],
            "importance": round(float(arr[int(idx)]), 6),
        }
        for idx in order
    ]


def generate_comparison_report(
    max_rows: Optional[int] = None,
    output_json: Path = OUTPUT_JSON,
    output_md: Path = OUTPUT_MD,
) -> Dict[str, Any]:
    """Run empirical 4-model evaluation on NF-UNSW-NB15-v3 test split."""
    env = collect_environment_metadata()
    provenance = dataset_provenance_summary()
    ok_data, missing_paths = check_nf_unsw_prerequisites()
    registry = ModelRegistry(warmup=True)

    missing_models = [st.model_key for st in registry.statuses() if not st.decision_ready]

    if not ok_data or missing_models:
        blocked = {
            "experiment_id": "EXP-RQ1-4MODEL-COMPARISON",
            "status": "BLOCKED",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "dataset_provenance": provenance,
            "environment": env,
            "blocked_reasons": {
                "missing_data_files": missing_paths,
                "unready_models": missing_models,
            },
            "models": {},
            "limitations": [
                "Cannot compute empirical 4-model comparison without raw NF-UNSW-NB15-v3 dataset and all 4 verified model artifacts."
            ],
        }
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(blocked, indent=2) + "\n", encoding="utf-8")
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(
            "# RQ1 — 4-Model Empirical Comparison (BLOCKED)\n\n"
            f"- Missing data files: `{missing_paths}`\n"
            f"- Unready models: `{missing_models}`\n",
            encoding="utf-8",
        )
        return blocked

    preprocessor = load_verified_preprocessor()
    X_test_raw, y_test, attack_test = load_partition_raw("test", max_rows=max_rows)
    X_test_df = preprocessor.transform(X_test_raw, partition_name="test")
    X_test_np = X_test_df.to_numpy(dtype=float)

    models_payload: Dict[str, Any] = {}
    for key in MODEL_KEYS:
        st = registry.status(key)
        assert st is not None
        t0 = time.perf_counter()
        raw_scores, y_pred = registry.score_batch(key, X_test_np)
        elapsed_s = max(1e-9, time.perf_counter() - t0)
        metrics = compute_binary_metrics(y_test, y_pred, y_score=raw_scores)
        disk_mb = round(Path(st.artifact_path).stat().st_size / (1024 * 1024), 4)
        top_feats = _extract_top_features(key, registry.model_object(key))
        protocol = (
            "supervised_binary_classification (trained on Train Ben+Attack; threshold on probability)"
            if key in ("random_forest", "xgboost")
            else (
                "unsupervised_anomaly_detection (trained on Train Benign-only; "
                f"threshold_source={st.threshold_source})"
            )
        )
        models_payload[key] = {
            "display_name": st.display_name,
            "model_type": st.model_type,
            "evaluation_protocol": protocol,
            "artifact_path": st.artifact_path,
            "artifact_sha256": st.artifact_sha256,
            "model_disk_size_mb": disk_mb,
            "decision_threshold": st.threshold,
            "threshold_source": st.threshold_source,
            "score_semantics": st.score_semantics,
            "metrics": metrics,
            "operational_characteristics": {
                "batch_elapsed_seconds": round(elapsed_s, 4),
                "avg_inference_latency_us": round((elapsed_s / len(y_test)) * 1e6, 3),
                "throughput_flows_sec": round(len(y_test) / elapsed_s, 2),
            },
            "explainability": {
                "top_features": top_feats,
            },
        }

    # Rank supervised and unsupervised empirically from measured results
    best_sup = max(
        ("random_forest", "xgboost"),
        key=lambda k: models_payload[k]["metrics"]["f1"],
    )
    best_unsup = max(
        ("isolation_forest", "autoencoder"),
        key=lambda k: models_payload[k]["metrics"]["f1"],
    )

    results: Dict[str, Any] = {
        "experiment_id": "EXP-RQ1-4MODEL-COMPARISON",
        "status": "COMPLETED",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_provenance": provenance,
        "evaluation_partition": "test",
        "sample_count": int(len(y_test)),
        "max_rows_cap": max_rows,
        "attack_class_support": {str(k): int(v) for k, v in attack_test.value_counts().items()},
        "environment": env,
        "models": models_payload,
        "synthesis": {
            "best_supervised_by_f1": best_sup,
            "best_unsupervised_by_f1": best_unsup,
        },
        "limitations": [
            "NF-UNSW-NB15-v3 contains strong MIN_TTL separation between benign and attack traffic; high supervised F1 partially reflects testbed topology.",
            "Supervised and unsupervised models follow different training and threshold calibration protocols and must be compared with protocol awareness.",
            "Batch throughput reflects offline vectorized inference on this host and does not directly measure live network line-rate capacity.",
        ],
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    # Render Markdown directly from computed results
    rows = []
    for key in MODEL_KEYS:
        m = models_payload[key]
        met = m["metrics"]
        op = m["operational_characteristics"]
        roc = f"{met['roc_auc']:.4f}" if met["roc_auc"] is not None else "N/A"
        pr = f"{met['pr_auc']:.4f}" if met["pr_auc"] is not None else "N/A"
        rows.append(
            f"| {m['display_name']} | {met['precision']:.4f} | {met['recall']:.4f} | "
            f"{met['f1']:.4f} | {met['macro_f1']:.4f} | {met['false_positive_rate']:.6f} | "
            f"{roc} | {pr} | {op['avg_inference_latency_us']:.2f} us | {op['throughput_flows_sec']:,.1f} flow/s |"
        )

    md_lines = [
        "# RQ1 — 4-Model Empirical Comparison Report (NF-UNSW-NB15-v3)",
        "",
        f"- **Status:** `{results['status']}`",
        f"- **Generated At (UTC):** `{results['generated_at_utc']}`",
        f"- **Dataset:** `{provenance['dataset_id']}` (SHA-256: `{provenance['dataset_sha256']}`)",
        f"- **Split Protocol:** `{provenance['split_protocol']}` (`test`, N={results['sample_count']:,})",
        f"- **Random Seed:** `{env['random_seed']}`",
        "",
        "## 1. Empirical Test Metrics (Same Preprocessing & Split)",
        "",
        "| Model | Precision | Recall | F1 | Macro-F1 | FPR | ROC-AUC | PR-AUC | Avg Latency | Throughput |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        *rows,
        "",
        "## 2. Evaluation Protocols & Artifact Hashes",
        "",
    ]
    for key in MODEL_KEYS:
        m = models_payload[key]
        md_lines.append(
            f"- **{m['display_name']}**: `{m['evaluation_protocol']}`, "
            f"threshold=`{m['decision_threshold']}`, sha256=`{m['artifact_sha256']}`"
        )
    md_lines.extend(["", "## 3. Limitations", ""])
    for lim in results["limitations"]:
        md_lines.append(f"- {lim}")

    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"RQ1 model comparison generated: {output_json} and {output_md}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="RQ1 4-Model Comparison on NF-UNSW-NB15-v3")
    parser.add_argument(
        "--max-rows", type=int, default=None, help="Optional row cap for quick test"
    )
    args = parser.parse_args()
    res = generate_comparison_report(max_rows=args.max_rows)
    if res["status"] != "COMPLETED":
        sys.exit(1)


if __name__ == "__main__":
    main()
