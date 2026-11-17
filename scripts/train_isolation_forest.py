#!/usr/bin/env python3
"""Train Isolation Forest unsupervised anomaly detector on NetFlow Sentinel v2."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = PROJECT_ROOT / "src"
_SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(_SRC_DIR), str(_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from _v2_train_common import (  # noqa: E402
    PREPROC_ARTIFACT_PATH,
    SPLIT_MANIFEST_PATH,
    audit_feature_shortcuts,
    build_environment_block,
    calibrate_unsupervised_threshold_on_validation,
    check_v2_training_prerequisites,
    evaluate_all_splits,
    load_v2_partitions,
    make_run_id,
)
from network_anomaly.data.v2_schema import (  # noqa: E402
    FEATURE_CONTRACT_ID,
    ML_FEATURE_COLUMNS,
)
from network_anomaly.models.isolation_forest import IsolationForestModel  # noqa: E402
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

MODEL_ARTIFACT_PATH = PROJECT_ROOT / "artifacts" / "models" / "isolation_forest" / "isolation_forest.joblib"
MODEL_SIDECAR_MANIFEST = PROJECT_ROOT / "artifacts" / "models" / "isolation_forest" / "isolation_forest_manifest.json"
REPORT_MANIFEST_PATH = PROJECT_ROOT / "reports" / "models" / "isolation_forest_manifest.json"
EVAL_REPORT_JSON = PROJECT_ROOT / "reports" / "evaluation" / "isolation_forest_v2_eval.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Isolation Forest v2 model")
    parser.add_argument("--verify-only", action="store_true", help="Exit 0 SKIPPED if datasets absent")
    parser.add_argument("--target-fpr", type=float, default=0.05, help="Validation Benign target FPR")
    args = parser.parse_args()

    ok, errors, info = check_v2_training_prerequisites()
    if not ok:
        if args.verify_only:
            print("[train_isolation_forest] SKIPPED — prerequisites missing:", "; ".join(errors[:2]))
            return
        print("ERROR: Prerequisite failure:\n  " + "\n  ".join(errors), file=sys.stderr)
        sys.exit(1)

    split_man = info["split_manifest"]
    split_sha = info["split_manifest_sha256"]
    prep_sha = info["preprocessor_sha256"]
    dataset_sha = split_man["dataset_sha256"]

    preproc = TrainOnlyPreprocessor.load_verified(
        artifact_path=PREPROC_ARTIFACT_PATH,
        manifest_path=PROJECT_ROOT / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json",
        split_manifest_path=SPLIT_MANIFEST_PATH,
    )
    partitions = load_v2_partitions(preproc, include_test=True, include_ctu=True)

    # Strictly fit ONLY on Benign flows from AIT Train
    X_train_all = partitions["ait_train"]["X"]
    y_train_all = partitions["ait_train"]["y"]
    benign_mask = y_train_all == 0
    X_train_benign = X_train_all.loc[benign_mask].reset_index(drop=True)

    run_id = make_run_id("if")
    model = IsolationForestModel(
        config={
            "n_estimators": 200,
            "max_samples": 512,
            "contamination": 0.05,
            "max_features": 1.0,
            "bootstrap": False,
            "random_state": 42,
            "n_jobs": -1,
        }
    )
    print(f"[IF] Fitting IsolationForest strictly on {len(X_train_benign):,} AIT Benign Train flows...", flush=True)
    t0 = time.perf_counter()
    model.fit(X_train_benign)
    train_seconds = time.perf_counter() - t0
    print(f"[IF] Fit completed in {train_seconds:.2f}s", flush=True)

    # Calibrate anomaly threshold strictly on Validation (russellmitchell)
    X_val = partitions["ait_val"]["X"]
    y_val = partitions["ait_val"]["y"]
    val_scores = model.anomaly_scores(X_val)
    threshold, cal_info, score_norm = calibrate_unsupervised_threshold_on_validation(
        val_scores, y_val, target_fpr=args.target_fpr
    )
    model.threshold = threshold

    evals = evaluate_all_splits(
        lambda X_df: model.anomaly_scores(X_df),
        partitions,
        threshold=threshold,
    )
    shortcut_audit = audit_feature_shortcuts(X_val, y_val)

    extra_fields: Dict[str, Any] = {
        "training_run_id": run_id,
        "run_id": run_id,
        "dataset_name": "AIT-NDS-v2",
        "dataset_provenance": (
            "AIT-NDS-v2 (10.5281/zenodo.13168643); Benign-only Train={fox,harrison,santos,wardbeck,wilson}"
        ),
        "dataset_sha256": dataset_sha,
        "fit_population": {
            "partition": "ait_train",
            "benign_only": True,
            "fit_row_count": int(len(X_train_benign)),
            "excluded_attack_rows_during_fit": int((~benign_mask).sum()),
        },
        "threshold_source": f"validation_benign_quantile_{1.0 - args.target_fpr:.2f}",
        "threshold_provenance": {
            "selected_on": "validation",
            "test_touched": False,
            "target_fpr": args.target_fpr,
        },
        "threshold_calibration": cal_info,
        "score_normalization": score_norm,
        "training_duration_seconds": round(train_seconds, 3),
        "shortcut_audit": shortcut_audit,
        "evaluation": evals,
        "environment": build_environment_block(),
    }

    model_sha = model.save(
        MODEL_ARTIFACT_PATH,
        manifest_path=REPORT_MANIFEST_PATH,
        preprocessor_artifact_sha256=prep_sha,
        split_manifest_sha256=split_sha,
        feature_contract_version=FEATURE_CONTRACT_ID,
        evaluation_summary=evals,
        extra_manifest_fields=extra_fields,
        metadata={"run_id": run_id, "feature_names": list(ML_FEATURE_COLUMNS)},
    )
    model_size_bytes = MODEL_ARTIFACT_PATH.stat().st_size
    manifest_obj = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest_obj["model_size_bytes"] = model_size_bytes
    REPORT_MANIFEST_PATH.write_text(json.dumps(manifest_obj, indent=2) + "\n", encoding="utf-8")
    MODEL_SIDECAR_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MODEL_SIDECAR_MANIFEST.write_text(json.dumps(manifest_obj, indent=2) + "\n", encoding="utf-8")

    reloaded = IsolationForestModel.load_verified(
        MODEL_ARTIFACT_PATH,
        REPORT_MANIFEST_PATH,
        expected_preprocessor_artifact_sha256=prep_sha,
        expected_split_manifest_sha256=split_sha,
    )
    s1 = model.anomaly_scores(X_val.iloc[:32])
    s2 = reloaded.anomaly_scores(X_val.iloc[:32])
    if not np.allclose(s1, s2, atol=1e-12):
        raise RuntimeError("Reload parity check failed for IsolationForest")

    EVAL_REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    EVAL_REPORT_JSON.write_text(json.dumps(manifest_obj, indent=2) + "\n", encoding="utf-8")
    print(
        f"[IF] Verified reload OK | sha256={model_sha[:12]} | size={model_size_bytes/1e6:.2f} MB | "
        f"th={threshold:.6f} | AIT-Val F1={evals['ait_val']['f1']:.4f} (FPR={evals['ait_val']['false_positive_rate']:.4f}) | "
        f"AIT-Test F1={evals['ait_test']['f1']:.4f} | CTU-Echo F1={evals['ctu_echo']['f1']:.4f} | "
        f"CTU-Win7AD F1={evals['ctu_windows7ad']['f1']:.4f}"
    )


if __name__ == "__main__":
    main()
