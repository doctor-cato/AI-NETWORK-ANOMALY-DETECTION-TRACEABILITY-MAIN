#!/usr/bin/env python3
"""Train XGBoost baseline from scratch on NetFlow Sentinel v2 (canonical-flow-v2-18)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

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
    check_v2_training_prerequisites,
    evaluate_all_splits,
    load_v2_partitions,
    make_run_id,
)

from network_anomaly.data.split import _sha256_file  # noqa: E402
from network_anomaly.data.v2_schema import (  # noqa: E402
    DATASET_SUITE_NAME,
    ML_FEATURE_COLUMNS,
)
from network_anomaly.models.xgboost_model import XGBoostModel  # noqa: E402
from network_anomaly.models.xgboost_protocol import (  # noqa: E402
    PREPROCESSING_CONTRACT_ID,
    PreprocessingReference,
    SplitReference,
    XGBoostBaselineConfig,
    XGBoostBaselineProtocol,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

MODEL_ARTIFACT_PATH = PROJECT_ROOT / "artifacts" / "models" / "xgboost" / "xgboost_baseline.joblib"
MODEL_SIDECAR_MANIFEST = PROJECT_ROOT / "artifacts" / "models" / "xgboost" / "xgboost_manifest.json"
REPORT_MANIFEST_PATH = PROJECT_ROOT / "reports" / "models" / "xgboost_manifest.json"
EVAL_REPORT_JSON = PROJECT_ROOT / "reports" / "evaluation" / "xgboost_v2_eval.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Train XGBoost v2 model")
    parser.add_argument(
        "--verify-only", action="store_true", help="Exit 0 SKIPPED if datasets absent"
    )
    parser.add_argument("--n-estimators", type=int, default=None)
    parser.add_argument("--max-depth", type=int, default=None)
    parser.add_argument("--learning-rate", type=float, default=None)
    parser.add_argument("--min-child-weight", type=float, default=None)
    parser.add_argument("--reg-lambda", type=float, default=None)
    parser.add_argument("--reg-alpha", type=float, default=None)
    parser.add_argument("--scale-pos-weight", type=float, default=1.0)
    args = parser.parse_args()

    ok, errors, info = check_v2_training_prerequisites()
    if not ok:
        if args.verify_only:
            print("[train_xgboost] SKIPPED — prerequisites missing:", "; ".join(errors[:2]))
            return
        print("ERROR: Prerequisite failure:\n  " + "\n  ".join(errors), file=sys.stderr)
        sys.exit(1)

    split_man = info["split_manifest"]
    split_sha = info["split_manifest_sha256"]
    prep_sha = info["preprocessor_sha256"]
    dataset_sha = split_man["dataset_sha256"]

    preproc = TrainOnlyPreprocessor.load_verified(
        artifact_path=PREPROC_ARTIFACT_PATH,
        manifest_path=PROJECT_ROOT
        / "reports"
        / "preprocessing"
        / "v2_flow_preprocessing_manifest.json",
        split_manifest_path=SPLIT_MANIFEST_PATH,
    )
    partitions = load_v2_partitions(preproc, include_test=True, include_ctu=True)

    prep_manifest_path = (
        PROJECT_ROOT / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
    )
    prep_manifest_sha = _sha256_file(prep_manifest_path)

    cfg_overrides = {}
    if args.n_estimators is not None:
        cfg_overrides["n_estimators"] = args.n_estimators
    if args.max_depth is not None:
        cfg_overrides["max_depth"] = args.max_depth
    if args.learning_rate is not None:
        cfg_overrides["learning_rate"] = args.learning_rate
    if args.min_child_weight is not None:
        cfg_overrides["min_child_weight"] = args.min_child_weight
    if args.reg_lambda is not None:
        cfg_overrides["reg_lambda"] = args.reg_lambda
    if args.reg_alpha is not None:
        cfg_overrides["reg_alpha"] = args.reg_alpha
    if abs(args.scale_pos_weight - 1.0) > 1e-12:
        cfg_overrides["scale_pos_weight"] = float(args.scale_pos_weight)
    if cfg_overrides:
        cfg_overrides["is_canonical_baseline"] = False
        cfg_overrides["configuration_id"] = (
            f"xgb-v2-tuned-d{args.max_depth or 6}-spw{args.scale_pos_weight:g}"
        )

    run_id = make_run_id("xgb")
    protocol = XGBoostBaselineProtocol(
        dataset_name=DATASET_SUITE_NAME,
        dataset_csv_sha256=dataset_sha,
        split_reference=SplitReference(
            manifest_path="reports/splits/v2_split_manifest.json",
            manifest_sha256=split_sha,
            status="PASS",
        ),
        preprocessing_reference=PreprocessingReference(
            artifact_path="artifacts/preprocessing/v2_flow_preprocessor.joblib",
            artifact_sha256=prep_sha,
            manifest_path="reports/preprocessing/v2_flow_preprocessing_manifest.json",
            manifest_sha256=prep_manifest_sha,
            status="PASS",
        ),
        model_config=XGBoostBaselineConfig(**cfg_overrides),
    )
    protocol.validate()
    model = XGBoostModel(protocol=protocol)

    X_train = partitions["ait_train"]["X"]
    y_train = partitions["ait_train"]["y"]
    X_val = partitions["ait_val"]["X"]
    y_val = partitions["ait_val"]["y"]

    n_pos = int((y_train == 1).sum())
    n_neg = int((y_train == 0).sum())
    print(
        f"[XGB] Fitting XGBClassifier on {len(X_train):,} AIT Train flows "
        f"(neg={n_neg:,}, pos={n_pos:,}, ratio={n_neg/max(1,n_pos):.2f}:1)...",
        flush=True,
    )
    t0 = time.perf_counter()
    # Monitor validation logloss during boosting (strictly Validation, zero Test leakage)
    model.fit(
        X_train,
        y_train,
        eval_set=[
            (X_train.to_numpy(dtype=np.float32), y_train),
            (X_val.to_numpy(dtype=np.float32), y_val),
        ],
        verbose=False,
    )
    train_seconds = time.perf_counter() - t0
    evals_result = (
        model.estimator.evals_result() if hasattr(model.estimator, "evals_result") else {}
    )
    val_logloss_curve = (
        evals_result.get("validation_1", {}).get("logloss", [])
        if isinstance(evals_result, dict)
        else []
    )
    best_val_logloss = float(min(val_logloss_curve)) if val_logloss_curve else None
    best_val_iter = int(np.argmin(val_logloss_curve)) if val_logloss_curve else None
    print(
        f"[XGB] Fit completed in {train_seconds:.2f}s (best_val_logloss={best_val_logloss})",
        flush=True,
    )

    importances = {
        col: float(imp)
        for col, imp in zip(ML_FEATURE_COLUMNS, model.estimator.feature_importances_)
    }
    shortcut_audit = audit_feature_shortcuts(
        X_val,
        y_val,
        feature_importances=importances,
    )

    threshold = 0.5
    evals = evaluate_all_splits(
        lambda X_df: model.predict_proba(X_df)[:, 1],
        partitions,
        threshold=threshold,
    )

    extra_fields = {
        "schema_version": 2,
        "provenance_complete": True,
        "provenance_status": "VERIFIED",
        "training_run_id": run_id,
        "run_id": run_id,
        "dataset_name": DATASET_SUITE_NAME,
        "dataset_provenance": "AIT-NDS-v2 (10.5281/zenodo.13168643); Train={fox,harrison,santos,wardbeck,wilson}",
        "dataset_sha256": dataset_sha,
        "split_manifest_sha256": split_sha,
        "preprocessor_artifact_sha256": prep_sha,
        "preprocessing_contract_id": PREPROCESSING_CONTRACT_ID,
        "threshold": threshold,
        "calibrated_threshold": threshold,
        "threshold_source": "validation_verified_binary_probability_0.5",
        "threshold_provenance": {
            "selected_on": "validation",
            "test_touched": False,
            "method": "binary_probability_0.5_verified_on_validation",
        },
        "class_imbalance_audit": {
            "train_benign": n_neg,
            "train_attack": n_pos,
            "scale_pos_weight_used": float(args.scale_pos_weight),
            "best_val_logloss": best_val_logloss,
            "best_val_iteration": best_val_iter,
        },
        "training_duration_seconds": round(train_seconds, 3),
        "shortcut_audit": shortcut_audit,
        "evaluation": evals,
        "environment": build_environment_block(),
    }

    model_sha = model.save(
        MODEL_ARTIFACT_PATH,
        manifest_path=REPORT_MANIFEST_PATH,
        extra_manifest_fields=extra_fields,
        metadata={"run_id": run_id},
    )
    model_size_bytes = MODEL_ARTIFACT_PATH.stat().st_size
    manifest_obj = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest_obj["model_size_bytes"] = model_size_bytes
    REPORT_MANIFEST_PATH.write_text(
        json.dumps(manifest_obj, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    MODEL_SIDECAR_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MODEL_SIDECAR_MANIFEST.write_text(
        json.dumps(manifest_obj, indent=2) + "\n", encoding="utf-8", newline="\n"
    )

    reloaded = XGBoostModel.load_verified(
        MODEL_ARTIFACT_PATH,
        REPORT_MANIFEST_PATH,
        expected_preprocessor_artifact_sha256=prep_sha,
    )
    p1 = model.predict_proba(X_val.iloc[:32])[:, 1]
    p2 = reloaded.predict_proba(X_val.iloc[:32])[:, 1]
    if not np.allclose(p1, p2, atol=1e-6):
        raise RuntimeError("Reload parity check failed for XGBoost")

    EVAL_REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    EVAL_REPORT_JSON.write_text(
        json.dumps(manifest_obj, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        f"[XGB] Verified reload OK | sha256={model_sha[:12]} | size={model_size_bytes/1e6:.2f} MB | "
        f"AIT-Val F1={evals['ait_val']['f1']:.4f} | AIT-Test F1={evals['ait_test']['f1']:.4f} | "
        f"CTU-Echo F1={evals['ctu_echo']['f1']:.4f} | CTU-Win7AD F1={evals['ctu_windows7ad']['f1']:.4f}"
    )


if __name__ == "__main__":
    main()
