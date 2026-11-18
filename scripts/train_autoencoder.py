#!/usr/bin/env python3
"""Train MLP Autoencoder unsupervised anomaly detector on NetFlow Sentinel v2."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import joblib
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

from network_anomaly.config import AUTOENCODER_DEFAULTS  # noqa: E402
from network_anomaly.data.split import _sha256_file  # noqa: E402
from network_anomaly.data.v2_schema import (  # noqa: E402
    FEATURE_CONTRACT_ID,
    ML_FEATURE_COLUMNS,
)
from network_anomaly.models.autoencoder import (  # noqa: E402
    AutoencoderModel,
    build_model,
    fit_model,
    reconstruction_errors,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

AE_DIR = PROJECT_ROOT / "artifacts" / "models" / "autoencoder"
MODEL_ARTIFACT_PATH = AE_DIR / "autoencoder_model.joblib"
CONFIG_SIDECAR_PATH = AE_DIR / "model_config.json"
THRESHOLD_SIDECAR_PATH = AE_DIR / "threshold.json"
NORM_SIDECAR_PATH = AE_DIR / "score_normalization.json"
MODEL_SIDECAR_MANIFEST = AE_DIR / "autoencoder_manifest.json"
REPORT_MANIFEST_PATH = PROJECT_ROOT / "reports" / "models" / "autoencoder_manifest.json"
EVAL_REPORT_JSON = PROJECT_ROOT / "reports" / "evaluation" / "autoencoder_v2_eval.json"


def _write_json(path: Path, payload: Dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return _sha256_file(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Autoencoder v2 model")
    parser.add_argument(
        "--verify-only", action="store_true", help="Exit 0 SKIPPED if datasets absent"
    )
    parser.add_argument(
        "--target-fpr", type=float, default=0.05, help="Validation Benign target FPR"
    )
    parser.add_argument(
        "--max-benign-train",
        type=int,
        default=400_000,
        help="Cap seeded Benign Train rows for bounded MLP convergence speed (0 = all)",
    )
    parser.add_argument("--alpha", type=float, default=None)
    parser.add_argument("--max-iter", type=int, default=None)
    parser.add_argument(
        "--hidden-layer-sizes",
        type=str,
        default=None,
        help="Comma-separated hidden layer sizes, e.g. 32,12,32",
    )
    args = parser.parse_args()

    ok, errors, info = check_v2_training_prerequisites()
    if not ok:
        if args.verify_only:
            print("[train_autoencoder] SKIPPED — prerequisites missing:", "; ".join(errors[:2]))
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

    # Strictly fit ONLY on Benign flows from AIT Train
    X_train_all = partitions["ait_train"]["X"]
    y_train_all = partitions["ait_train"]["y"]
    benign_mask = y_train_all == 0
    X_benign = X_train_all.loc[benign_mask].reset_index(drop=True)
    if args.max_benign_train > 0 and len(X_benign) > args.max_benign_train:
        rng = np.random.default_rng(42)
        sel = np.sort(rng.choice(len(X_benign), size=args.max_benign_train, replace=False))
        X_fit = X_benign.iloc[sel].reset_index(drop=True)
    else:
        X_fit = X_benign

    run_id = make_run_id("ae")
    cfg_dict: Dict[str, Any] = dict(AUTOENCODER_DEFAULTS)
    if args.alpha is not None:
        cfg_dict["alpha"] = float(args.alpha)
    if args.max_iter is not None:
        cfg_dict["max_iter"] = int(args.max_iter)
    if args.hidden_layer_sizes is not None:
        cfg_dict["hidden_layer_sizes"] = [
            int(x.strip()) for x in args.hidden_layer_sizes.split(",")
        ]
    else:
        cfg_dict["hidden_layer_sizes"] = list(cfg_dict["hidden_layer_sizes"])
    estimator = build_model(cfg_dict)

    # Fit per-feature Benign standardization inside Autoencoder so unscaled
    # protocol_num ({1, 6, 17}) does not overwhelm reconstruction MSE.
    X_fit_arr = X_fit.to_numpy(dtype=np.float64)
    feat_mean = np.mean(X_fit_arr, axis=0)
    feat_scale = np.maximum(np.std(X_fit_arr, axis=0), 1.0)
    X_fit_std = (X_fit_arr - feat_mean) / feat_scale

    print(
        f"[AE] Fitting MLPRegressor Autoencoder on {len(X_fit):,} standardized AIT Benign Train flows...",
        flush=True,
    )
    t0 = time.perf_counter()
    fit_model(estimator, X_fit_std)
    train_seconds = time.perf_counter() - t0
    print(f"[AE] Fit completed in {train_seconds:.2f}s (n_iter_={estimator.n_iter_})", flush=True)

    # Calibrate reconstruction threshold strictly on Validation (russellmitchell)
    X_val = partitions["ait_val"]["X"]
    y_val = partitions["ait_val"]["y"]
    X_val_std = (X_val.to_numpy(dtype=np.float64) - feat_mean) / feat_scale
    val_scores = reconstruction_errors(estimator, X_val_std)
    threshold, cal_info, score_norm = calibrate_unsupervised_threshold_on_validation(
        val_scores, y_val, target_fpr=args.target_fpr
    )
    cal_info["unknown_categories_excluded"] = []

    model_wrapper = AutoencoderModel(
        estimator, threshold=threshold, feature_mean=feat_mean, feature_scale=feat_scale
    )
    evals = evaluate_all_splits(
        lambda X_df: model_wrapper.anomaly_scores(X_df),
        partitions,
        threshold=threshold,
    )
    shortcut_audit = audit_feature_shortcuts(X_val, y_val)

    AE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "model_type": "Autoencoder",
        "estimator": estimator,
        "threshold": threshold,
        "feature_mean": feat_mean.tolist(),
        "feature_scale": feat_scale.tolist(),
        "config": cfg_dict,
        "feature_contract_version": FEATURE_CONTRACT_ID,
        "feature_names": list(ML_FEATURE_COLUMNS),
        "run_id": run_id,
    }
    joblib.dump(payload, MODEL_ARTIFACT_PATH, compress=3)
    model_sha = _sha256_file(MODEL_ARTIFACT_PATH)
    model_size_bytes = MODEL_ARTIFACT_PATH.stat().st_size

    config_sha = _write_json(CONFIG_SIDECAR_PATH, cfg_dict)
    threshold_sha = _write_json(THRESHOLD_SIDECAR_PATH, cal_info)
    _write_json(NORM_SIDECAR_PATH, score_norm)

    manifest: Dict[str, Any] = {
        "schema_version": "1.0",
        "artifact_type": "autoencoder-anomaly-detector",
        "model_type": "Autoencoder",
        "training_run_id": run_id,
        "run_id": run_id,
        "dataset_name": "AIT-NDS-v2",
        "dataset_provenance": (
            "AIT-NDS-v2 (10.5281/zenodo.13168643); Benign-only Train={fox,harrison,santos,wardbeck,wilson}"
        ),
        "dataset_sha256": dataset_sha,
        "split_manifest_sha256": split_sha,
        "feature_contract_version": FEATURE_CONTRACT_ID,
        "selected_features": list(ML_FEATURE_COLUMNS),
        "preprocessor_sha256": prep_sha,
        "preprocessor_artifact_sha256": prep_sha,
        "model_file": MODEL_ARTIFACT_PATH.name,
        "model_sha256": model_sha,
        "model_artifact_sha256": model_sha,
        "model_size_bytes": model_size_bytes,
        "config_file": CONFIG_SIDECAR_PATH.name,
        "config_sha256": config_sha,
        "threshold_file": THRESHOLD_SIDECAR_PATH.name,
        "threshold_sha256": threshold_sha,
        "hyperparameters": cfg_dict,
        "model_architecture": {
            "class": "MLPRegressor",
            "input_dimension": len(ML_FEATURE_COLUMNS),
            "output_dimension": len(ML_FEATURE_COLUMNS),
            "hidden_layer_sizes": cfg_dict["hidden_layer_sizes"],
        },
        "threshold": threshold,
        "calibrated_threshold": threshold,
        "threshold_source": f"validation_benign_quantile_{1.0 - args.target_fpr:.2f}",
        "threshold_provenance": {
            "selected_on": "validation",
            "test_touched": False,
            "target_fpr": args.target_fpr,
        },
        "threshold_calibration": cal_info,
        "score_normalization": score_norm,
        "unknown_attack_categories": [],
        "fit_population": {
            "partition": "ait_train",
            "benign_only": True,
            "total_benign_available": int(len(X_benign)),
            "fit_row_count": int(len(X_fit)),
            "n_iter": int(estimator.n_iter_),
            "final_loss": float(estimator.loss_),
        },
        "provenance": {
            "model": {"sha256": model_sha, "config_sha256": config_sha},
            "calibration": {"threshold_sha256": threshold_sha, "threshold_frozen": True},
            "preprocessor": {"artifact_sha256": prep_sha},
        },
        "training_duration_seconds": round(train_seconds, 3),
        "shortcut_audit": shortcut_audit,
        "evaluation": evals,
        "environment": build_environment_block(),
    }

    _write_json(MODEL_SIDECAR_MANIFEST, manifest)
    _write_json(REPORT_MANIFEST_PATH, manifest)
    _write_json(EVAL_REPORT_JSON, manifest)

    reloaded = AutoencoderModel.load_verified(
        MODEL_ARTIFACT_PATH,
        REPORT_MANIFEST_PATH,
        expected_preprocessor_sha256=prep_sha,
        expected_split_manifest_sha256=split_sha,
    )
    e1 = model_wrapper.anomaly_scores(X_val.iloc[:32])
    e2 = reloaded.anomaly_scores(X_val.iloc[:32])
    if not np.allclose(e1, e2, atol=1e-12):
        raise RuntimeError("Reload parity check failed for Autoencoder")

    print(
        f"[AE] Verified reload OK | sha256={model_sha[:12]} | size={model_size_bytes/1e6:.3f} MB | "
        f"th={threshold:.6f} | AIT-Val F1={evals['ait_val']['f1']:.4f} (FPR={evals['ait_val']['false_positive_rate']:.4f}) | "
        f"AIT-Test F1={evals['ait_test']['f1']:.4f} | CTU-Echo F1={evals['ctu_echo']['f1']:.4f} | "
        f"CTU-Win7AD F1={evals['ctu_windows7ad']['f1']:.4f}"
    )


if __name__ == "__main__":
    main()
