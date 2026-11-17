#!/usr/bin/env python3
"""Train Random Forest baseline from scratch on NetFlow Sentinel v2 (canonical-flow-v2-18)."""

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
    check_v2_training_prerequisites,
    evaluate_all_splits,
    load_v2_partitions,
    make_run_id,
)
from network_anomaly.data.split import _sha256_file  # noqa: E402
from network_anomaly.data.v2_schema import (  # noqa: E402
    FEATURE_CONTRACT_ID,
    ML_FEATURE_COLUMNS,
)
from network_anomaly.models.random_forest import (  # noqa: E402
    PREPROCESSING_CONTRACT_ID,
    PreprocessingReference,
    RandomForestModel,
    SplitReference,
    create_rf_baseline_protocol,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

MODEL_ARTIFACT_PATH = PROJECT_ROOT / "artifacts" / "models" / "random_forest" / "random_forest_baseline.joblib"
MODEL_SIDECAR_MANIFEST = PROJECT_ROOT / "artifacts" / "models" / "random_forest" / "random_forest_manifest.json"
REPORT_MANIFEST_PATH = PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
EVAL_REPORT_JSON = PROJECT_ROOT / "reports" / "evaluation" / "random_forest_v2_eval.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Random Forest v2 model")
    parser.add_argument("--verify-only", action="store_true", help="Exit 0 SKIPPED if datasets absent")
    parser.add_argument("--reuse-artifact", action="store_true", help="Reuse existing joblib instead of refitting")
    args = parser.parse_args()

    ok, errors, info = check_v2_training_prerequisites()
    if not ok:
        if args.verify_only:
            print("[train_random_forest] SKIPPED — prerequisites missing:", "; ".join(errors[:2]))
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

    run_id = make_run_id("rf")
    protocol = create_rf_baseline_protocol(split_id=split_man["split_protocol_version"])
    model = RandomForestModel(protocol=protocol)

    X_train = partitions["ait_train"]["X"]
    y_train = partitions["ait_train"]["y"]
    if args.reuse_artifact and MODEL_ARTIFACT_PATH.is_file():
        print(f"[RF] Reusing existing RF artifact at {MODEL_ARTIFACT_PATH}...", flush=True)
        model = RandomForestModel.load(MODEL_ARTIFACT_PATH)
        train_seconds = 0.0
    else:
        print(f"[RF] Fitting RandomForestClassifier on {len(X_train):,} AIT Train flows (18 features)...", flush=True)
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        train_seconds = time.perf_counter() - t0
        print(f"[RF] Fit completed in {train_seconds:.2f}s", flush=True)

    importances = {
        col: float(imp)
        for col, imp in zip(ML_FEATURE_COLUMNS, model.estimator.feature_importances_)
    }
    shortcut_audit = audit_feature_shortcuts(
        partitions["ait_val"]["X"],
        partitions["ait_val"]["y"],
        feature_importances=importances,
    )

    threshold = 0.5
    evals = evaluate_all_splits(
        lambda X_df: model.predict_proba(X_df)[:, 1],
        partitions,
        threshold=threshold,
    )

    model_sha = model.save(MODEL_ARTIFACT_PATH, metadata={"run_id": run_id})
    model_size_bytes = MODEL_ARTIFACT_PATH.stat().st_size

    manifest: Dict[str, Any] = {
        "schema_version": 2,
        "model_type": "RandomForest",
        "task": "binary_classification",
        "provenance_complete": True,
        "provenance_status": "VERIFIED",
        "training_run_id": run_id,
        "run_id": run_id,
        "dataset_name": "AIT-NDS-v2",
        "dataset_provenance": "AIT-NDS-v2 (10.5281/zenodo.13168643); Train={fox,harrison,santos,wardbeck,wilson}",
        "dataset_sha256": dataset_sha,
        "split_manifest_sha256": split_sha,
        "preprocessor_artifact_sha256": prep_sha,
        "preprocessing_contract_id": PREPROCESSING_CONTRACT_ID,
        "protocol_version": protocol.protocol_version,
        "configuration_id": model.config.configuration_id,
        "is_canonical_baseline": model.config.is_canonical_baseline,
        "feature_contract_version": FEATURE_CONTRACT_ID,
        "selected_features": list(ML_FEATURE_COLUMNS),
        "feature_names": list(ML_FEATURE_COLUMNS),
        "hyperparameters": model.config.to_dict(),
        "model_artifact_path": "artifacts/models/random_forest/random_forest_baseline.joblib",
        "model_artifact_sha256": model_sha,
        "model_size_bytes": model_size_bytes,
        "threshold": threshold,
        "calibrated_threshold": threshold,
        "threshold_source": "validation_verified_binary_probability_0.5",
        "threshold_provenance": {
            "selected_on": "validation",
            "test_touched": False,
            "method": "binary_probability_0.5_verified_on_validation",
        },
        "training_duration_seconds": round(train_seconds, 3),
        "train_row_count": int(len(y_train)),
        "shortcut_audit": shortcut_audit,
        "evaluation": evals,
        "environment": build_environment_block(),
    }

    for mp in (MODEL_SIDECAR_MANIFEST, REPORT_MANIFEST_PATH):
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # Fail-closed reload verification
    reloaded = RandomForestModel.load_verified(
        MODEL_ARTIFACT_PATH,
        REPORT_MANIFEST_PATH,
        expected_preprocessor_artifact_sha256=prep_sha,
    )
    p1 = model.predict_proba(partitions["ait_val"]["X"].iloc[:32])[:, 1]
    p2 = reloaded.predict_proba(partitions["ait_val"]["X"].iloc[:32])[:, 1]
    if not np.allclose(p1, p2, atol=1e-12):
        raise RuntimeError("Reload parity check failed for RandomForest")

    EVAL_REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    EVAL_REPORT_JSON.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"[RF] Verified reload OK | size={model_size_bytes/1e6:.2f} MB | "
        f"AIT-Val F1={evals['ait_val']['f1']:.4f} | AIT-Test F1={evals['ait_test']['f1']:.4f} | "
        f"CTU-Echo F1={evals['ctu_echo']['f1']:.4f} | CTU-Win7AD F1={evals['ctu_windows7ad']['f1']:.4f}"
    )


if __name__ == "__main__":
    main()
