"""Unit tests for Stage-2 6-class classifier sidecar, RQ2 train-only oversampling, and experiment schemas."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SRC_DIR = PROJECT_ROOT / "src"
_SCRIPTS_DIR = PROJECT_ROOT / "scripts"
for p in (str(_SRC_DIR), str(_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from run_rq2_rare_attack_experiment import _oversample_rare_train_only  # noqa: E402

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.models.stage2_multiclass import (  # noqa: E402
    ATTACK_ONLY_CLASSES,
    CANONICAL_6_CLASSES,
    DEFAULT_STAGE2_MANIFEST_PATH,
    Stage2MulticlassClassifier,
)


def test_stage2_classifier_default_and_centroid_fallback(tmp_path: Path) -> None:
    clf_default = Stage2MulticlassClassifier.try_load_default()
    assert clf_default is not None
    assert clf_default.classes == CANONICAL_6_CLASSES

    sample_row = np.zeros(len(ML_FEATURE_COLUMNS), dtype=np.float64)
    sample_batch = np.vstack([sample_row, np.ones(len(ML_FEATURE_COLUMNS), dtype=np.float64)])

    cat1, conf1 = clf_default.predict_one(sample_row)
    assert cat1 in ATTACK_ONLY_CLASSES
    assert 0.0 <= conf1 <= 1.0

    batch_preds = clf_default.predict_batch(sample_batch)
    assert len(batch_preds) == 2
    for cat, conf in batch_preds:
        assert cat in ATTACK_ONLY_CLASSES
        assert 0.0 <= conf <= 1.0

    # Explicit centroid fallback when .joblib is absent
    clf_centroid = Stage2MulticlassClassifier.try_load_default(
        artifact_path=tmp_path / "nonexistent_stage2.joblib",
        manifest_path=DEFAULT_STAGE2_MANIFEST_PATH,
    )
    assert clf_centroid is not None
    assert clf_centroid.mode == "centroid"
    cat_c, conf_c = clf_centroid.predict_one(sample_row)
    assert cat_c in ATTACK_ONLY_CLASSES
    assert 0.0 <= conf_c <= 1.0
    batch_c = clf_centroid.predict_batch(sample_batch)
    assert len(batch_c) == 2

    # Preprocessor SHA-256 verification (fail-closed on mismatch)
    manifest_data = json.loads(DEFAULT_STAGE2_MANIFEST_PATH.read_text(encoding="utf-8"))
    preproc_sha = manifest_data["preprocessor_artifact_sha256"]
    clf_verified = Stage2MulticlassClassifier.from_manifest(
        manifest_path=DEFAULT_STAGE2_MANIFEST_PATH,
        artifact_path=tmp_path / "nonexistent_stage2.joblib",
        expected_preprocessor_sha256=preproc_sha,
    )
    assert clf_verified.mode == "centroid"
    try:
        Stage2MulticlassClassifier.from_manifest(
            manifest_path=DEFAULT_STAGE2_MANIFEST_PATH,
            artifact_path=tmp_path / "nonexistent_stage2.joblib",
            expected_preprocessor_sha256="0" * 64,
        )
        raise AssertionError("Expected ValueError on preprocessor SHA-256 mismatch")
    except ValueError as exc:
        assert "preprocessor SHA-256 mismatch" in str(exc)
    assert (
        Stage2MulticlassClassifier.try_load_default(
            artifact_path=tmp_path / "nonexistent_stage2.joblib",
            manifest_path=DEFAULT_STAGE2_MANIFEST_PATH,
            expected_preprocessor_sha256="0" * 64,
        )
        is None
    )


def test_oversample_rare_train_only_preserves_binary_flags() -> None:
    rng = np.random.default_rng(123)
    n_features = len(ML_FEATURE_COLUMNS)
    X = rng.normal(0.0, 1.0, size=(100, n_features))
    # Set protocol_num and binary flags exact
    proto_idx = ML_FEATURE_COLUMNS.index("protocol_num")
    flag_indices = [
        ML_FEATURE_COLUMNS.index("has_response"),
        ML_FEATURE_COLUMNS.index("is_tcp"),
        ML_FEATURE_COLUMNS.index("is_udp"),
    ]
    X[:, proto_idx] = 6.0
    for fi in flag_indices:
        X[:, fi] = rng.integers(0, 2, size=100).astype(np.float64)

    y = np.zeros(100, dtype=np.int64)
    y[:5] = 1
    attacks = pd.Series(["Credential_Attack"] * 5 + ["Benign"] * 95)

    X_os, y_os = _oversample_rare_train_only(
        X,
        y,
        attacks,
        rare_categories=["Credential_Attack"],
        target_per_rare_class=25,
        seed=42,
    )
    assert len(X_os) == 120  # 100 + (25 - 5)
    assert int(np.sum(y_os == 1)) == 25
    # Binary flags remain strictly {0.0, 1.0}
    for fi in flag_indices:
        assert set(np.unique(X_os[:, fi])).issubset({0.0, 1.0})
    assert set(np.unique(X_os[:, proto_idx])) == {6.0}


def test_experiment_manifests_and_reports_schema() -> None:
    manifest_path = (
        PROJECT_ROOT / "reports" / "experiments" / "ml" / "multiclass_stage2_manifest.json"
    )
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for key in (
        "model_artifact_sha256",
        "preprocessor_artifact_sha256",
        "feature_columns",
        "classes",
        "validation_macro_f1",
        "test_macro_f1",
        "class_centroids",
        "class_stds",
    ):
        assert key in manifest
    assert len(manifest["feature_columns"]) == 18
    assert tuple(manifest["classes"]) == CANONICAL_6_CLASSES

    rq2_path = PROJECT_ROOT / "reports" / "experiments" / "imbalance" / "rq2_imbalance_report.json"
    assert rq2_path.is_file()
    rq2 = json.loads(rq2_path.read_text(encoding="utf-8"))
    assert rq2["status"] == "COMPLETED"
    assert "RandomForest_TrainOnlyOversampled" in rq2["overall_test_metrics"]
    assert "XGBoost_TrainOnlyOversampled" in rq2["overall_test_metrics"]

    e1_path = (
        PROJECT_ROOT / "reports" / "experiments" / "ml" / "e1_multidomain_experiment_report.json"
    )
    assert e1_path.is_file()
    e1 = json.loads(e1_path.read_text(encoding="utf-8"))
    assert e1["e0_artifacts_untouched"] is True
    for split_name in ("AIT_Test", "CTU_Test", "CTU_Win7AD_Test", "UWF_Test"):
        assert split_name in e1["results_by_test_split"]
        assert "Autoencoder_E3b_VarianceNormalized" in e1["results_by_test_split"][split_name]
