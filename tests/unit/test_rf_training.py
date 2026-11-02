"""Unit tests for Random Forest baseline training and artifact lifecycle (Issue #10).

Verifies artifact loading, prerequisite checks, checksum mismatch detection,
target leakage prevention, save/load roundtrips, and reproducibility without
modifying real dataset files or confusing unit tests with real-data execution.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.exceptions import NotFittedError

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.models.random_forest import (
    RandomForestBaselineConfig,
    RandomForestBaselineProtocol,
    RandomForestModel,
    create_rf_baseline_protocol,
)
from network_anomaly.preprocessing.pipeline import PreprocessingConfig, TrainOnlyPreprocessor
from scripts.train_random_forest import check_prerequisites, parse_args


@pytest.fixture
def minimal_47_feature_data():
    """Minimal 47-feature synthetic fixture strictly for interface and lifecycle testing."""
    rng = np.random.RandomState(42)
    n_samples = 20
    data = {col: rng.uniform(0.0, 100.0, size=n_samples) for col in ML_FEATURE_COLUMNS}
    X = pd.DataFrame(data)
    y = pd.Series(rng.randint(0, 2, size=n_samples), name="Label")
    return X, y


def test_unfitted_model_cannot_be_saved(tmp_path):
    """Saving an unfitted model must raise NotFittedError."""
    model = RandomForestModel()
    with pytest.raises(NotFittedError, match="Cannot save an unfitted"):
        model.save(tmp_path / "model.joblib")


def test_model_save_and_load_roundtrip(tmp_path, minimal_47_feature_data):
    """Fitted model saves, computes sha256, and reloads with identical predictions."""
    X, y = minimal_47_feature_data
    model = RandomForestModel()
    model.fit(X, y)

    model_path = tmp_path / "rf_model.joblib"
    sha = model.save(model_path, metadata={"run": "test"})

    assert model_path.exists()
    assert isinstance(sha, str)
    assert len(sha) == 64

    # Reload model
    reloaded = RandomForestModel.load(model_path)
    assert reloaded.is_fitted is True
    assert reloaded.model_type == "RandomForest"
    assert reloaded.feature_names == model.feature_names

    # Check identical predictions
    np.testing.assert_array_equal(model.predict(X), reloaded.predict(X))
    np.testing.assert_allclose(model.predict_proba(X), reloaded.predict_proba(X))


def test_model_load_verified(tmp_path, minimal_47_feature_data):
    """load_verified checks manifest sha256 and detects artifact tampering."""
    X, y = minimal_47_feature_data
    model = RandomForestModel()
    model.fit(X, y)

    model_path = tmp_path / "rf_verified.joblib"
    sha = model.save(model_path)

    manifest_path = tmp_path / "rf_manifest.json"
    manifest_data = {
        "model_artifact_sha256": sha,
        "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        "split_manifest_sha256": "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    # Success case
    verified_model = RandomForestModel.load_verified(
        model_path=model_path,
        manifest_path=manifest_path,
        expected_dataset_sha256="4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        expected_split_manifest_sha256="bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
    )
    assert verified_model.is_fitted is True

    # Check tampering detection
    manifest_data["model_artifact_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
    with pytest.raises(ValueError, match="Model artifact SHA-256 mismatch"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )


def test_reproducibility_with_same_seed(minimal_47_feature_data):
    """Two models initialized with the same seed produce bitwise identical trees."""
    X, y = minimal_47_feature_data
    cfg = RandomForestBaselineConfig(n_estimators=10, max_depth=4, random_state=42)

    m1 = RandomForestModel(config=cfg).fit(X, y)
    m2 = RandomForestModel(config=cfg).fit(X, y)

    np.testing.assert_array_equal(m1.predict(X), m2.predict(X))
    np.testing.assert_allclose(m1.predict_proba(X), m2.predict_proba(X))


def test_check_prerequisites_detects_missing_files(tmp_path):
    """check_prerequisites reports all missing files cleanly and returns BLOCKED."""
    audit = check_prerequisites(
        dataset_path=tmp_path / "nonexistent.csv",
        split_manifest_path=tmp_path / "nonexistent_sm.json",
        indices_dir=tmp_path / "nonexistent_dir",
        preprocessor_artifact_path=tmp_path / "nonexistent.joblib",
        preprocessor_manifest_path=tmp_path / "nonexistent_pm.json",
    )

    assert audit["status"] == "BLOCKED"
    assert len(audit["missing_prerequisites"]) >= 4


def test_check_prerequisites_detects_hash_mismatch(tmp_path):
    """check_prerequisites catches corrupted or mismatched dataset bytes."""
    corrupted_csv = tmp_path / "corrupted.csv"
    corrupted_csv.write_text("dummy,content\n", encoding="utf-8")

    audit = check_prerequisites(
        dataset_path=corrupted_csv,
        split_manifest_path=tmp_path / "sm.json",
        indices_dir=tmp_path / "splits",
        preprocessor_artifact_path=tmp_path / "prep.joblib",
        preprocessor_manifest_path=tmp_path / "pm.json",
    )

    assert audit["status"] == "BLOCKED"
    assert any("Dataset SHA-256 mismatch" in msg for msg in audit["missing_prerequisites"])


def test_feature_ordering_and_target_leakage_guards():
    """Verify strict 47-feature ordering and rejection of targets/metadata."""
    protocol = create_rf_baseline_protocol()
    model = RandomForestModel(protocol=protocol)

    assert model.feature_names == ML_FEATURE_COLUMNS
    assert len(model.feature_names) == 47

    # Targets must never be features
    assert "Label" not in model.feature_names
    assert "Attack" not in model.feature_names

    # Trace metadata must never be features
    for col in TRACE_METADATA_COLUMNS:
        assert col not in model.feature_names


def test_no_preprocessing_refit_invariance(minimal_47_feature_data):
    """Verify that transforming data does NOT alter fitted preprocessor state."""
    X, _ = minimal_47_feature_data
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig())
    prep.fit(X)

    # Capture initial fitted parameters
    imputed_before = prep.imputed_values_.copy()
    vocab_before = {k: list(v) for k, v in prep.category_vocabularies_.items()}

    # Transform twice
    _ = prep.transform(X)
    _ = prep.transform(X)

    # Verify state remains completely frozen
    assert prep.imputed_values_ == imputed_before
    assert {k: list(v) for k, v in prep.category_vocabularies_.items()} == vocab_before
