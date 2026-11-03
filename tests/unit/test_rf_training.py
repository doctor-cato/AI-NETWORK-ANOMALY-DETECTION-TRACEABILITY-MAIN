"""Unit and integration tests for Random Forest baseline training and artifact lifecycle (Issue #10).

Verifies artifact loading, prerequisite checks, checksum mismatch detection,
strict test-partition isolation, target leakage prevention, save/load roundtrips,
runtime provenance injection, and reproducibility.
"""

from __future__ import annotations

import gzip
import json
import os
from pathlib import Path

import joblib

import numpy as np
import pandas as pd
import pytest
from sklearn.exceptions import NotFittedError

from network_anomaly.data.nf_unsw_nb15_v3 import (
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.data.split import (
    SPLIT_PROTOCOL_VERSION,
    _sha256_file,
    load_partition_indices,
)
from network_anomaly.models.random_forest import (
    CANONICAL_BASELINE_PARAMS,
    RandomForestBaselineConfig,
    RandomForestBaselineProtocol,
    RandomForestModel,
    create_rf_baseline_protocol,
)
from network_anomaly.preprocessing.pipeline import (
    EXPECTED_DATASET_SHA256,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)
from scripts.train_random_forest import (
    DEFAULT_DATASET,
    DEFAULT_INDICES_DIR,
    DEFAULT_PREPROCESSOR_ARTIFACT,
    DEFAULT_PREPROCESSOR_MANIFEST,
    DEFAULT_SPLIT_MANIFEST,
    EXPECTED_PREPROCESSOR_ARTIFACT_SHA256,
    EXPECTED_PREPROCESSOR_MANIFEST_SHA256,
    EXPECTED_SPLIT_MANIFEST_SHA256,
    EXPECTED_TRAIN_ROWS,
    EXPECTED_VAL_ROWS,
    PartitionAccessTracker,
    check_prerequisites,
    execute_training,
    load_partition,
    parse_args,
    stream_partition_data,
)


@pytest.fixture
def minimal_47_feature_data():
    """Minimal 47-feature synthetic fixture strictly for interface and lifecycle testing."""
    rng = np.random.RandomState(42)
    n_samples = 20
    data = {col: rng.uniform(0.0, 100.0, size=n_samples) for col in ML_FEATURE_COLUMNS}
    X = pd.DataFrame(data)
    y = pd.Series(rng.randint(0, 2, size=n_samples), name="Label")
    return X, y


@pytest.fixture
def mock_split_environment(tmp_path):
    """Create a fully valid mock split environment for testing partition loading and isolation."""
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir(parents=True, exist_ok=True)

    train_idx = np.array([0, 1, 3, 5, 6], dtype=np.int64)
    val_idx = np.array([2, 4], dtype=np.int64)
    test_idx = np.array([7, 8, 9], dtype=np.int64)

    def write_idx_file(name: str, arr: np.ndarray) -> str:
        p = indices_dir / f"{name}_indices.csv.gz"
        df = pd.DataFrame({"source_row_index": arr})
        df.to_csv(p, index=False, compression="gzip")
        return _sha256_file(p)

    train_sha = write_idx_file("train", train_idx)
    val_sha = write_idx_file("validation", val_idx)
    test_sha = write_idx_file("test", test_idx)

    split_manifest = {
        "manifest_schema_version": 1,
        "dataset_name": DATASET_NAME,
        "split_protocol_version": SPLIT_PROTOCOL_VERSION,
        "partitions": {
            "train": {"row_count": len(train_idx), "index_sha256": train_sha},
            "validation": {"row_count": len(val_idx), "index_sha256": val_sha},
            "test": {"row_count": len(test_idx), "index_sha256": test_sha},
        },
    }
    manifest_path = tmp_path / "split_manifest.json"
    manifest_path.write_text(json.dumps(split_manifest), encoding="utf-8")

    return {
        "manifest_path": manifest_path,
        "indices_dir": indices_dir,
        "train_idx": train_idx,
        "val_idx": val_idx,
        "test_idx": test_idx,
    }


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

    # Check tampering detection: wrong artifact sha
    manifest_data["model_artifact_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
    with pytest.raises(ValueError, match="Model artifact SHA-256 mismatch"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # Check missing artifact sha in manifest raises fail-closed
    manifest_path.write_text(json.dumps({}), encoding="utf-8")
    with pytest.raises(ValueError, match="Missing required field 'model_artifact_sha256'"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # Check missing dataset_sha256 raises fail-closed
    manifest_path.write_text(
        json.dumps({"model_artifact_sha256": sha}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="Missing required field 'dataset_sha256'"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # Check missing split_manifest_sha256 raises fail-closed
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError, match="Missing required field 'split_manifest_sha256'"
    ):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # Check invalid 64-char hex format raises fail-closed
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": "invalid_hash_too_short",
                "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
                "split_manifest_sha256": "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid or malformed 64-character hexadecimal SHA-256"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # Check dataset SHA-256 mismatch detection
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": "1" * 64,
                "split_manifest_sha256": "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Dataset SHA-256 mismatch"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_dataset_sha256="4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        )

    # Check split manifest SHA-256 mismatch detection
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
                "split_manifest_sha256": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Split manifest SHA-256 mismatch"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_split_manifest_sha256="bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
        )

    # Check split_provenance conflict detection
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
                "split_manifest_sha256": "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
                "split_provenance": {
                    "split_manifest_sha256": "1" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Conflicting split_manifest_sha256"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # Check malformed JSON detection
    manifest_path.write_text("{not-valid-json", encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed model manifest JSON"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )


def test_reproducibility_with_same_seed(minimal_47_feature_data):
    """Two models initialized with the same seed produce bitwise identical trees."""
    X, y = minimal_47_feature_data
    cfg = RandomForestBaselineConfig(
        n_estimators=10,
        max_depth=4,
        random_state=42,
        is_canonical_baseline=False,
        configuration_id="rf-repro-test-10",
    )

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


# ==============================================================================
# Critical 1 Tests: load_partition_indices and load_partition signature/validation
# ==============================================================================


def test_load_partition_indices_correct_signature(mock_split_environment):
    """Verify load_partition_indices works with correct 3-parameter signature."""
    env = mock_split_environment
    train_idx = load_partition_indices(env["manifest_path"], env["indices_dir"], "train")
    val_idx = load_partition_indices(env["manifest_path"], env["indices_dir"], "validation")

    np.testing.assert_array_equal(train_idx, env["train_idx"])
    np.testing.assert_array_equal(val_idx, env["val_idx"])


def test_load_partition_indices_invalid_partition(mock_split_environment):
    """Requesting an unknown partition must raise ValueError."""
    env = mock_split_environment
    with pytest.raises(ValueError, match="Partition unknown not found"):
        load_partition_indices(env["manifest_path"], env["indices_dir"], "unknown")


def test_load_partition_indices_missing_manifest(tmp_path):
    """Missing split manifest must raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_partition_indices(tmp_path / "missing.json", tmp_path, "train")


def test_load_partition_indices_missing_index_file(mock_split_environment):
    """Missing index file on disk must raise FileNotFoundError."""
    env = mock_split_environment
    (env["indices_dir"] / "train_indices.csv.gz").unlink()
    with pytest.raises(FileNotFoundError, match="Missing partition index file"):
        load_partition_indices(env["manifest_path"], env["indices_dir"], "train")


def test_load_partition_indices_hash_mismatch(mock_split_environment):
    """Tampered index file must raise ValueError indicating SHA-256 mismatch."""
    env = mock_split_environment
    p = env["indices_dir"] / "train_indices.csv.gz"
    p.write_bytes(b"tampered content")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_partition_indices(env["manifest_path"], env["indices_dir"], "train")


# ==============================================================================
# Critical 2 Tests: Strict Test Lock, Tracker, and Selective Streaming
# ==============================================================================


def test_load_partition_blocks_test_partition(mock_split_environment):
    """Attempting to load 'test' partition during training stage must raise PermissionError."""
    env = mock_split_environment
    tracker = PartitionAccessTracker()

    with pytest.raises(PermissionError, match="Strict Test Lock Violation"):
        load_partition(env["manifest_path"], env["indices_dir"], "test", tracker=tracker)

    audit = tracker.to_audit_dict()
    assert audit["test_partition_accessed"] is True
    assert audit["test_indices_loaded"] is True
    assert audit["test_rows_loaded"] == 0


def test_stream_partition_data_strict_test_isolation(tmp_path):
    """Verify that streaming data strictly ignores and never materializes test rows."""
    # 10 rows: 0-4 train, 5-6 validation, 7-9 test
    n_rows = 10
    train_idx = np.array([0, 1, 2, 3, 4], dtype=np.int64)
    val_idx = np.array([5, 6], dtype=np.int64)
    test_idx = np.array([7, 8, 9], dtype=np.int64)

    rows = []
    for i in range(n_rows):
        row = {col: float(i * 10) for col in ML_FEATURE_COLUMNS}
        row["Label"] = 1 if i in [3, 4, 8] else 0
        row["Attack"] = "Exploits" if row["Label"] == 1 else "Benign"
        rows.append(row)
    df_full = pd.DataFrame(rows)
    csv_path = tmp_path / "dataset.csv"
    df_full.to_csv(csv_path, index=False)

    tracker = PartitionAccessTracker()
    usecols = list(ML_FEATURE_COLUMNS) + ["Label", "Attack"]

    # Stream in chunks of 3 rows
    df_train, df_val = stream_partition_data(
        dataset_path=csv_path,
        train_indices=train_idx,
        val_indices=val_idx,
        usecols=usecols,
        chunksize=3,
        tracker=tracker,
    )

    # Verify lengths
    assert len(df_train) == 5
    assert len(df_val) == 2

    # Verify indices
    assert set(df_train.index) == set(train_idx)
    assert set(df_val.index) == set(val_idx)

    # Strictly verify zero test rows in materialized DataFrames
    assert len(set(df_train.index).intersection(test_idx)) == 0
    assert len(set(df_val.index).intersection(test_idx)) == 0

    # Verify tracker audit
    audit = tracker.to_audit_dict()
    assert audit["test_partition_accessed"] is False
    assert audit["test_rows_loaded"] == 0
    assert audit["train_rows_loaded"] == 5
    assert audit["val_rows_loaded"] == 2


def test_stream_partition_data_detects_overlap_leakage(tmp_path):
    """Overlapping train and validation indices must raise ValueError."""
    train_idx = np.array([0, 1, 2], dtype=np.int64)
    val_idx = np.array([2, 3], dtype=np.int64)  # 2 overlaps!

    with pytest.raises(ValueError, match="Partition leakage"):
        stream_partition_data(
            dataset_path=tmp_path / "dummy.csv",
            train_indices=train_idx,
            val_indices=val_idx,
            usecols=["Label"],
        )


# ==============================================================================
# Critical 3 & Integration Tests: execute_training with Mock Component Fixtures
# ==============================================================================


def test_execute_training_full_pipeline_mock_integration(tmp_path):
    """End-to-end integration test of execute_training verifying test lock and provenance."""
    # 1. Create a 15-row synthetic dataset
    n_rows = 15
    train_idx = np.array([0, 1, 2, 3, 4, 5, 6, 7], dtype=np.int64)
    val_idx = np.array([8, 9, 10, 11], dtype=np.int64)
    test_idx = np.array([12, 13, 14], dtype=np.int64)

    rows = []
    rng = np.random.RandomState(42)
    for i in range(n_rows):
        row = {col: float(rng.uniform(1.0, 50.0)) for col in ML_FEATURE_COLUMNS}
        row["Label"] = int(rng.choice([0, 1]))
        row["Attack"] = "DoS" if row["Label"] == 1 else "Benign"
        rows.append(row)
    df_raw = pd.DataFrame(rows)
    dataset_path = tmp_path / "NF-UNSW-NB15-v3.csv"
    df_raw.to_csv(dataset_path, index=False)
    actual_dataset_sha = _sha256_file(dataset_path)

    # 2. Create indices
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir(parents=True, exist_ok=True)

    def write_idx(name: str, arr: np.ndarray) -> str:
        p = indices_dir / f"{name}_indices.csv.gz"
        pd.DataFrame({"source_row_index": arr}).to_csv(p, index=False, compression="gzip")
        return _sha256_file(p)

    train_sha = write_idx("train", train_idx)
    val_sha = write_idx("validation", val_idx)
    test_sha = write_idx("test", test_idx)

    split_manifest = {
        "manifest_schema_version": 1,
        "dataset_name": DATASET_NAME,
        "dataset_sha256": actual_dataset_sha,
        "split_protocol_version": SPLIT_PROTOCOL_VERSION,
        "partitions": {
            "train": {"row_count": len(train_idx), "index_sha256": train_sha},
            "validation": {"row_count": len(val_idx), "index_sha256": val_sha},
            "test": {"row_count": len(test_idx), "index_sha256": test_sha},
        },
    }
    split_manifest_path = tmp_path / "split_manifest.json"
    split_manifest_path.write_text(json.dumps(split_manifest), encoding="utf-8")
    actual_sm_sha = _sha256_file(split_manifest_path)

    # Patch EXPECTED_DATASET_SHA256 in both modules for this temporary mock test run
    import network_anomaly.preprocessing.pipeline as pp_mod
    import scripts.train_random_forest as trf

    orig_expected_ds_sha = trf.EXPECTED_DATASET_SHA256
    orig_pp_ds_sha = pp_mod.EXPECTED_DATASET_SHA256
    trf.EXPECTED_DATASET_SHA256 = actual_dataset_sha
    pp_mod.EXPECTED_DATASET_SHA256 = actual_dataset_sha

    # 3. Create fitted preprocessor
    df_train_only = df_raw.iloc[train_idx][list(ML_FEATURE_COLUMNS)]
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig())
    prep.dataset_sha256 = actual_dataset_sha
    prep.split_manifest_sha256 = actual_sm_sha
    prep.fit(df_train_only)

    preprocessor_artifact_path = tmp_path / "preprocessor.joblib"
    preprocessor_manifest_path = tmp_path / "preprocessor_manifest.json"
    prep_sha = prep.save(preprocessor_artifact_path, manifest_path=preprocessor_manifest_path)

    output_model_path = tmp_path / "rf_model.joblib"
    output_manifest_path = tmp_path / "rf_manifest.json"

    try:
        manifest = execute_training(
            dataset_path=dataset_path,
            split_manifest_path=split_manifest_path,
            indices_dir=indices_dir,
            preprocessor_artifact_path=preprocessor_artifact_path,
            preprocessor_manifest_path=preprocessor_manifest_path,
            output_model_path=output_model_path,
            output_manifest_path=output_manifest_path,
        )

        assert output_model_path.exists()
        assert output_manifest_path.exists()

        # Verify Test Lock Audit in manifest
        assert manifest["test_lock_audit"]["test_partition_accessed"] is False
        assert manifest["test_lock_audit"]["test_rows_loaded"] == 0
        assert manifest["test_lock_audit"]["train_rows_loaded"] == len(train_idx)
        assert manifest["test_lock_audit"]["val_rows_loaded"] == len(val_idx)

        # Verify Provenance
        assert manifest["split_provenance"]["verification_status"] == "PASS"
        assert manifest["preprocessing_provenance"]["verification_status"] == "PASS"
        assert manifest["environment"]["git_commit"] != ""
        assert "packages" in manifest["environment"]

        # Verify reloaded model
        reloaded = RandomForestModel.load_verified(
            model_path=output_model_path,
            manifest_path=output_manifest_path,
        )
        assert reloaded.is_fitted is True

    finally:
        trf.EXPECTED_DATASET_SHA256 = orig_expected_ds_sha
        pp_mod.EXPECTED_DATASET_SHA256 = orig_pp_ds_sha


@pytest.mark.skipif(
    not DEFAULT_DATASET.exists() or not DEFAULT_PREPROCESSOR_ARTIFACT.exists(),
    reason="Real NF-UNSW-NB15-v3 dataset CSV or preprocessor artifact is not present in local workspace",
)
def test_execute_training_real_data(tmp_path):
    """Verify execution of training on verified real NF-UNSW-NB15-v3 dataset when available."""
    if not DEFAULT_DATASET.exists() or not DEFAULT_PREPROCESSOR_ARTIFACT.exists():
        pytest.skip(
            "Real NF-UNSW-NB15-v3 raw CSV or preprocessor artifact absent in local workspace: SKIPPED / NOT VERIFIED"
        )

    out_model = tmp_path / "real_rf_model.joblib"
    out_manifest = tmp_path / "real_rf_manifest.json"

    manifest = execute_training(
        dataset_path=DEFAULT_DATASET,
        split_manifest_path=DEFAULT_SPLIT_MANIFEST,
        indices_dir=DEFAULT_INDICES_DIR,
        preprocessor_artifact_path=DEFAULT_PREPROCESSOR_ARTIFACT,
        preprocessor_manifest_path=DEFAULT_PREPROCESSOR_MANIFEST,
        output_model_path=out_model,
        output_manifest_path=out_manifest,
    )

    assert out_model.exists()
    assert out_manifest.exists()
    assert manifest["split_provenance"]["train_rows_count"] == EXPECTED_TRAIN_ROWS
    assert manifest["split_provenance"]["val_rows_count"] == EXPECTED_VAL_ROWS
    assert manifest["preprocessing_provenance"]["features_count"] == 47
    assert manifest["test_lock_audit"]["test_partition_accessed"] is False
    assert manifest["test_lock_audit"]["test_rows_loaded"] == 0
    assert manifest["test_lock_audit"]["train_rows_loaded"] == EXPECTED_TRAIN_ROWS
    assert manifest["test_lock_audit"]["val_rows_loaded"] == EXPECTED_VAL_ROWS

    # Verified reload check
    reloaded = RandomForestModel.load_verified(
        model_path=out_model,
        manifest_path=out_manifest,
        expected_dataset_sha256=EXPECTED_DATASET_SHA256,
        expected_split_manifest_sha256=EXPECTED_SPLIT_MANIFEST_SHA256,
        expected_preprocessor_artifact_sha256=EXPECTED_PREPROCESSOR_ARTIFACT_SHA256,
    )
    assert reloaded.is_fitted is True
    assert reloaded.feature_names == ML_FEATURE_COLUMNS
    assert len(reloaded.feature_names) == 47


def test_canonical_baseline_config_locking():
    """Verify locking of canonical baseline configuration and rejection of unauthorized overrides."""
    # 1. Default canonical baseline passes validation
    canonical_cfg = RandomForestBaselineConfig()
    canonical_cfg.validate()
    assert canonical_cfg.is_canonical_baseline is True
    assert canonical_cfg.configuration_id == "rf-baseline-canonical-v1"

    # 2. Unauthorized override claiming canonical status raises ValueError
    unauthorized_cfg = RandomForestBaselineConfig(
        n_estimators=100, is_canonical_baseline=True
    )
    with pytest.raises(
        ValueError, match="Configuration claims canonical baseline status"
    ):
        unauthorized_cfg.validate()

    # 3. Explicit experimental configuration passes validation
    experimental_cfg = RandomForestBaselineConfig(
        n_estimators=100,
        is_canonical_baseline=False,
        configuration_id="rf-tuning-exp-100",
    )
    experimental_cfg.validate()
    assert experimental_cfg.is_canonical_baseline is False
    assert experimental_cfg.configuration_id == "rf-tuning-exp-100"

    # 4. Experimental configuration cannot hijack canonical configuration_id
    bad_id_cfg = RandomForestBaselineConfig(
        n_estimators=100,
        is_canonical_baseline=False,
        configuration_id="rf-baseline-canonical-v1",
    )
    with pytest.raises(
        ValueError,
        match="Non-canonical / experimental configuration cannot use canonical",
    ):
        bad_id_cfg.validate()

    # 5. Protocol validation checks canonical consistency
    with pytest.raises(
        ValueError, match="Protocol claiming official canonical version"
    ):
        RandomForestBaselineProtocol(
            protocol_version="rf-baseline-nf-unsw-nb15-v3-v1",
            model_config=experimental_cfg,
        ).validate()


def test_model_persistence_preserves_protocol_and_classes(
    tmp_path, minimal_47_feature_data
):
    """Verify that saving and loading persists protocol context, class ordering, and configuration."""
    X, y = minimal_47_feature_data
    protocol = create_rf_baseline_protocol()
    model = RandomForestModel(protocol=protocol)
    model.fit(X, y)

    model_path = tmp_path / "model_proto.joblib"
    sha = model.save(model_path)
    assert len(sha) == 64

    # Inspect raw saved payload
    payload = joblib.load(model_path)
    assert payload["configuration_id"] == "rf-baseline-canonical-v1"
    assert payload["is_canonical_baseline"] is True
    assert payload["classes"] == [0, 1]
    assert payload["protocol"] is not None
    assert payload["protocol"]["protocol_version"] == protocol.protocol_version

    # Reconstruct model
    reloaded = RandomForestModel.load(model_path)
    assert reloaded.protocol is not None
    assert reloaded.protocol.protocol_version == protocol.protocol_version
    assert reloaded.config.configuration_id == "rf-baseline-canonical-v1"
    assert reloaded.config.is_canonical_baseline is True


def test_check_prerequisites_detects_preprocessor_manifest_mismatch(tmp_path):
    """check_prerequisites catches companion preprocessor manifest hash mismatch."""
    pm_path = tmp_path / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    pm_path.write_text(json.dumps({"tampered": True}), encoding="utf-8")

    import scripts.train_random_forest as trf

    orig_def = trf.DEFAULT_PREPROCESSOR_MANIFEST
    trf.DEFAULT_PREPROCESSOR_MANIFEST = pm_path
    try:
        audit = check_prerequisites(
            dataset_path=tmp_path / "dummy.csv",
            split_manifest_path=tmp_path / "sm.json",
            indices_dir=tmp_path / "splits",
            preprocessor_artifact_path=tmp_path / "prep.joblib",
            preprocessor_manifest_path=pm_path,
        )
        assert audit["status"] == "BLOCKED"
        assert any(
            "Preprocessor companion manifest SHA-256 mismatch" in msg
            for msg in audit["missing_prerequisites"]
        )
    finally:
        trf.DEFAULT_PREPROCESSOR_MANIFEST = orig_def


def test_check_prerequisites_indices_audits(tmp_path, mock_split_environment):
    """check_prerequisites audits index row counts, duplicates, overlaps, and boundaries."""
    env = mock_split_environment

    # Test duplicate indices detection
    dup_p = env["indices_dir"] / "train_indices.csv.gz"
    pd.DataFrame({"source_row_index": [0, 0, 1, 2]}).to_csv(
        dup_p, index=False, compression="gzip"
    )
    new_sha = _sha256_file(dup_p)

    sm_data = json.loads(env["manifest_path"].read_text(encoding="utf-8"))
    sm_data["partitions"]["train"]["row_count"] = 4
    sm_data["partitions"]["train"]["index_sha256"] = new_sha
    env["manifest_path"].write_text(json.dumps(sm_data), encoding="utf-8")

    audit = check_prerequisites(
        dataset_path=tmp_path / "ds.csv",
        split_manifest_path=env["manifest_path"],
        indices_dir=env["indices_dir"],
        preprocessor_artifact_path=tmp_path / "prep.joblib",
        preprocessor_manifest_path=tmp_path / "pm.json",
    )
    assert audit["status"] == "BLOCKED"
    assert any("duplicate row indices" in msg for msg in audit["missing_prerequisites"])

    # Test overlap detection
    pd.DataFrame({"source_row_index": [0, 1, 2, 4]}).to_csv(
        dup_p, index=False, compression="gzip"
    )
    sm_data["partitions"]["train"]["index_sha256"] = _sha256_file(dup_p)
    env["manifest_path"].write_text(json.dumps(sm_data), encoding="utf-8")

    audit = check_prerequisites(
        dataset_path=tmp_path / "ds.csv",
        split_manifest_path=env["manifest_path"],
        indices_dir=env["indices_dir"],
        preprocessor_artifact_path=tmp_path / "prep.joblib",
        preprocessor_manifest_path=tmp_path / "pm.json",
    )
    assert audit["status"] == "BLOCKED"
    assert any("indices overlap" in msg for msg in audit["missing_prerequisites"])
