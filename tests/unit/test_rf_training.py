"""Unit and integration tests for Random Forest baseline training (Issue #10).

Verifies artifact loading, prerequisite checks, checksum mismatch detection,
strict test-partition isolation, target leakage prevention, save/load roundtrips,
runtime provenance injection, and reproducibility.
"""

from __future__ import annotations

import json

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.exceptions import NotFittedError

from network_anomaly.data.nf_unsw_nb15_v3 import (
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.data.split import (
    SPLIT_PROTOCOL_VERSION,
    _sha256_file,
    load_partition_indices,
)
from network_anomaly.models.random_forest import (
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
    EXPECTED_SPLIT_MANIFEST_SHA256,
    EXPECTED_TRAIN_ROWS,
    EXPECTED_VAL_ROWS,
    PartitionAccessTracker,
    check_prerequisites,
    execute_training,
    load_partition,
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
        "environment": {"git_commit": "73c6f32a0cc7b94bbe938edda0a331db97e55a6b"},
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
    manifest_path.write_text(json.dumps({"model_artifact_sha256": sha}), encoding="utf-8")
    with pytest.raises(ValueError, match="Missing required field 'dataset_sha256'"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # Check missing split_manifest_sha256 raises fail-closed
    ds_hex = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    sm_hex = "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88"
    prep_hex = "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"

    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": ds_hex,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Missing required field 'split_manifest_sha256'"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # Check invalid 64-char hex format raises fail-closed
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": "invalid_hash_too_short",
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": sm_hex,
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
                "split_manifest_sha256": sm_hex,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Dataset SHA-256 mismatch"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_dataset_sha256=ds_hex,
        )

    # Check split manifest SHA-256 mismatch detection
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Split manifest SHA-256 mismatch"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_split_manifest_sha256=sm_hex,
        )

    # Check split_provenance conflict detection
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": sm_hex,
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

    # P0-02: Missing preprocessor hash when expected_preprocessor_artifact_sha256 is passed
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": sm_hex,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Missing required field 'preprocessor_artifact_sha256'"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_preprocessor_artifact_sha256=prep_hex,
        )

    # P0-02: Malformed preprocessor hash
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": sm_hex,
                "preprocessor_artifact_sha256": "not_64_chars",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid or malformed 64-character hexadecimal SHA-256"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_preprocessor_artifact_sha256=prep_hex,
        )

    # P0-02: Preprocessor hash mismatch
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": sm_hex,
                "preprocessor_artifact_sha256": "3" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Preprocessor artifact SHA-256 mismatch"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_preprocessor_artifact_sha256=prep_hex,
        )

    # P0-02: Preprocessor provenance conflict between top-level and nested
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": sm_hex,
                "preprocessor_artifact_sha256": prep_hex,
                "preprocessing_provenance": {
                    "preprocessor_artifact_sha256": "4" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Conflicting preprocessor_artifact_sha256"):
        RandomForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
        )

    # P0-02: Valid matching preprocessor hash in both top-level and nested provenance
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": sha,
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": sm_hex,
                "preprocessor_artifact_sha256": prep_hex,
                "preprocessing_provenance": {
                    "preprocessor_artifact_sha256": prep_hex,
                },
                "environment": {"git_commit": "73c6f32a0cc7b94bbe938edda0a331db97e55a6b"},
            }
        ),
        encoding="utf-8",
    )
    v_model = RandomForestModel.load_verified(
        model_path=model_path,
        manifest_path=manifest_path,
        expected_preprocessor_artifact_sha256=prep_hex,
    )
    assert v_model.is_fitted is True


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
    prep.save(preprocessor_artifact_path, manifest_path=preprocessor_manifest_path)

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
    reason=(
        "Real NF-UNSW-NB15-v3 dataset CSV or preprocessor artifact "
        "is not present in local workspace"
    ),
)
def test_execute_training_real_data(tmp_path):
    """Verify execution of training on verified real NF-UNSW-NB15-v3 dataset when available."""
    if not DEFAULT_DATASET.exists() or not DEFAULT_PREPROCESSOR_ARTIFACT.exists():
        pytest.skip(
            "Real NF-UNSW-NB15-v3 raw CSV or preprocessor artifact absent "
            "in local workspace: SKIPPED / NOT VERIFIED"
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
    assert manifest["configuration_id"] == "rf-baseline-canonical-v1"
    assert manifest["is_canonical_baseline"] is True
    assert manifest["model_artifact_sha256"] == _sha256_file(out_model)
    assert manifest["model_artifact_size_bytes"] == out_model.stat().st_size
    assert manifest["hyperparameters"]["n_estimators"] == 200
    assert manifest["hyperparameters"]["max_depth"] == 16
    assert manifest["hyperparameters"]["criterion"] == "gini"
    assert manifest["hyperparameters"]["random_state"] == 42
    assert manifest["hyperparameters"]["n_jobs"] == -1
    assert manifest["selected_features"] == list(ML_FEATURE_COLUMNS)
    assert manifest["class_mapping"] == {"0": "Benign", "1": "Attack"}
    assert manifest["split_provenance"]["train_rows_count"] == EXPECTED_TRAIN_ROWS
    assert manifest["split_provenance"]["val_rows_count"] == EXPECTED_VAL_ROWS
    assert manifest["preprocessing_provenance"]["features_count"] == 47
    assert (
        manifest["preprocessing_provenance"]["preprocessor_artifact_sha256"]
        == EXPECTED_PREPROCESSOR_ARTIFACT_SHA256
    )
    assert manifest["test_lock_audit"]["test_partition_accessed"] is False
    assert manifest["test_lock_audit"]["test_rows_loaded"] == 0
    assert manifest["test_lock_audit"]["test_indices_loaded"] is False
    assert manifest["test_lock_audit"]["train_rows_loaded"] == EXPECTED_TRAIN_ROWS
    assert manifest["test_lock_audit"]["val_rows_loaded"] == EXPECTED_VAL_ROWS
    assert manifest["validation_summary"]["rows_evaluated"] == EXPECTED_VAL_ROWS
    assert "f1" in manifest["validation_summary"]
    assert "confusion_matrix" in manifest["validation_summary"]
    assert len(manifest["validation_summary"]["per_category_breakdown"]) == 10
    assert manifest["reload_verification"]["status"] == "PASSED"

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
    assert list(reloaded.estimator.classes_) == [0, 1]
    assert len(reloaded.estimator.estimators_) == 200


def test_canonical_baseline_config_locking():
    """Verify locking of canonical baseline config and rejection of unauthorized overrides."""
    # 1. Default canonical baseline passes validation
    canonical_cfg = RandomForestBaselineConfig()
    canonical_cfg.validate()
    assert canonical_cfg.is_canonical_baseline is True
    assert canonical_cfg.configuration_id == "rf-baseline-canonical-v1"

    # 2. Unauthorized override claiming canonical status raises ValueError
    unauthorized_cfg = RandomForestBaselineConfig(n_estimators=100, is_canonical_baseline=True)
    with pytest.raises(ValueError, match="Configuration claims canonical baseline status"):
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
    with pytest.raises(ValueError, match="Protocol claiming official canonical version"):
        RandomForestBaselineProtocol(
            protocol_version="rf-baseline-nf-unsw-nb15-v3-v1",
            model_config=experimental_cfg,
        ).validate()


def test_model_persistence_preserves_protocol_and_classes(tmp_path, minimal_47_feature_data):
    """Verify that saving and loading persists protocol context, classes, and config."""
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
    pd.DataFrame({"source_row_index": [0, 0, 1, 2]}).to_csv(dup_p, index=False, compression="gzip")
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
    pd.DataFrame({"source_row_index": [0, 1, 2, 4]}).to_csv(dup_p, index=False, compression="gzip")
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


def test_check_prerequisites_fails_when_verify_preprocessing_artifact_returns_fail(
    tmp_path, monkeypatch
):
    """P0-01: verify_preprocessing_artifact returning FAIL must mark status as BLOCKED."""
    prep_art = tmp_path / "prep.joblib"
    prep_art.write_bytes(b"dummy_art")
    pm_path = tmp_path / "pm.json"
    prep_hex = "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"
    pm_path.write_text(
        json.dumps({"artifact_sha256": prep_hex}),
        encoding="utf-8",
    )

    import scripts.train_random_forest as trf

    # Monkeypatch verify_preprocessing_artifact to return FAIL without raising
    monkeypatch.setattr(
        trf,
        "verify_preprocessing_artifact",
        lambda **kwargs: {
            "status": "FAIL",
            "errors": ["Metadata contract mismatch", "Scaler parameter corruption"],
        },
    )

    audit = trf.check_prerequisites(
        dataset_path=tmp_path / "dummy.csv",
        split_manifest_path=tmp_path / "sm.json",
        indices_dir=tmp_path / "indices",
        preprocessor_artifact_path=prep_art,
        preprocessor_manifest_path=pm_path,
    )
    assert audit["status"] == "BLOCKED"
    assert any("status=FAIL" in err for err in audit["missing_prerequisites"])
    assert any("Metadata contract mismatch" in err for err in audit["missing_prerequisites"])


def test_check_prerequisites_fails_when_verify_preprocessing_artifact_invalid_status(
    tmp_path, monkeypatch
):
    """P0-01: verify_preprocessing_artifact returning missing or invalid status fails closed."""
    prep_art = tmp_path / "prep.joblib"
    prep_art.write_bytes(b"dummy_art")
    pm_path = tmp_path / "pm.json"
    prep_hex = "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"
    pm_path.write_text(
        json.dumps({"artifact_sha256": prep_hex}),
        encoding="utf-8",
    )

    import scripts.train_random_forest as trf

    # Case 1: Missing status
    monkeypatch.setattr(
        trf,
        "verify_preprocessing_artifact",
        lambda **kwargs: {"errors": ["some error"]},
    )
    audit = trf.check_prerequisites(
        dataset_path=tmp_path / "dummy.csv",
        split_manifest_path=tmp_path / "sm.json",
        indices_dir=tmp_path / "indices",
        preprocessor_artifact_path=prep_art,
        preprocessor_manifest_path=pm_path,
    )
    assert audit["status"] == "BLOCKED"
    assert any("missing 'status' field" in err for err in audit["missing_prerequisites"])

    # Case 2: Invalid status value
    monkeypatch.setattr(
        trf,
        "verify_preprocessing_artifact",
        lambda **kwargs: {"status": "UNKNOWN_STATE", "errors": []},
    )
    audit2 = trf.check_prerequisites(
        dataset_path=tmp_path / "dummy.csv",
        split_manifest_path=tmp_path / "sm.json",
        indices_dir=tmp_path / "indices",
        preprocessor_artifact_path=prep_art,
        preprocessor_manifest_path=pm_path,
    )
    assert audit2["status"] == "BLOCKED"
    assert any("status=UNKNOWN_STATE" in err for err in audit2["missing_prerequisites"])


def test_check_prerequisites_fails_when_verify_preprocessing_artifact_raises(tmp_path, monkeypatch):
    """P0-01: verify_preprocessing_artifact raising an exception fails closed."""
    prep_art = tmp_path / "prep.joblib"
    prep_art.write_bytes(b"dummy_art")
    pm_path = tmp_path / "pm.json"
    prep_hex = "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"
    pm_path.write_text(
        json.dumps({"artifact_sha256": prep_hex}),
        encoding="utf-8",
    )

    import scripts.train_random_forest as trf

    def _exploding_verifier(**kwargs):
        raise RuntimeError("Unexpected filesystem corruption during verification")

    monkeypatch.setattr(trf, "verify_preprocessing_artifact", _exploding_verifier)

    audit = trf.check_prerequisites(
        dataset_path=tmp_path / "dummy.csv",
        split_manifest_path=tmp_path / "sm.json",
        indices_dir=tmp_path / "indices",
        preprocessor_artifact_path=prep_art,
        preprocessor_manifest_path=pm_path,
    )
    assert audit["status"] == "BLOCKED"
    assert any("Unexpected filesystem corruption" in err for err in audit["missing_prerequisites"])


def test_check_prerequisites_preprocessor_manifest_schema_enforcement(tmp_path):
    """P1-01: Companion preprocessor manifest must use canonical 'artifact_sha256' field."""
    import scripts.train_random_forest as trf

    # Case 1: Missing artifact_sha256
    pm_missing = tmp_path / "pm_missing.json"
    pm_missing.write_text(json.dumps({"wrong_field": "12345"}), encoding="utf-8")
    audit1 = trf.check_prerequisites(
        dataset_path=tmp_path / "ds.csv",
        split_manifest_path=tmp_path / "sm.json",
        indices_dir=tmp_path / "indices",
        preprocessor_artifact_path=tmp_path / "prep.joblib",
        preprocessor_manifest_path=pm_missing,
    )
    assert audit1["status"] == "BLOCKED"
    assert any(
        "missing required canonical field 'artifact_sha256'" in err
        for err in audit1["missing_prerequisites"]
    )

    # Case 2: Mismatched artifact_sha256
    pm_mismatch = tmp_path / "pm_mismatch.json"
    pm_mismatch.write_text(json.dumps({"artifact_sha256": "0" * 64}), encoding="utf-8")
    audit2 = trf.check_prerequisites(
        dataset_path=tmp_path / "ds.csv",
        split_manifest_path=tmp_path / "sm.json",
        indices_dir=tmp_path / "indices",
        preprocessor_artifact_path=tmp_path / "prep.joblib",
        preprocessor_manifest_path=pm_mismatch,
    )
    assert audit2["status"] == "BLOCKED"
    assert any(
        "Preprocessor manifest artifact SHA-256 mismatch" in err
        for err in audit2["missing_prerequisites"]
    )


def test_model_load_fails_on_malformed_protocol(tmp_path, minimal_47_feature_data):
    """P1-02: RandomForestModel.load() fails closed when payload contains malformed protocol."""
    X, y = minimal_47_feature_data
    model = RandomForestModel()
    model.fit(X, y)

    model_path = tmp_path / "corrupted_proto_model.joblib"
    model.save(model_path)

    # Corrupt protocol dictionary inside payload with invalid feature selection
    payload = joblib.load(model_path)
    payload["protocol"] = {"selected_features": ["invalid_unknown_feature"]}
    joblib.dump(payload, model_path)

    with pytest.raises(
        ValueError, match="Failed to deserialize model protocol from artifact payload"
    ):
        RandomForestModel.load(model_path)


def test_model_load_verified_rejects_missing_protocol(tmp_path, minimal_47_feature_data):
    """P1-02: RandomForestModel.load_verified() rejects legacy payload lacking protocol."""
    X, y = minimal_47_feature_data
    model = RandomForestModel()
    model.fit(X, y)

    model_path = tmp_path / "legacy_model.joblib"
    model.save(model_path)

    # Remove protocol to simulate legacy artifact
    payload = joblib.load(model_path)
    payload["protocol"] = None
    joblib.dump(payload, model_path)
    actual_sha = _sha256_file(model_path)

    # Plain load() succeeds in backward compatibility mode
    legacy_model = RandomForestModel.load(model_path)
    assert legacy_model.protocol is None
    assert legacy_model.is_fitted is True

    # load_verified() strictly rejects unverified legacy model without protocol
    manifest_path = tmp_path / "manifest.json"
    ds_hex = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    sm_hex = "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88"
    manifest_path.write_text(
        json.dumps(
            {
                "model_artifact_sha256": actual_sha,
                "dataset_sha256": ds_hex,
                "split_manifest_sha256": sm_hex,
                "environment": {"git_commit": "73c6f32a0cc7b94bbe938edda0a331db97e55a6b"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="lacks required protocol provenance for verified loading"):
        RandomForestModel.load_verified(model_path, manifest_path)


def test_reload_probability_tolerance_enforces_rtol_zero():
    """P1-04: Reload probability check enforces absolute tolerance atol=1e-7 with rtol=0."""
    orig = np.array([[0.8, 0.2], [0.3, 0.7]], dtype=np.float64)

    # Identical: passes
    assert np.allclose(orig, orig, atol=1e-7, rtol=0)

    # Within tolerance (0.5e-7): passes
    reloaded_close = orig + 0.5e-7
    assert np.allclose(orig, reloaded_close, atol=1e-7, rtol=0)

    # Beyond tolerance (2e-7): fails
    reloaded_far = orig + 2e-7
    assert not np.allclose(orig, reloaded_far, atol=1e-7, rtol=0)

    # Relative tolerance difference: with default rtol=1e-5, a 1e-6 diff passes!
    # With rtol=0, it strictly FAILS as required by the contract.
    reloaded_scaled = orig + 1e-6
    assert np.allclose(orig, reloaded_scaled, atol=1e-7)  # Passes with default rtol=1e-5!
    assert not np.allclose(orig, reloaded_scaled, atol=1e-7, rtol=0)  # Fails with rtol=0!


def test_load_verified_rejects_empty_expected_hashes_and_malformed_top_level_fields(
    tmp_path, minimal_47_feature_data
):
    """Fail-closed: empty expected hash args or empty top-level hashes raise ValueError."""
    X, y = minimal_47_feature_data
    model = RandomForestModel()
    model.fit(X, y)

    model_path = tmp_path / "model.joblib"
    actual_sha = model.save(model_path)

    valid_ds = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    valid_sm = "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88"
    valid_prep = "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"

    manifest_path = tmp_path / "manifest.json"
    base_manifest = {
        "model_artifact_sha256": actual_sha,
        "dataset_sha256": valid_ds,
        "split_manifest_sha256": valid_sm,
        "preprocessor_artifact_sha256": valid_prep,
    }
    manifest_path.write_text(json.dumps(base_manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="expected_dataset_sha256"):
        RandomForestModel.load_verified(model_path, manifest_path, expected_dataset_sha256="")

    with pytest.raises(ValueError, match="expected_split_manifest_sha256"):
        RandomForestModel.load_verified(
            model_path, manifest_path, expected_split_manifest_sha256=""
        )

    with pytest.raises(ValueError, match="expected_preprocessor_artifact_sha256"):
        RandomForestModel.load_verified(
            model_path, manifest_path, expected_preprocessor_artifact_sha256=""
        )

    # Empty top-level split_manifest_sha256 with valid nested split_provenance fails closed
    bad_sm_manifest = dict(base_manifest)
    bad_sm_manifest["split_manifest_sha256"] = ""
    bad_sm_manifest["split_provenance"] = {"split_manifest_sha256": valid_sm}
    manifest_path.write_text(json.dumps(bad_sm_manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="split_manifest_sha256"):
        RandomForestModel.load_verified(model_path, manifest_path)

    # Empty top-level preprocessor_artifact_sha256 with valid nested provenance fails closed
    bad_prep_manifest = dict(base_manifest)
    bad_prep_manifest["preprocessor_artifact_sha256"] = ""
    bad_prep_manifest["preprocessing_provenance"] = {"preprocessor_artifact_sha256": valid_prep}
    manifest_path.write_text(json.dumps(bad_prep_manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="preprocessor_artifact_sha256"):
        RandomForestModel.load_verified(model_path, manifest_path)


def test_load_verified_rejects_incomplete_provenance_or_unknown_git_commit(
    tmp_path, minimal_47_feature_data
):
    """Fail-closed: manifests marking provenance incomplete or git_commit UNKNOWN fail."""
    X, y = minimal_47_feature_data
    model = RandomForestModel()
    model.fit(X, y)

    model_path = tmp_path / "model.joblib"
    actual_sha = model.save(model_path)

    valid_ds = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    valid_sm = "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88"

    manifest_path = tmp_path / "manifest.json"
    base_manifest = {
        "model_artifact_sha256": actual_sha,
        "dataset_sha256": valid_ds,
        "split_manifest_sha256": valid_sm,
    }

    for bad_update, match_pattern in [
        ({"provenance_complete": False}, "incomplete provenance"),
        ({"provenance_status": "INCOMPLETE"}, "incomplete provenance"),
        ({"environment": {"git_commit": "UNKNOWN"}}, "git_commit"),
        ({"environment": {"git_commit": ""}}, "git_commit"),
    ]:
        m = dict(base_manifest)
        m.update(bad_update)
        manifest_path.write_text(json.dumps(m), encoding="utf-8")
        with pytest.raises(ValueError, match=match_pattern):
            RandomForestModel.load_verified(model_path, manifest_path)


def test_check_prerequisites_fails_when_split_manifest_missing_index_sha256(
    tmp_path, mock_split_environment
):
    """Fail-closed: missing index_sha256 in split manifest marks audit BLOCKED."""
    env = mock_split_environment
    sm_data = json.loads(env["manifest_path"].read_text(encoding="utf-8"))
    del sm_data["partitions"]["train"]["index_sha256"]
    env["manifest_path"].write_text(json.dumps(sm_data), encoding="utf-8")

    audit = check_prerequisites(
        dataset_path=tmp_path / "ds.csv",
        split_manifest_path=env["manifest_path"],
        indices_dir=env["indices_dir"],
        preprocessor_artifact_path=tmp_path / "prep.joblib",
        preprocessor_manifest_path=tmp_path / "pm.json",
    )
    assert audit["status"] == "BLOCKED"
    assert any("index_sha256" in msg for msg in audit["missing_prerequisites"])
    assert audit["findings"]["indices_audit"]["status"] == "FAIL"


def test_execute_training_rejects_nan_in_transformed_features(
    tmp_path, mock_split_environment, monkeypatch
):
    """Fail-closed: NaN/Inf in transformed features aborts execute_training before fit."""
    env = mock_split_environment
    rng = np.random.default_rng(42)
    n_total = 10

    data = {col: rng.uniform(0, 100, size=n_total) for col in ML_FEATURE_COLUMNS}
    for col in TRACE_METADATA_COLUMNS:
        data[col] = ["10.0.0.1"] * n_total
    data["Label"] = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
    data["Attack"] = [
        "Benign",
        "Exploits",
        "Benign",
        "DoS",
        "Benign",
        "Fuzzers",
        "Benign",
        "Generic",
        "Benign",
        "Worms",
    ]

    df_raw = pd.DataFrame(data)
    dataset_path = tmp_path / "nan_dataset.csv"
    df_raw.to_csv(dataset_path, index=False)
    actual_dataset_sha = _sha256_file(dataset_path)

    split_manifest_path = env["manifest_path"]
    sm_data = json.loads(split_manifest_path.read_text(encoding="utf-8"))
    sm_data["dataset_sha256"] = actual_dataset_sha
    split_manifest_path.write_text(json.dumps(sm_data), encoding="utf-8")
    indices_dir = env["indices_dir"]
    actual_sm_sha = _sha256_file(split_manifest_path)

    import network_anomaly.preprocessing.pipeline as pp_mod
    import scripts.train_random_forest as trf

    monkeypatch.setattr(trf, "EXPECTED_DATASET_SHA256", actual_dataset_sha)
    monkeypatch.setattr(pp_mod, "EXPECTED_DATASET_SHA256", actual_dataset_sha)

    df_train_only = df_raw.iloc[env["train_idx"]][list(ML_FEATURE_COLUMNS)]
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig())
    prep.dataset_sha256 = actual_dataset_sha
    prep.split_manifest_sha256 = actual_sm_sha
    prep.fit(df_train_only)

    prep_art = tmp_path / "prep.joblib"
    prep_man = tmp_path / "prep_man.json"
    prep.save(prep_art, manifest_path=prep_man)

    orig_transform = TrainOnlyPreprocessor.transform

    def _corrupted_transform(self, df):
        res = orig_transform(self, df).copy()
        res.iloc[0, 0] = np.nan
        return res

    monkeypatch.setattr(TrainOnlyPreprocessor, "transform", _corrupted_transform)

    with pytest.raises(ValueError, match="Transformed X_train contains non-finite values"):
        execute_training(
            dataset_path=dataset_path,
            split_manifest_path=split_manifest_path,
            indices_dir=indices_dir,
            preprocessor_artifact_path=prep_art,
            preprocessor_manifest_path=prep_man,
            output_model_path=tmp_path / "out_model.joblib",
            output_manifest_path=tmp_path / "out_man.json",
        )
