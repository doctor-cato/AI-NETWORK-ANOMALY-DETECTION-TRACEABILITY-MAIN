"""Unit and integration tests for XGBoost baseline training (Issue #31 / C3).

Verifies artifact loading, prerequisite checks, checksum mismatch detection,
strict test-partition isolation, target leakage prevention, XGBoost fit/predict
behavior, save/load roundtrips, manifest schema/runtime provenance, and
fail-closed CLI exit codes using small synthetic 47-feature fixtures.

NOTE: synthetic fixtures here validate pipeline BEHAVIOR only. They are never
presented as experimental benchmark results (see docs/XGB_BASELINE_PROTOCOL.md).
"""

from __future__ import annotations

import json
from pathlib import Path

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
    SPLIT_MANIFEST_SCHEMA_VERSION,
    SPLIT_PROTOCOL_VERSION,
    _sha256_file,
)
from network_anomaly.evaluation.metrics import compute_metrics
from network_anomaly.models.xgboost_model import XGBoostModel
from network_anomaly.models.xgboost_protocol import (
    XGBoostBaselineConfig,
)
from network_anomaly.preprocessing.pipeline import (
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)
from scripts.train_xgboost import (
    DEFAULT_DATASET,
    DEFAULT_PREPROCESSOR_ARTIFACT,
    DEFAULT_PREPROCESSOR_MANIFEST,
    DEFAULT_SPLIT_MANIFEST,
    PartitionAccessTracker,
    check_prerequisites,
    execute_training,
    load_partition,
    main,
    stream_partition_data,
)


@pytest.fixture
def minimal_47_feature_data():
    """Minimal 47-feature synthetic fixture strictly for interface lifecycle tests."""
    rng = np.random.RandomState(42)
    n_samples = 40
    data = {col: rng.uniform(0.0, 100.0, size=n_samples) for col in ML_FEATURE_COLUMNS}
    X = pd.DataFrame(data)
    y = pd.Series(rng.randint(0, 2, size=n_samples), name="Label")
    return X, y


def _build_mock_split_environment(tmp_path):
    """Create a small valid split environment (manifest + index files + CSV)."""
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

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir(parents=True, exist_ok=True)

    def write_idx(name: str, arr: np.ndarray) -> str:
        p = indices_dir / f"{name}_indices.csv.gz"
        pd.DataFrame({"source_row_index": arr}).to_csv(p, index=False, compression="gzip")
        return _sha256_file(p)

    train_sha = write_idx("train", train_idx)
    val_sha = write_idx("validation", val_idx)
    write_idx("test", test_idx)

    split_manifest_path = tmp_path / "split_manifest.json"
    split_manifest_path.write_text(
        json.dumps(
            {
                "manifest_schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
                "dataset_name": DATASET_NAME,
                "dataset_sha256": actual_dataset_sha,
                "split_protocol_version": SPLIT_PROTOCOL_VERSION,
                "total_source_rows": n_rows,
                "audit_summary": {"status": "PASS"},
                "partitions": {
                    "train": {"row_count": len(train_idx), "index_sha256": train_sha},
                    "validation": {"row_count": len(val_idx), "index_sha256": val_sha},
                    "test": {
                        "row_count": len(test_idx),
                        "index_sha256": _sha256_file(indices_dir / "test_indices.csv.gz"),
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    actual_sm_sha = _sha256_file(split_manifest_path)

    return {
        "dataset_path": dataset_path,
        "split_manifest_path": split_manifest_path,
        "indices_dir": indices_dir,
        "train_idx": train_idx,
        "val_idx": val_idx,
        "test_idx": test_idx,
        "df_raw": df_raw,
        "dataset_sha": actual_dataset_sha,
        "split_manifest_sha": actual_sm_sha,
    }


@pytest.fixture
def mock_split_environment(tmp_path):
    return _build_mock_split_environment(tmp_path)


@pytest.fixture
def patch_dataset_sha(monkeypatch):
    """Patch EXPECTED_DATASET_SHA256 in all consumer modules to the fixture value."""
    import network_anomaly.preprocessing.pipeline as pp_mod
    import scripts.train_xgboost as txgb

    def _patch(value: str):
        monkeypatch.setattr(pp_mod, "EXPECTED_DATASET_SHA256", value)
        monkeypatch.setattr(txgb, "EXPECTED_DATASET_SHA256", value)

    return _patch


@pytest.fixture
def fitted_preprocessor_fixture(mock_split_environment, patch_dataset_sha):
    """Fit and save a TrainOnlyPreprocessor on the fixture train partition."""
    env = mock_split_environment
    patch_dataset_sha(env["dataset_sha"])
    df_train_only = env["df_raw"].iloc[env["train_idx"]][list(ML_FEATURE_COLUMNS)]
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig())
    prep.dataset_sha256 = env["dataset_sha"]
    prep.split_manifest_sha256 = env["split_manifest_sha"]
    prep.fit(df_train_only)
    return env, prep


def test_unfitted_model_cannot_be_saved(tmp_path):
    model = XGBoostModel()
    with pytest.raises(NotFittedError):
        model.save(tmp_path / "model.joblib")


def test_model_fit_predict_predict_proba(minimal_47_feature_data):
    X, y = minimal_47_feature_data
    model = XGBoostModel()
    assert model.is_fitted is False
    model.fit(X, y)
    assert model.is_fitted is True
    preds = model.predict(X)
    assert preds.shape == (len(X),)
    assert set(np.unique(preds)).issubset({0, 1})
    probs = model.predict_proba(X)
    assert probs.shape == (len(X), 2)
    assert np.allclose(probs.sum(axis=1), 1.0, atol=1e-5)
    assert not np.isnan(probs).any()


def test_model_predict_parity_dataframe_and_matrix(minimal_47_feature_data):
    X, y = minimal_47_feature_data
    model = XGBoostModel(XGBoostBaselineConfig()).fit(X, y)
    preds_df = model.predict(X)
    preds_mat = model.predict(X[list(ML_FEATURE_COLUMNS)].values)
    assert np.array_equal(preds_df, preds_mat)


def test_model_predict_rejects_missing_features(minimal_47_feature_data):
    X, y = minimal_47_feature_data
    model = XGBoostModel().fit(X, y)
    dropped_col = ML_FEATURE_COLUMNS[0]
    broken = X.drop(columns=[dropped_col])
    with pytest.raises(ValueError, match="missing required features"):
        model.predict(broken)
    with pytest.raises(ValueError, match="missing required features"):
        model.predict_proba(broken)


def test_model_rejects_duplicate_columns(minimal_47_feature_data):
    X, y = minimal_47_feature_data
    model = XGBoostModel().fit(X, y)
    dcol = ML_FEATURE_COLUMNS[2]
    X_dup = pd.concat([X, X[[dcol]]], axis=1)
    assert X_dup.columns.duplicated().any()
    with pytest.raises(ValueError, match="Duplicate columns"):
        model.predict(X_dup)


def test_model_rejects_non_finite_input(minimal_47_feature_data):
    X, y = minimal_47_feature_data
    X = X.copy()
    X.loc[0, "FLOW_DURATION_MILLISECONDS"] = np.nan
    model = XGBoostModel()
    with pytest.raises(ValueError, match="non-finite"):
        model.fit(X, y)


def test_model_rejects_invalid_labels(minimal_47_feature_data):
    X, _ = minimal_47_feature_data
    model = XGBoostModel()
    with pytest.raises(ValueError, match="binary"):
        model.fit(X.iloc[:10], np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]))
    with pytest.raises(ValueError, match="row mismatch"):
        model.fit(X.iloc[:10], np.array([0, 1]))


def test_model_rejects_feature_count_mismatch(minimal_47_feature_data):
    X, y = minimal_47_feature_data
    model = XGBoostModel()
    with pytest.raises(ValueError, match="Feature dimension mismatch"):
        model.fit(X.values[:, :46], y)


def test_model_save_load_roundtrip(tmp_path, minimal_47_feature_data):
    X, y = minimal_47_feature_data
    model = XGBoostModel().fit(X, y)
    model_path = tmp_path / "xgb_model.joblib"
    artifact_sha = model.save(model_path)
    assert isinstance(artifact_sha, str) and len(artifact_sha) == 64
    assert model_path.exists()

    loaded = XGBoostModel.load(model_path)
    assert loaded.is_fitted is True
    assert loaded.feature_names == model.feature_names
    assert loaded.config.to_dict() == model.config.to_dict()
    assert set(np.unique(loaded.predict(X))).issubset({0, 1})
    assert np.array_equal(loaded.predict(X), model.predict(X))
    assert np.array_equal(loaded.predict_proba(X), model.predict_proba(X))


def test_model_load_verified_and_tamper_detection(tmp_path, minimal_47_feature_data):
    X, y = minimal_47_feature_data
    model = XGBoostModel().fit(X, y)
    model_path = tmp_path / "xgb_model.joblib"
    manifest_path = tmp_path / "xgb_manifest.json"
    model.save(model_path, manifest_path=manifest_path)

    # API-only save has no runtime provenance evidence and must not manufacture a
    # VERIFIED manifest.  Plain load remains available for synthetic round-trips.
    with pytest.raises(ValueError, match="incomplete provenance"):
        XGBoostModel.load_verified(model_path=model_path, manifest_path=manifest_path)

    # Mismatched expected_sha256 must fail closed
    with pytest.raises(ValueError, match="Invalid or malformed"):
        XGBoostModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_sha256="0" * 64,
        )

    # Tampered artifact must fail closed
    model_path.write_bytes(model_path.read_bytes()[:-4] + b"AAAA")
    with pytest.raises(ValueError, match="Integrity check failed"):
        XGBoostModel.load_verified(model_path=model_path, manifest_path=manifest_path)


def test_load_verified_rejects_missing_artifact_and_manifest(tmp_path, minimal_47_feature_data):
    with pytest.raises(FileNotFoundError):
        XGBoostModel.load_verified(
            model_path=tmp_path / "absent.joblib",
            manifest_path=tmp_path / "absent_manifest.json",
        )

    X, y = minimal_47_feature_data
    model = XGBoostModel().fit(X, y)
    model_path = tmp_path / "xgb_model.joblib"
    model.save(model_path)
    # Missing manifest_path must fail closed
    with pytest.raises(ValueError, match="Companion manifest path is required"):
        XGBoostModel.load_verified(model_path=model_path)


def test_check_prerequisites_passes_on_mock_environment(mock_split_environment, patch_dataset_sha):
    env = mock_split_environment
    patch_dataset_sha(env["dataset_sha"])
    audit = check_prerequisites(
        env["dataset_path"],
        env["split_manifest_path"],
        env["indices_dir"],
        Path("absent_preprocessor.joblib"),
        Path("absent_manifest.json"),
    )
    # Everything except the (still missing) preprocessor must pass cleanly.
    assert audit["findings"]["dataset"]["status"] == "PASS"
    assert audit["findings"]["split_manifest"]["status"] == "PASS"
    assert audit["findings"]["indices"]["status"] == "PASS"
    assert audit["status"] == "BLOCKED"
    assert any("Preprocessor artifact not found" in m for m in audit["missing_prerequisites"])


def test_check_prerequisites_detects_dataset_hash_mismatch(
    mock_split_environment, patch_dataset_sha
):
    env = mock_split_environment
    audit = check_prerequisites(
        env["dataset_path"],
        env["split_manifest_path"],
        env["indices_dir"],
        Path("absent.joblib"),
        Path("absent.json"),
    )
    assert audit["findings"]["dataset"]["status"] == "FAIL"
    assert audit["status"] == "BLOCKED"


def test_check_prerequisites_detects_missing_files(tmp_path):
    audit = check_prerequisites(
        tmp_path / "no.csv",
        tmp_path / "no_manifest.json",
        tmp_path / "no_indices",
        tmp_path / "no.joblib",
        tmp_path / "no_pm.json",
    )
    assert audit["status"] == "BLOCKED"
    assert len(audit["missing_prerequisites"]) >= 5


def test_check_prerequisites_detects_index_hash_mismatch(mock_split_environment, patch_dataset_sha):
    env = mock_split_environment
    patch_dataset_sha(env["dataset_sha"])
    # Corrupt train index file: rewrite bytes with different content
    train_idx_path = env["indices_dir"] / "train_indices.csv.gz"
    pd.DataFrame({"source_row_index": list(env["train_idx"]) * 2}).to_csv(
        train_idx_path, index=False, compression="gzip"
    )
    audit = check_prerequisites(
        env["dataset_path"],
        env["split_manifest_path"],
        env["indices_dir"],
        Path("absent.joblib"),
        Path("absent.json"),
    )
    assert audit["findings"]["indices"]["status"] == "FAIL"


def test_check_prerequisites_detects_split_manifest_schema_violation(
    mock_split_environment, patch_dataset_sha
):
    env = mock_split_environment
    patch_dataset_sha(env["dataset_sha"])
    manifest = json.loads(env["split_manifest_path"].read_text(encoding="utf-8"))
    manifest["manifest_schema_version"] = 99
    env["split_manifest_path"].write_text(json.dumps(manifest), encoding="utf-8")
    audit = check_prerequisites(
        env["dataset_path"],
        env["split_manifest_path"],
        env["indices_dir"],
        Path("absent.joblib"),
        Path("absent.json"),
    )
    assert audit["findings"]["split_manifest"]["status"] == "FAIL"


def test_load_partition_blocks_test_partition(mock_split_environment):
    env = mock_split_environment
    tracker = PartitionAccessTracker()
    with pytest.raises(PermissionError):
        load_partition(env["split_manifest_path"], env["indices_dir"], "test", tracker=tracker)
    assert tracker.test_partition_accessed is True
    assert tracker.test_indices_loaded is True


def test_stream_partition_data_strict_test_isolation(mock_split_environment):
    env = mock_split_environment
    tracker = PartitionAccessTracker()
    usecols = list(ML_FEATURE_COLUMNS) + ["Label", "Attack"]
    df_train, df_val = stream_partition_data(
        dataset_path=env["dataset_path"],
        train_indices=env["train_idx"],
        val_indices=env["val_idx"],
        usecols=usecols,
        tracker=tracker,
    )
    assert len(df_train) == len(env["train_idx"])
    assert len(df_val) == len(env["val_idx"])
    assert tracker.test_rows_loaded == 0
    assert tracker.test_partition_accessed is False
    expected_rows = set(env["train_idx"]) | set(env["val_idx"])
    test_rows = set(env["test_idx"])
    assert not (test_rows & expected_rows)


def test_stream_partition_data_detects_overlap_leakage(mock_split_environment):
    env = mock_split_environment
    with pytest.raises(ValueError, match="overlap"):
        stream_partition_data(
            dataset_path=env["dataset_path"],
            train_indices=env["train_idx"],
            val_indices=np.array([0, 1, 2], dtype=np.int64),
            usecols=list(ML_FEATURE_COLUMNS) + ["Label", "Attack"],
        )


def test_execute_training_full_pipeline_mock_integration(
    tmp_path, mock_split_environment, patch_dataset_sha
):
    """End-to-end integration test of execute_training on a tiny synthetic fixture."""
    env = mock_split_environment
    patch_dataset_sha(env["dataset_sha"])

    df_train_only = env["df_raw"].iloc[env["train_idx"]][list(ML_FEATURE_COLUMNS)]
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig())
    prep.dataset_sha256 = env["dataset_sha"]
    prep.split_manifest_sha256 = env["split_manifest_sha"]
    prep.fit(df_train_only)

    preprocessor_artifact_path = tmp_path / "preprocessor.joblib"
    preprocessor_manifest_path = tmp_path / "preprocessor_manifest.json"
    prep.save(preprocessor_artifact_path, manifest_path=preprocessor_manifest_path)

    output_model_path = tmp_path / "xgb_baseline.joblib"
    output_manifest_path = tmp_path / "xgb_manifest.json"

    manifest = execute_training(
        dataset_path=env["dataset_path"],
        split_manifest_path=env["split_manifest_path"],
        indices_dir=env["indices_dir"],
        preprocessor_artifact_path=preprocessor_artifact_path,
        preprocessor_manifest_path=preprocessor_manifest_path,
        output_model_path=output_model_path,
        output_manifest_path=output_manifest_path,
        report_md_path=tmp_path / "xgb_report.md",
    )

    assert output_model_path.exists()
    assert output_manifest_path.exists()

    # Test Lock audit evidence
    assert manifest["test_lock_audit"]["test_partition_accessed"] is False
    assert manifest["test_lock_audit"]["test_rows_loaded"] == 0
    assert manifest["test_lock_audit"]["train_rows_loaded"] == len(env["train_idx"])
    assert manifest["test_lock_audit"]["val_rows_loaded"] == len(env["val_idx"])

    # Model contract
    assert manifest["model_type"] == "XGBoost"
    assert manifest["task"] == "binary_classification"
    assert manifest["target"] == "Label"
    assert manifest["num_features"] == 47
    assert len(manifest["selected_features"]) == 47
    assert manifest["selected_features"] == list(ML_FEATURE_COLUMNS)
    assert "Label" not in manifest["selected_features"]
    assert "Attack" not in manifest["selected_features"]
    assert not any(m in manifest["selected_features"] for m in TRACE_METADATA_COLUMNS)
    assert manifest["label_policy"]["positive_label"] == 1
    assert manifest["label_policy"]["confusion_matrix_label_order"] == [0, 1]

    # Provenance + metrics schema
    assert manifest["provenance_complete"] is True
    assert manifest["split_provenance"]["verification_status"] == "PASS"
    assert manifest["preprocessing_provenance"]["verification_status"] == "PASS"
    assert manifest["preprocessing_provenance"]["refit_during_training"] is False
    assert "precision" in manifest["validation_summary"]
    assert "recall" in manifest["validation_summary"]
    assert "f1" in manifest["validation_summary"]
    assert "macro_f1" in manifest["validation_summary"]
    assert "false_positive_rate" in manifest["validation_summary"]
    assert manifest["validation_summary"]["confusion_matrix_labeled"] == {
        "tn": manifest["validation_summary"]["confusion_matrix"][0][0],
        "fp": manifest["validation_summary"]["confusion_matrix"][0][1],
        "fn": manifest["validation_summary"]["confusion_matrix"][1][0],
        "tp": manifest["validation_summary"]["confusion_matrix"][1][1],
    }
    assert manifest["reload_verification"]["status"] == "PASSED"
    assert manifest["environment"]["packages"]["xgboost"]
    assert manifest["model_artifact_sha256"] == _sha256_file(output_model_path)

    # Verified reload through the public API
    reloaded = XGBoostModel.load_verified(
        model_path=output_model_path,
        manifest_path=output_manifest_path,
    )
    assert reloaded.is_fitted is True
    assert reloaded.feature_names == model_feature_names(manifest)

    # Overwrite guard
    with pytest.raises(RuntimeError, match="overwrite"):
        execute_training(
            dataset_path=env["dataset_path"],
            split_manifest_path=env["split_manifest_path"],
            indices_dir=env["indices_dir"],
            preprocessor_artifact_path=preprocessor_artifact_path,
            preprocessor_manifest_path=preprocessor_manifest_path,
            output_model_path=output_model_path,
            output_manifest_path=output_manifest_path,
        )


def model_feature_names(manifest):
    return tuple(manifest["selected_features"])


def test_compute_validation_metrics_contract():
    y_true = np.array([0, 0, 1, 1, 1])
    y_pred = np.array([0, 1, 1, 1, 0])
    metrics = compute_metrics(y_true, y_pred, labels=[0, 1])
    assert metrics["confusion_matrix"] == [[1, 1], [1, 2]]
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["precision"] == pytest.approx(2 / 3)
    assert metrics["recall"] == pytest.approx(2 / 3)
    assert metrics["macro_f1"] == pytest.approx((0.5 + (2 / 3)) / 2)


def test_cli_verify_only_exit_codes(mock_split_environment, patch_dataset_sha, capsys):
    env = mock_split_environment
    patch_dataset_sha(env["dataset_sha"])
    # Prerequisites incomplete (no preprocessor) → exit code 1
    rc = main(["--verify-only"])
    assert rc == 1

    # Prerequisites complete → verify-only exits 0
    df_train_only = env["df_raw"].iloc[env["train_idx"]][list(ML_FEATURE_COLUMNS)]
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig())
    prep.dataset_sha256 = env["dataset_sha"]
    prep.split_manifest_sha256 = env["split_manifest_sha"]
    prep.fit(df_train_only)
    artifact_path = env["dataset_path"].parent / "preprocessor.joblib"
    artifact_manifest = env["dataset_path"].parent / "preprocessor_manifest.json"
    prep.save(artifact_path, manifest_path=artifact_manifest)

    rc = main(
        [
            "--verify-only",
            "--dataset",
            str(env["dataset_path"]),
            "--split-manifest",
            str(env["split_manifest_path"]),
            "--indices-dir",
            str(env["indices_dir"]),
            "--preprocessor-artifact",
            str(artifact_path),
            "--preprocessor-manifest",
            str(artifact_manifest),
        ]
    )
    assert rc == 0


def test_cli_train_mock_fails_cleanly_without_artifacts(tmp_path, capsys):
    rc = main(
        [
            "--verify-only",
            "--dataset",
            str(tmp_path / "missing.csv"),
            "--split-manifest",
            str(tmp_path / "missing_manifest.json"),
            "--indices-dir",
            str(tmp_path / "missing_indices"),
            "--preprocessor-artifact",
            str(tmp_path / "missing.joblib"),
            "--preprocessor-manifest",
            str(tmp_path / "missing_pm.json"),
        ]
    )
    assert rc == 1


@pytest.mark.skipif(
    not DEFAULT_DATASET.exists()
    or not DEFAULT_SPLIT_MANIFEST.exists()
    or not DEFAULT_PREPROCESSOR_ARTIFACT.exists()
    or not DEFAULT_PREPROCESSOR_MANIFEST.exists(),
    reason="Real NF-UNSW-NB15-v3 dataset CSV or preprocessor artifact not present in workspace",
)
def test_check_prerequisites_passes_on_real_artifacts():
    """Real-data gate: when dataset + artifacts exist, the audit must PASS."""
    audit = check_prerequisites(
        DEFAULT_DATASET,
        DEFAULT_SPLIT_MANIFEST,
        Path(__file__).resolve().parents[2] / "data" / "processed" / "splits",
        DEFAULT_PREPROCESSOR_ARTIFACT,
        DEFAULT_PREPROCESSOR_MANIFEST,
    )
    assert audit["status"] == "PASS", audit["missing_prerequisites"]

    rc = main(
        [
            "--verify-only",
            "--split-manifest",
            str(DEFAULT_SPLIT_MANIFEST),
            "--preprocessor-artifact",
            str(DEFAULT_PREPROCESSOR_ARTIFACT),
            "--preprocessor-manifest",
            str(DEFAULT_PREPROCESSOR_MANIFEST),
        ]
    )
    assert rc == 0
