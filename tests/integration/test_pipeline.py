#!/usr/bin/env python3
"""Integration tests for NF-UNSW-NB15-v3 ML pipeline components (Issue #17).

Covers:
1. Preprocessing Integration:
   - Fit on synthetic training flows, transform, save artifact and companion manifest.
   - Verify artifact integrity with verify_preprocessing_artifact.
   - Reload via TrainOnlyPreprocessor.load_verified and verify transformation invariance.
   - Fail-closed error guards (tampering, missing artifact, corrupted file).
2. Model Artifact Integration:
   - Fit RandomForestModel on transformed synthetic features.
   - Save artifact and companion manifest.
   - Load via RandomForestModel.load and load_verified.
   - Verification of prediction invariance and probability invariance.
   - Fail-closed rejection of unfitted models, corrupted files, and SHA-256 mismatches.
3. End-to-End Pipeline Integration:
   - CSV Input -> Schema Validation -> Load Preprocessor -> Transform -> Load Model ->
     Predict -> Export CSV -> Metadata Generation.
   - Row identity preservation, 47 canonical features contract, zero target/trace leakage.
   - Output CSV structure, probability columns, companion metadata JSON.
   - Input file immutability, repeated inference determinism.
   - Cross-artifact compatibility (preprocessor SHA-256 enforcement).
   - Unsupervised Isolation Forest pipeline integration.
4. Failure Paths:
   - Missing input file, empty CSV, missing features, invalid feature values.
5. Real-Data Smoke Checks:
   - Real preprocessor artifact verification (explicit skip if absent; never silent pass).
   - Real model artifact verification (explicit skip when binary excluded by .gitignore).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.exceptions import NotFittedError

from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import (
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.inference import (
    InferenceResult,
    run_inference,
)
from network_anomaly.inference.pipeline import predict_from_artifact
from network_anomaly.inference.predict import _sha256_file
from network_anomaly.models.isolation_forest import build_model as build_isolation_forest
from network_anomaly.models.random_forest import (
    RandomForestBaselineConfig,
    RandomForestModel,
    create_rf_baseline_protocol,
)
from network_anomaly.preprocessing import (
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_POLICY_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
    verify_preprocessing_artifact,
)
from network_anomaly.preprocessing.pipeline import EXPECTED_DATASET_SHA256

# =========================================================================
# Synthetic Fixtures for Integration Testing
# =========================================================================


@pytest.fixture
def synthetic_pipeline_setup(
    tmp_path: Path,
) -> Tuple[Path, Path, Path, Path, Path]:
    """Create synthetic input CSV, fitted preprocessor, and fitted RandomForest artifacts."""
    rng = np.random.default_rng(seed=42)
    n_rows = 40

    # 1. Generate synthetic network flow features adhering to the 47-feature schema
    data: Dict[str, np.ndarray] = {}
    for col in ML_FEATURE_COLUMNS:
        if col in CATEGORICAL_CODED_COLUMNS:
            data[col] = rng.integers(0, 5, size=n_rows)
        elif "DURATION" in col or "BYTES" in col or "PKTS" in col or "THROUGHPUT" in col:
            data[col] = np.abs(rng.normal(loc=100.0, scale=20.0, size=n_rows)) + 1.0
        else:
            data[col] = np.abs(rng.normal(loc=50.0, scale=10.0, size=n_rows))

    df_full = pd.DataFrame(data, columns=list(ML_FEATURE_COLUMNS))

    # Add trace metadata and target columns to verify pipeline isolation
    for col in TRACE_METADATA_COLUMNS:
        if "ADDR" in col:
            df_full[col] = "192.168.1.1"
        else:
            df_full[col] = 80
    df_full["Label"] = np.array([0 if i % 2 == 0 else 1 for i in range(n_rows)])
    df_full["Attack"] = np.array(["Benign" if i % 2 == 0 else "Exploits" for i in range(n_rows)])
    df_full["row_id"] = [f"test_flow_{i:03d}" for i in range(n_rows)]

    input_csv_path = tmp_path / "incoming_flows.csv"
    df_full.to_csv(input_csv_path, index=False)

    # 2. Fit TrainOnlyPreprocessor on train-only features (47 features, no targets/trace)
    split_manifest_dummy_sha = "b" * 64
    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256=split_manifest_dummy_sha,
    )
    df_train_only = df_full[list(ML_FEATURE_COLUMNS)].copy()
    prep.fit(df_train_only)

    prep_art_path = tmp_path / "artifacts" / "test_preprocessor.joblib"
    prep_man_path = tmp_path / "reports" / "test_preprocessor_manifest.json"
    prep_sha = prep.save(artifact_path=prep_art_path, manifest_path=prep_man_path)

    # 3. Fit RandomForestModel on preprocessed features
    X_trans = prep.transform(df_train_only, partition_name="train")
    y_train = df_full["Label"].to_numpy()

    rf = RandomForestModel(
        config=RandomForestBaselineConfig(
            n_estimators=5,
            max_depth=3,
            random_state=42,
        )
    )
    rf.fit(X_trans, y_train)

    model_art_path = tmp_path / "artifacts" / "test_rf_model.joblib"
    model_man_path = tmp_path / "reports" / "test_rf_manifest.json"
    model_sha = rf.save(model_art_path)

    model_manifest_data = {
        "run_id": "integration-pipeline-rf-001",
        "model_type": "RandomForest",
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "model_artifact_path": str(model_art_path.name),
        "model_artifact_sha256": model_sha,
        "preprocessor_artifact_sha256": prep_sha,
        "dataset_sha256": EXPECTED_DATASET_SHA256,
        "split_manifest_sha256": split_manifest_dummy_sha,
        "provenance_complete": True,
        "provenance_status": "VERIFIED",
        "environment": {"git_commit": "abcdef12345678"},
        "class_mapping": {"0": "Benign", "1": "Attack"},
        "hyperparameters": {"n_estimators": 5, "max_depth": 3, "random_state": 42},
    }
    model_man_path.parent.mkdir(parents=True, exist_ok=True)
    model_man_path.write_text(json.dumps(model_manifest_data, indent=2) + "\n", encoding="utf-8")

    return input_csv_path, prep_art_path, prep_man_path, model_art_path, model_man_path


# =========================================================================
# 1. Preprocessing Integration Tests
# =========================================================================


def test_preprocessing_pipeline_integration(tmp_path: Path):
    """Verify TrainOnlyPreprocessor lifecycle: fit, transform, save, verify, and reload."""
    rng = np.random.default_rng(seed=101)
    n_rows = 30
    data = {
        col: (
            rng.integers(0, 4, size=n_rows)
            if col in CATEGORICAL_CODED_COLUMNS
            else np.abs(rng.normal(loc=10.0, scale=2.0, size=n_rows)) + 0.1
        )
        for col in ML_FEATURE_COLUMNS
    }
    df = pd.DataFrame(data, columns=list(ML_FEATURE_COLUMNS))

    # Preprocessor initialization contract
    config = PreprocessingConfig(scaler_type="none")
    split_sha = "c" * 64
    preprocessor = TrainOnlyPreprocessor(
        config=config,
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256=split_sha,
    )
    assert preprocessor.is_fitted_ is False
    assert FEATURE_CONTRACT_VERSION == "nf-unsw-nb15-v3-baseline-47"
    assert PREPROCESSING_POLICY_VERSION == "nf-unsw-nb15-v3-preprocessing-v1"

    # Fit and transform
    preprocessor.fit(df)
    assert preprocessor.is_fitted_ is True
    assert preprocessor.train_row_count_ == n_rows
    transformed_orig = preprocessor.transform(df, partition_name="val")
    assert transformed_orig.shape == (n_rows, 47)

    # Save artifact and companion manifest
    art_path = tmp_path / "artifacts" / "prep.joblib"
    man_path = tmp_path / "reports" / "prep_manifest.json"
    art_sha = preprocessor.save(art_path, man_path)
    assert art_path.is_file()
    assert man_path.is_file()
    assert len(art_sha) == 64

    # Verify companion manifest and SHA-256
    v_res = verify_preprocessing_artifact(art_path, manifest_path=man_path)
    assert v_res["status"] == "PASS"
    assert v_res["metadata"]["train_row_count"] == n_rows

    # Reload verified and ensure identical transformations
    reloaded = TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)
    assert reloaded.is_fitted_ is True
    assert reloaded.train_row_count_ == n_rows
    transformed_reloaded = reloaded.transform(df, partition_name="inference")
    np.testing.assert_allclose(transformed_orig, transformed_reloaded, rtol=1e-6, atol=1e-6)

    # Ensure transforms do not mutate fitted state
    assert reloaded.is_fitted_ is True
    assert reloaded.train_row_count_ == n_rows


def test_preprocessing_failure_paths_fail_closed(tmp_path: Path):
    """Verify that tampered, missing, or corrupted preprocessors fail closed."""
    art_path = tmp_path / "missing_prep.joblib"
    man_path = tmp_path / "prep_manifest.json"

    # 1. Missing artifact file fails closed
    v_res = verify_preprocessing_artifact(art_path, manifest_path=man_path)
    assert v_res["status"] == "FAIL"
    assert any("Artifact file not found" in err for err in v_res["errors"])
    with pytest.raises(ValueError, match="Artifact file not found"):
        TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)

    # 2. Corrupted artifact content
    art_path.parent.mkdir(parents=True, exist_ok=True)
    art_path.write_bytes(b"corrupted invalid bytes")
    man_data = {
        "artifact_path": str(art_path),
        "artifact_sha256": _sha256_file(art_path),
        "dataset_sha256": EXPECTED_DATASET_SHA256,
        "split_manifest_sha256": "d" * 64,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "train_row_count": 100,
        "fitted_at_utc": "2026-01-01T00:00:00Z",
    }
    man_path.parent.mkdir(parents=True, exist_ok=True)
    man_path.write_text(json.dumps(man_data), encoding="utf-8")

    with pytest.raises((ValueError, RuntimeError)):
        TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)

    # 3. Hash mismatch in companion manifest
    man_data["artifact_sha256"] = "e" * 64
    man_path.write_text(json.dumps(man_data), encoding="utf-8")
    fail_res = verify_preprocessing_artifact(art_path, manifest_path=man_path)
    assert fail_res["status"] == "FAIL"
    assert any("SHA-256 mismatch" in err for err in fail_res["errors"])
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)


# =========================================================================
# 2. Model Artifact Integration Tests
# =========================================================================


def test_random_forest_model_artifact_integration(tmp_path: Path):
    """Verify RandomForestModel fitting, saving, verified reload, and prediction invariance."""
    rng = np.random.default_rng(seed=88)
    n_samples = 30
    X = rng.normal(loc=0.0, scale=1.0, size=(n_samples, 47))
    y = np.array([0 if i % 2 == 0 else 1 for i in range(n_samples)])

    protocol = create_rf_baseline_protocol(
        n_estimators=5,
        max_depth=3,
        random_seed=42,
    )
    model = RandomForestModel(protocol=protocol)
    assert model.is_fitted is False

    # Unfitted model cannot be saved or used for prediction
    art_path = tmp_path / "rf.joblib"
    with pytest.raises(NotFittedError):
        model.save(art_path)
    with pytest.raises(NotFittedError):
        model.predict(X)

    # Fit model
    model.fit(X, y)
    assert model.is_fitted is True
    orig_preds = model.predict(X)
    orig_probas = model.predict_proba(X)

    # Save model artifact
    saved_sha = model.save(art_path)
    assert art_path.is_file()
    assert len(saved_sha) == 64

    # Reload via standard load()
    loaded_model = RandomForestModel.load(art_path)
    assert loaded_model.is_fitted is True
    reloaded_preds = loaded_model.predict(X)
    reloaded_probas = loaded_model.predict_proba(X)
    np.testing.assert_array_equal(orig_preds, reloaded_preds)
    np.testing.assert_allclose(orig_probas, reloaded_probas, rtol=1e-6, atol=1e-6)

    # Save manifest and verify via load_verified()
    man_path = tmp_path / "rf_manifest.json"
    dummy_split_sha = "f" * 64
    manifest = {
        "model_artifact_path": str(art_path.name),
        "model_artifact_sha256": saved_sha,
        "dataset_sha256": EXPECTED_DATASET_SHA256,
        "split_manifest_sha256": dummy_split_sha,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "model_type": "RandomForest",
        "provenance_complete": True,
        "provenance_status": "VERIFIED",
        "environment": {"git_commit": "abcdef12345678"},
    }
    man_path.write_text(json.dumps(manifest), encoding="utf-8")

    verified_model = RandomForestModel.load_verified(
        art_path,
        manifest_path=man_path,
        expected_dataset_sha256=EXPECTED_DATASET_SHA256,
        expected_split_manifest_sha256=dummy_split_sha,
    )
    assert verified_model.is_fitted is True
    np.testing.assert_array_equal(orig_preds, verified_model.predict(X))


def test_random_forest_verification_failure_paths(tmp_path: Path):
    """Verify that tampered model artifacts or manifests fail closed."""
    art_path = tmp_path / "model.joblib"
    art_path.write_bytes(b"corrupt model content")
    man_path = tmp_path / "manifest.json"

    # Missing manifest
    with pytest.raises(FileNotFoundError):
        RandomForestModel.load_verified(art_path, manifest_path=man_path)

    # SHA-256 mismatch in manifest
    manifest = {
        "model_artifact_path": str(art_path.name),
        "model_artifact_sha256": "0" * 64,  # incorrect hash
        "dataset_sha256": EXPECTED_DATASET_SHA256,
        "split_manifest_sha256": "1" * 64,
        "provenance_complete": True,
        "provenance_status": "VERIFIED",
        "environment": {"git_commit": "abcdef12345678"},
    }
    man_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        RandomForestModel.load_verified(art_path, manifest_path=man_path)


# =========================================================================
# 3. End-to-End Pipeline Integration Tests
# =========================================================================


def test_isolation_forest_load():
    """Verify Isolation Forest construction, fitting on synthetic data, and scoring."""
    m = build_isolation_forest()
    assert m is not None

    rng = np.random.default_rng(seed=42)
    X = rng.normal(size=(20, 47))
    m.fit(X)

    preds = m.predict(X)
    assert len(preds) == 20
    assert set(preds).issubset({-1, 1})

    scores = m.decision_function(X)
    assert len(scores) == 20
    assert scores.dtype == np.float64


def test_inference_module_resolves_artifact_location():
    """Verify artifact path resolution and legacy predict_from_artifact compatibility."""
    assert ARTIFACTS.name == "artifacts"
    assert callable(predict_from_artifact)


def test_end_to_end_pipeline_integration(
    synthetic_pipeline_setup: Tuple[Path, Path, Path, Path, Path],
    tmp_path: Path,
):
    """Verify complete end-to-end inference flow:
    CSV -> Schema -> Preprocess -> Model -> Predict.
    """
    input_csv, prep_art, prep_man, model_art, model_man = synthetic_pipeline_setup
    output_csv = tmp_path / "output" / "predictions.csv"

    input_sha_before = _sha256_file(input_csv)

    result = run_inference(
        input_path=input_csv,
        output_path=output_csv,
        model_artifact_path=model_art,
        preprocessor_artifact_path=prep_art,
        model_manifest_path=model_man,
        preprocessor_manifest_path=prep_man,
    )

    # 1. Output structure and row count
    assert isinstance(result, InferenceResult)
    assert isinstance(result, InferenceResult)
    assert output_csv.is_file()
    df_out = pd.read_csv(output_csv)
    assert len(df_out) == 40

    # 2. Row identity preservation
    assert "row_id" in df_out.columns
    assert list(df_out["row_id"]) == [f"test_flow_{i:03d}" for i in range(40)]

    # 3. Predictions and probability columns
    assert "prediction" in df_out.columns
    assert "probability_Benign" in df_out.columns
    assert "probability_Attack" in df_out.columns
    assert set(df_out["prediction"].unique()).issubset({0, 1})

    # 4. Traceability identifiers
    assert "model_artifact_sha256" in df_out.columns
    assert "preprocessor_artifact_sha256" in df_out.columns
    assert df_out["model_artifact_sha256"].iloc[0] == _sha256_file(model_art)
    assert df_out["preprocessor_artifact_sha256"].iloc[0] == _sha256_file(prep_art)

    # 5. Companion metadata JSON
    meta_path = output_csv.with_name(f"{output_csv.stem}.metadata.json")
    assert meta_path.is_file()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["execution_status"] == "SUCCESS"
    assert meta["input_row_count"] == 40
    assert meta["prediction_count"] == 40
    assert meta["error_count"] == 0
    assert meta["feature_contract_version"] == FEATURE_CONTRACT_VERSION
    assert meta["output_file_sha256"] == _sha256_file(output_csv)
    assert meta["input_file_sha256"] == input_sha_before

    # 6. Immutability: input CSV file was not modified
    assert _sha256_file(input_csv) == input_sha_before

    # 7. Reproducibility: second run on same input gives identical predictions
    out2 = tmp_path / "output" / "predictions_run2.csv"
    run_inference(
        input_path=input_csv,
        output_path=out2,
        model_artifact_path=model_art,
        preprocessor_artifact_path=prep_art,
        model_manifest_path=model_man,
        preprocessor_manifest_path=prep_man,
        run_id="run-deterministic-01",
    )
    df_out2 = pd.read_csv(out2)
    pd.testing.assert_series_equal(df_out["prediction"], df_out2["prediction"])
    pd.testing.assert_series_equal(df_out["probability_Attack"], df_out2["probability_Attack"])


def test_end_to_end_pipeline_with_isolation_forest(
    synthetic_pipeline_setup: Tuple[Path, Path, Path, Path, Path],
    tmp_path: Path,
):
    """Verify inference pipeline execution with unsupervised Isolation Forest model."""
    input_csv, prep_art, prep_man, _, _ = synthetic_pipeline_setup
    output_csv = tmp_path / "if_output" / "if_predictions.csv"

    # Fit small IsolationForest on preprocessed feature DataFrame to preserve feature names
    df_input = pd.read_csv(input_csv)
    prep = TrainOnlyPreprocessor.load_verified(prep_art, manifest_path=prep_man)
    X_trans = prep.transform(df_input[list(ML_FEATURE_COLUMNS)], partition_name="train")

    if_model = build_isolation_forest()
    if_model.fit(X_trans)

    if_art = tmp_path / "artifacts" / "if_model.joblib"
    joblib.dump(if_model, if_art)
    if_sha = _sha256_file(if_art)

    if_man = tmp_path / "reports" / "if_manifest.json"
    if_manifest_data = {
        "model_type": "IsolationForest",
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "model_artifact_path": str(if_art.name),
        "model_artifact_sha256": if_sha,
        "preprocessor_artifact_sha256": _sha256_file(prep_art),
    }
    if_man.write_text(json.dumps(if_manifest_data), encoding="utf-8")

    result = run_inference(
        input_path=input_csv,
        output_path=output_csv,
        model_artifact_path=if_art,
        preprocessor_artifact_path=prep_art,
        model_manifest_path=if_man,
        preprocessor_manifest_path=prep_man,
    )

    assert isinstance(result, InferenceResult)
    assert output_csv.is_file()
    df_out = pd.read_csv(output_csv)
    assert len(df_out) == 40
    assert "prediction" in df_out.columns
    assert "anomaly_score" in df_out.columns or "decision_score" in df_out.columns


def test_cross_artifact_preprocessor_hash_mismatch_fails_closed(
    synthetic_pipeline_setup: Tuple[Path, Path, Path, Path, Path],
    tmp_path: Path,
):
    """Verify that model trained with a different preprocessor hash fails closed."""
    input_csv, prep_art, prep_man, model_art, model_man = synthetic_pipeline_setup
    output_csv = tmp_path / "out.csv"

    # Tamper with model manifest preprocessor hash
    man_data = json.loads(model_man.read_text(encoding="utf-8"))
    man_data["preprocessor_artifact_sha256"] = "9" * 64
    tampered_man = tmp_path / "tampered_model_manifest.json"
    tampered_man.write_text(json.dumps(man_data), encoding="utf-8")

    with pytest.raises(ValueError, match="preprocessor SHA-256"):
        run_inference(
            input_path=input_csv,
            output_path=output_csv,
            model_artifact_path=model_art,
            preprocessor_artifact_path=prep_art,
            model_manifest_path=tampered_man,
            preprocessor_manifest_path=prep_man,
        )


# =========================================================================
# 4. Failure-Path Testing
# =========================================================================


def test_pipeline_failure_paths(
    synthetic_pipeline_setup: Tuple[Path, Path, Path, Path, Path],
    tmp_path: Path,
):
    """Verify that invalid inputs fail closed with explicit exceptions."""
    input_csv, prep_art, prep_man, model_art, model_man = synthetic_pipeline_setup

    # 1. Non-existent input CSV
    with pytest.raises(FileNotFoundError, match="Input file not found at"):
        run_inference(
            input_path=tmp_path / "non_existent.csv",
            output_path=tmp_path / "out.csv",
            model_artifact_path=model_art,
            preprocessor_artifact_path=prep_art,
            model_manifest_path=model_man,
            preprocessor_manifest_path=prep_man,
        )

    # 2. Empty input CSV
    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match=r"is empty \(0 bytes\)"):
        run_inference(
            input_path=empty_csv,
            output_path=tmp_path / "out.csv",
            model_artifact_path=model_art,
            preprocessor_artifact_path=prep_art,
            model_manifest_path=model_man,
            preprocessor_manifest_path=prep_man,
        )

    # 3. Missing required features
    invalid_schema_csv = tmp_path / "invalid_schema.csv"
    pd.DataFrame({"FLOW_DURATION_MILLISECONDS": [50.0]}).to_csv(invalid_schema_csv, index=False)
    with pytest.raises(ValueError, match="missing"):
        run_inference(
            input_path=invalid_schema_csv,
            output_path=tmp_path / "out.csv",
            model_artifact_path=model_art,
            preprocessor_artifact_path=prep_art,
            model_manifest_path=model_man,
            preprocessor_manifest_path=prep_man,
        )

    # 4. Invalid feature values (unparseable non-numeric token)
    csv_text = input_csv.read_text(encoding="utf-8")
    lines = csv_text.splitlines()
    first_data_line = lines[1].split(",")
    first_data_line[0] = "corrupt_token_string"
    lines[1] = ",".join(first_data_line)
    invalid_val_csv = tmp_path / "invalid_values.csv"
    invalid_val_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid numeric token"):
        run_inference(
            input_path=invalid_val_csv,
            output_path=tmp_path / "out.csv",
            model_artifact_path=model_art,
            preprocessor_artifact_path=prep_art,
            model_manifest_path=model_man,
            preprocessor_manifest_path=prep_man,
        )


# =========================================================================
# 5. Real-Data Verification Tests
# =========================================================================


def test_real_preprocessor_artifact_verification():
    """Verify real Issue #8 preprocessor artifact if present; report SKIPPED if absent."""
    artifact_path = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    manifest_path = (
        PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )

    if not artifact_path.is_file() or not manifest_path.is_file():
        pytest.skip(
            f"Real preprocessor artifact from Issue #8 not found "
            f"(artifact={artifact_path.exists()}, manifest={manifest_path.exists()}). "
            "Skipping real-data preprocessor verification."
        )

    res = verify_preprocessing_artifact(artifact_path, manifest_path=manifest_path)
    assert res["status"] == "PASS"
    assert res["metadata"]["train_row_count"] == 1655797


def test_real_model_artifact_verification():
    """Verify real RF baseline model against manifest if binary present.

    Reports SKIPPED if binary model is absent from working tree.
    """
    manifest_path = PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
    if not manifest_path.is_file():
        pytest.skip(f"Model manifest not found at {manifest_path}")

    # Verify manifest JSON structure without binary
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_data["run_id"] == "rf-baseline-1794068628"
    assert manifest_data["feature_contract_version"] == FEATURE_CONTRACT_VERSION
    assert manifest_data["model_artifact_sha256"] == (
        "801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea"
    )

    model_path = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
    if not model_path.is_file():
        pytest.skip(
            "Real RF baseline model binary (.joblib) is not present in working tree "
            "(excluded via .gitignore policy). Companion manifest is verified."
        )

    model = RandomForestModel.load_verified(model_path, manifest_path=manifest_path)
    assert model.is_fitted is True
