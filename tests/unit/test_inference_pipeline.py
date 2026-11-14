"""Unit tests for NF-UNSW-NB15-v3 CSV Inference Pipeline (Issue #15).

Verifies:
1. Input schema validation (completeness, ordering, extra/target/metadata columns, invalid tokens).
2. Data types, missing, NaN, Inf handling.
3. Input row identity preservation.
4. Preprocessor artifact verified loading (fail-closed on missing or hash mismatch).
5. Model artifact verified loading (provenance, contract, hash, preprocessor compatibility).
6. Zero-refitting guarantee (preprocessor and model state remain frozen).
7. Output DataFrame consistency (row counts, class probabilities, anomaly scores).
8. Metadata generation and schema verification.
9. Backward compatibility for legacy entrypoints.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import (
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.inference import (
    InferencePipeline,
    InferenceResult,
    load_verified_model,
    load_verified_preprocessor,
    predict_from_artifact,
    run_inference,
    validate_inference_input,
)
from network_anomaly.inference.predict import _sha256_file
from network_anomaly.ingestion.gate import InferenceEligibilityGate
from network_anomaly.models.isolation_forest import IsolationForestModel
from network_anomaly.preprocessing import (
    FEATURE_CONTRACT_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)


@pytest.fixture
def synthetic_features() -> pd.DataFrame:
    """Create a synthetic DataFrame satisfying the 47-feature baseline contract."""
    rng = np.random.default_rng(seed=42)
    n_rows = 25
    data: Dict[str, np.ndarray] = {}
    for col in ML_FEATURE_COLUMNS:
        if col in CATEGORICAL_CODED_COLUMNS:
            data[col] = rng.integers(0, 10, size=n_rows)
        else:
            data[col] = rng.normal(loc=100.0, scale=15.0, size=n_rows)
    return pd.DataFrame(data, columns=list(ML_FEATURE_COLUMNS))


@pytest.fixture
def synthetic_preprocessor_and_model(
    synthetic_features: pd.DataFrame,
    tmp_path: Path,
) -> Tuple[Path, Path, Path, Path]:
    """Fit a synthetic preprocessor and model, save them with companion manifests."""
    # 1. Fit preprocessor on synthetic features
    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256="4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        split_manifest_sha256="bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
    )
    prep.fit(synthetic_features)

    prep_art_path = tmp_path / "test_preprocessor.joblib"
    prep_man_path = tmp_path / "test_preprocessor_manifest.json"
    prep_sha = prep.save(artifact_path=prep_art_path, manifest_path=prep_man_path)

    # 2. Fit a small RandomForest model on transformed features
    X_trans = prep.transform(synthetic_features)
    y = np.array([0 if i % 2 == 0 else 1 for i in range(len(X_trans))])

    rf = RandomForestClassifier(n_estimators=5, max_depth=3, random_state=42)
    rf.fit(X_trans, y)

    model_art_path = tmp_path / "test_model.joblib"
    model_man_path = tmp_path / "test_model_manifest.json"

    joblib.dump(rf, model_art_path, compress=3)
    model_sha = _sha256_file(model_art_path)

    model_manifest_data = {
        "run_id": "test-run-synthetic-001",
        "model_type": "RandomForestClassifier",
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "model_artifact_path": str(model_art_path.name),
        "model_artifact_sha256": model_sha,
        "preprocessor_artifact_sha256": prep_sha,
        "class_mapping": {"0": "Benign", "1": "Attack"},
        "hyperparameters": {"n_estimators": 5, "max_depth": 3, "random_state": 42},
    }
    model_man_path.write_text(json.dumps(model_manifest_data, indent=2) + "\n", encoding="utf-8")

    return prep_art_path, prep_man_path, model_art_path, model_man_path


# =========================================================================
# 1. Schema Validation Tests
# =========================================================================


def test_validate_inference_input_success(synthetic_features: pd.DataFrame):
    """Test successful schema validation on canonical contract input."""
    X_ordered, summary = validate_inference_input(synthetic_features)
    assert isinstance(X_ordered, pd.DataFrame)
    assert list(X_ordered.columns) == list(ML_FEATURE_COLUMNS)
    assert len(X_ordered) == len(synthetic_features)
    assert summary["row_count"] == len(synthetic_features)
    assert summary["feature_count"] == 47
    assert summary["extra_columns_count"] == 0


def test_validate_inference_input_type_error():
    """Test rejection when input is not a DataFrame."""
    with pytest.raises(TypeError, match="Input must be a pandas DataFrame"):
        validate_inference_input([1, 2, 3])  # type: ignore

    with pytest.raises(TypeError, match="Input must be a pandas DataFrame"):
        validate_inference_input({"PROTOCOL": [6]})  # type: ignore


def test_validate_inference_input_empty_error():
    """Test rejection when input DataFrame contains 0 rows."""
    empty_df = pd.DataFrame(columns=list(ML_FEATURE_COLUMNS))
    with pytest.raises(ValueError, match="Input DataFrame is empty"):
        validate_inference_input(empty_df)


def test_validate_inference_input_missing_features(synthetic_features: pd.DataFrame):
    """Test rejection when one or more required features are missing."""
    df_missing = synthetic_features.drop(columns=["PROTOCOL", "IN_BYTES"])
    with pytest.raises(ValueError, match="missing 2 required baseline ML feature"):
        validate_inference_input(df_missing)


def test_validate_inference_input_reorders_columns(synthetic_features: pd.DataFrame):
    """Test that arbitrarily permuted columns are safely reordered to exact contract."""
    # Reverse column order
    reversed_cols = list(reversed(synthetic_features.columns))
    df_reversed = synthetic_features[reversed_cols].copy()

    X_ordered, _ = validate_inference_input(df_reversed)
    assert list(X_ordered.columns) == list(ML_FEATURE_COLUMNS)
    assert list(df_reversed.columns) != list(ML_FEATURE_COLUMNS)


def test_validate_inference_input_excludes_targets_and_trace_metadata(
    synthetic_features: pd.DataFrame,
):
    """Test that Label, Attack, and trace-only metadata columns are strictly excluded from X."""
    df_with_extras = synthetic_features.copy()
    # Add target columns
    df_with_extras["Label"] = 1
    df_with_extras["Attack"] = "Exploits"
    # Add trace metadata columns
    df_with_extras["IPV4_SRC_ADDR"] = "192.168.1.10"
    df_with_extras["IPV4_DST_ADDR"] = "10.0.0.1"
    df_with_extras["L4_SRC_PORT"] = 54321
    df_with_extras["L4_DST_PORT"] = 80
    df_with_extras["FLOW_START_MILLISECONDS"] = 1600000000000
    df_with_extras["FLOW_END_MILLISECONDS"] = 1600000005000

    X_ordered, summary = validate_inference_input(df_with_extras)

    # Feature matrix X must only contain the 47 ML features
    assert list(X_ordered.columns) == list(ML_FEATURE_COLUMNS)
    for col in TARGET_COLUMNS:
        assert col not in X_ordered.columns
    for col in TRACE_METADATA_COLUMNS:
        assert col not in X_ordered.columns

    # Summary correctly documents the excluded columns
    assert set(summary["target_columns_excluded"]) == set(TARGET_COLUMNS)
    assert set(summary["trace_metadata_excluded"]) == set(TRACE_METADATA_COLUMNS)


def test_validate_inference_input_excludes_arbitrary_extra_columns(
    synthetic_features: pd.DataFrame,
):
    """Test that arbitrary unexpected columns are not injected into X."""
    df_extra = synthetic_features.copy()
    df_extra["analyst_comment"] = "suspicious spike"
    df_extra["capture_interface"] = "eth0"

    X_ordered, summary = validate_inference_input(df_extra)
    assert list(X_ordered.columns) == list(ML_FEATURE_COLUMNS)
    assert "analyst_comment" not in X_ordered.columns
    assert "capture_interface" not in X_ordered.columns
    assert "analyst_comment" in summary["other_extra_columns_excluded"]


def test_validate_inference_input_preserves_row_identity(synthetic_features: pd.DataFrame):
    """Test that row identifiers are preserved from existing column or generated."""
    # 1. Custom row_id provided
    df_with_id = synthetic_features.copy()
    df_with_id["row_id"] = [f"flow_{i:04d}" for i in range(len(df_with_id))]

    _, summary1 = validate_inference_input(df_with_id)
    assert list(summary1["row_ids"]) == [f"flow_{i:04d}" for i in range(len(df_with_id))]

    # 2. Generated sequential row_id
    _, summary2 = validate_inference_input(synthetic_features)
    assert list(summary2["row_ids"]) == list(range(len(synthetic_features)))


def test_validate_inference_input_rejects_unparseable_strings(
    synthetic_features: pd.DataFrame,
):
    """Test that non-numeric unparseable string tokens raise a descriptive ValueError."""
    df_corrupt = synthetic_features.copy()
    df_corrupt["IN_BYTES"] = df_corrupt["IN_BYTES"].astype(object)
    df_corrupt.loc[2, "IN_BYTES"] = "invalid_string_payload"

    with pytest.raises(ValueError, match="invalid numeric token"):
        validate_inference_input(df_corrupt)


def test_validate_inference_input_accepts_valid_missing_tokens(
    synthetic_features: pd.DataFrame,
):
    """Test that standard missing/infinity tokens are accepted for preprocessor imputation."""
    df_missing = synthetic_features.copy()
    df_missing.loc[0, "IN_BYTES"] = np.nan
    df_missing.loc[1, "OUT_BYTES"] = float("inf")
    df_missing.loc[2, "MIN_TTL"] = float("-inf")

    X_ordered, _ = validate_inference_input(df_missing)
    assert len(X_ordered) == len(synthetic_features)


# =========================================================================
# 2. Preprocessor & Model Loading Tests
# =========================================================================


def test_load_real_issue_8_preprocessor():
    """Verify loading the real preprocessor artifact from Issue #8 if present."""
    art_path = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    man_path = (
        PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )
    if not art_path.is_file() or not man_path.is_file():
        pytest.skip("Real preprocessor artifact is unavailable")
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_sha256") != _sha256_file(art_path):
        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            load_verified_preprocessor(art_path, manifest_path=man_path)
        return
    prep, meta = load_verified_preprocessor(art_path, manifest_path=man_path)
    assert prep.is_fitted_ is True
    assert meta["feature_contract_version"] == FEATURE_CONTRACT_VERSION
    assert meta["train_row_count"] == 1655797


def test_load_verified_preprocessor_missing_artifact(tmp_path: Path):
    """Fail closed when preprocessor artifact does not exist."""
    non_existent = tmp_path / "does_not_exist.joblib"
    with pytest.raises(FileNotFoundError, match="Preprocessing artifact not found"):
        load_verified_preprocessor(non_existent)


def test_load_verified_preprocessor_missing_manifest(tmp_path: Path):
    """Fail closed when preprocessor companion manifest does not exist."""
    dummy_art = tmp_path / "fake.joblib"
    dummy_art.write_bytes(b"dummy")
    with pytest.raises(FileNotFoundError, match="Companion manifest"):
        load_verified_preprocessor(dummy_art, manifest_path=tmp_path / "no_manifest.json")


def test_load_verified_preprocessor_hash_mismatch(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
):
    """Fail closed when preprocessor SHA-256 does not match manifest."""
    prep_art_path, prep_man_path, _, _ = synthetic_preprocessor_and_model

    # Corrupt preprocessor artifact file by appending bytes
    corrupt_art = prep_art_path.parent / "corrupt_preprocessor.joblib"
    content = bytearray(prep_art_path.read_bytes())
    content.extend(b"tampered")
    corrupt_art.write_bytes(content)

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_verified_preprocessor(corrupt_art, manifest_path=prep_man_path)


def test_load_verified_model_missing_artifact(tmp_path: Path):
    """Fail closed when model artifact does not exist."""
    non_existent = tmp_path / "non_existent_model.joblib"
    with pytest.raises(FileNotFoundError, match="Model artifact not found"):
        load_verified_model(non_existent)


def test_load_verified_model_hash_mismatch(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
):
    """Fail closed when model SHA-256 does not match manifest."""
    _, _, model_art_path, model_man_path = synthetic_preprocessor_and_model

    corrupt_model = model_art_path.parent / "corrupt_model.joblib"
    content = bytearray(model_art_path.read_bytes())
    content.extend(b"corrupted_weights")
    corrupt_model.write_bytes(content)

    with pytest.raises(ValueError, match="Model artifact SHA-256 mismatch"):
        load_verified_model(corrupt_model, manifest_path=model_man_path)


def test_load_verified_model_feature_contract_mismatch(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    tmp_path: Path,
):
    """Fail closed when model manifest declares an incompatible feature contract."""
    _, _, model_art_path, model_man_path = synthetic_preprocessor_and_model

    man_data = json.loads(model_man_path.read_text(encoding="utf-8"))
    man_data["feature_contract_version"] = "incompatible-contract-v99"

    incompat_manifest = tmp_path / "incompat_manifest.json"
    incompat_manifest.write_text(json.dumps(man_data), encoding="utf-8")

    with pytest.raises(ValueError, match="Model feature contract version"):
        load_verified_model(model_art_path, manifest_path=incompat_manifest)


def test_load_verified_model_preprocessor_mismatch(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    tmp_path: Path,
):
    """Fail closed when model was trained with a different preprocessor hash."""
    _, _, model_art_path, model_man_path = synthetic_preprocessor_and_model

    with pytest.raises(ValueError, match="Model was trained with preprocessor SHA-256"):
        load_verified_model(
            model_art_path,
            manifest_path=model_man_path,
            expected_preprocessor_sha256="0000000000000000000000000000000000000000000000000000000000000000",
        )


def test_load_verified_model_requires_manifest_preprocessor_hash(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path], tmp_path: Path
):
    prep_art_path, _, model_art_path, model_man_path = synthetic_preprocessor_and_model
    manifest = json.loads(model_man_path.read_text(encoding="utf-8"))
    del manifest["preprocessor_artifact_sha256"]
    bad_manifest = tmp_path / "missing_preprocessor_hash.json"
    bad_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field 'preprocessor_artifact_sha256'"):
        load_verified_model(
            model_art_path,
            manifest_path=bad_manifest,
            expected_preprocessor_sha256=_sha256_file(prep_art_path),
        )


def test_eligibility_gate_abstains_before_model_prediction(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
):
    prep_art_path, prep_man_path, model_art_path, model_man_path = synthetic_preprocessor_and_model

    class RejectingGate:
        def evaluate(self, **kwargs):
            return SimpleNamespace(can_proceed_to_ml=False, abstention_reasons=["OOD drift"])

    pipeline = InferencePipeline.from_artifacts(
        model_artifact_path=model_art_path,
        preprocessor_artifact_path=prep_art_path,
        model_manifest_path=model_man_path,
        preprocessor_manifest_path=prep_man_path,
        eligibility_gate=RejectingGate(),
    )
    result = pipeline.predict(synthetic_features)
    assert len(result) == len(synthetic_features)
    assert result["prediction"].isna().all()
    assert (result["inference_status"] == "ABSTAINED").all()


def test_eligibility_gate_abstains_on_zero_ttl_batch(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
):
    prep_art_path, prep_man_path, model_art_path, model_man_path = synthetic_preprocessor_and_model
    pipeline = InferencePipeline.from_artifacts(
        model_artifact_path=model_art_path,
        preprocessor_artifact_path=prep_art_path,
        model_manifest_path=model_man_path,
        preprocessor_manifest_path=prep_man_path,
        eligibility_gate=InferenceEligibilityGate(),
    )
    flows = synthetic_features.copy()
    flows["MIN_TTL"] = 0
    result = pipeline.predict(flows)
    assert len(result) == len(flows)
    assert result["prediction"].isna().all()
    assert (result["inference_status"] == "ABSTAINED").all()


def test_eligibility_gate_abstains_on_missing_feature(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
):
    prep_art_path, prep_man_path, model_art_path, model_man_path = synthetic_preprocessor_and_model
    pipeline = InferencePipeline.from_artifacts(
        model_artifact_path=model_art_path,
        preprocessor_artifact_path=prep_art_path,
        model_manifest_path=model_man_path,
        preprocessor_manifest_path=prep_man_path,
        eligibility_gate=InferenceEligibilityGate(),
    )
    result = pipeline.predict(synthetic_features.drop(columns=[ML_FEATURE_COLUMNS[0]]))
    assert result["prediction"].isna().all()
    assert (result["inference_status"] == "ABSTAINED").all()


# =========================================================================
# 3. Prediction Pipeline & Zero-Refitting Tests
# =========================================================================


def test_inference_pipeline_predict_no_refit(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
):
    """Guarantee that neither preprocessor nor model is refitted during inference."""
    prep_art_path, prep_man_path, model_art_path, model_man_path = synthetic_preprocessor_and_model

    pipeline = InferencePipeline.from_artifacts(
        model_artifact_path=model_art_path,
        preprocessor_artifact_path=prep_art_path,
        model_manifest_path=model_man_path,
        preprocessor_manifest_path=prep_man_path,
    )

    # Capture frozen fitted state before prediction
    fitted_time_before = pipeline.preprocessor.fitted_at_utc_
    imputed_values_before = pipeline.preprocessor.imputed_values_.copy()
    categories_before = pipeline.preprocessor.category_vocabularies_.copy()

    # Run predictions on new input
    preds_df = pipeline.predict(synthetic_features)

    # Verify frozen state is unchanged
    assert pipeline.preprocessor.fitted_at_utc_ == fitted_time_before
    assert pipeline.preprocessor.imputed_values_ == imputed_values_before
    assert pipeline.preprocessor.category_vocabularies_ == categories_before
    assert len(preds_df) == len(synthetic_features)


def test_inference_pipeline_row_count_and_columns(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
):
    """Test output DataFrame row count, schema, probability columns, and alignment."""
    prep_art_path, prep_man_path, model_art_path, model_man_path = synthetic_preprocessor_and_model

    pipeline = InferencePipeline.from_artifacts(
        model_artifact_path=model_art_path,
        preprocessor_artifact_path=prep_art_path,
        model_manifest_path=model_man_path,
        preprocessor_manifest_path=prep_man_path,
    )

    preds_df = pipeline.predict(synthetic_features)

    # Core required columns
    assert "row_id" in preds_df.columns
    assert "prediction" in preds_df.columns
    assert "model_type" in preds_df.columns
    assert "run_id" in preds_df.columns
    assert "model_artifact_sha256" in preds_df.columns
    assert "preprocessor_artifact_sha256" in preds_df.columns

    # Probability columns using class_mapping from manifest
    assert "probability_Benign" in preds_df.columns
    assert "probability_Attack" in preds_df.columns

    # Probabilities sum to 1.0
    prob_sum = preds_df["probability_Benign"] + preds_df["probability_Attack"]
    np.testing.assert_allclose(prob_sum.values, 1.0, atol=1e-6)

    # Row count matches input exactly
    assert len(preds_df) == len(synthetic_features)


def test_inference_pipeline_isolation_forest(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
    tmp_path: Path,
):
    """Test inference pipeline with an unsupervised Isolation Forest model."""
    prep_art_path, prep_man_path, _, _ = synthetic_preprocessor_and_model

    # Fit small IsolationForest
    prep = TrainOnlyPreprocessor.load_verified(prep_art_path, manifest_path=prep_man_path)
    X_trans = prep.transform(synthetic_features)

    if_model = IsolationForestModel(config={"n_estimators": 10}, threshold=0.1)
    if_model.fit(X_trans)

    if_art_path = tmp_path / "if_model.joblib"
    prep_sha = _sha256_file(prep_art_path)
    if_man_path = tmp_path / "if_model_manifest.json"
    if_model.save(if_art_path, if_man_path, preprocessor_artifact_sha256=prep_sha)

    pipeline = InferencePipeline.from_artifacts(
        model_artifact_path=if_art_path,
        preprocessor_artifact_path=prep_art_path,
        model_manifest_path=if_man_path,
        preprocessor_manifest_path=prep_man_path,
    )

    preds_df = pipeline.predict(synthetic_features)
    assert len(preds_df) == len(synthetic_features)
    assert "prediction" in preds_df.columns
    # Isolation Forest has decision_function -> decision_score column
    assert "decision_score" in preds_df.columns
    assert set(preds_df["prediction"].unique()).issubset({0, 1})
    assert np.array_equal(
        preds_df["prediction"].to_numpy(),
        (preds_df["decision_score"].to_numpy() >= 0.1).astype(int),
    )


# =========================================================================
# 4. End-to-End File I/O and Metadata Tests
# =========================================================================


def test_run_inference_end_to_end(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
    tmp_path: Path,
):
    """Test full file-based inference execution, CSV output, and metadata generation."""
    prep_art_path, prep_man_path, model_art_path, model_man_path = synthetic_preprocessor_and_model

    input_csv = tmp_path / "new_flows.csv"
    output_csv = tmp_path / "predictions.csv"
    synthetic_features.to_csv(input_csv, index=False)

    result = run_inference(
        input_path=input_csv,
        output_path=output_csv,
        model_artifact_path=model_art_path,
        preprocessor_artifact_path=prep_art_path,
        model_manifest_path=model_man_path,
        preprocessor_manifest_path=prep_man_path,
    )

    assert isinstance(result, InferenceResult)
    assert output_csv.is_file()

    # Verify output CSV content
    df_read = pd.read_csv(output_csv)
    assert len(df_read) == len(synthetic_features)
    assert "prediction" in df_read.columns
    assert "row_id" in df_read.columns

    # Verify metadata JSON
    metadata_file = tmp_path / "predictions.metadata.json"
    assert metadata_file.is_file()

    meta = json.loads(metadata_file.read_text(encoding="utf-8"))
    assert meta["input_file_path"] == str(input_csv)
    assert meta["input_row_count"] == len(synthetic_features)
    assert meta["prediction_count"] == len(synthetic_features)
    assert meta["execution_status"] == "SUCCESS"
    assert meta["feature_contract_version"] == FEATURE_CONTRACT_VERSION
    assert meta["output_file_sha256"] == _sha256_file(output_csv)


def test_run_inference_rejects_output_same_as_input(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
    tmp_path: Path,
):
    """Test that output path cannot overwrite input CSV."""
    prep_art_path, prep_man_path, model_art_path, model_man_path = synthetic_preprocessor_and_model

    input_csv = tmp_path / "flows.csv"
    synthetic_features.to_csv(input_csv, index=False)

    with pytest.raises(ValueError, match="Output path cannot overwrite input path"):
        run_inference(
            input_path=input_csv,
            output_path=input_csv,
            model_artifact_path=model_art_path,
            preprocessor_artifact_path=prep_art_path,
            model_manifest_path=model_man_path,
            preprocessor_manifest_path=prep_man_path,
        )


def test_predict_from_artifact_backward_compatibility(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
):
    """Test that legacy predict_from_artifact remains callable and functional."""
    prep_art_path, prep_man_path, model_art_path, _ = synthetic_preprocessor_and_model
    preds = predict_from_artifact(
        synthetic_features,
        artifact_path=model_art_path,
        preprocessor_artifact_path=prep_art_path,
        preprocessor_manifest_path=prep_man_path,
    )
    assert len(preds) == len(synthetic_features)


# =========================================================================
# 5. Issue #53 Secure Verified Model Loading & Anti-Deserialization Tests
# =========================================================================


def test_load_verified_model_missing_manifest_raises_fail_closed(tmp_path: Path):
    """Issue #53: Enforce fail-closed error when companion manifest is missing."""
    fake_model_path = tmp_path / "orphan_model.joblib"
    joblib.dump({"dummy": "payload"}, fake_model_path)

    with pytest.raises(FileNotFoundError, match="Companion manifest for model not found"):
        load_verified_model(fake_model_path, manifest_path=None)


def test_load_verified_model_explicit_nonexistent_manifest(tmp_path: Path):
    """Issue #53: Enforce fail-closed FileNotFoundError on missing explicit manifest."""
    fake_model_path = tmp_path / "model.joblib"
    joblib.dump({"dummy": "payload"}, fake_model_path)
    non_existent_man = tmp_path / "does_not_exist_manifest.json"

    with pytest.raises(FileNotFoundError, match="Companion manifest for model not found"):
        load_verified_model(fake_model_path, manifest_path=non_existent_man)


def test_load_verified_model_tampered_single_byte_digest_mismatch(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    tmp_path: Path,
):
    """Issue #53: Enforce fail-closed ValueError on byte-by-byte SHA-256 mismatch."""
    _, _, model_art_path, model_man_path = synthetic_preprocessor_and_model

    # Create a 1-byte modified copy of the model artifact
    raw_bytes = bytearray(model_art_path.read_bytes())
    raw_bytes[0] ^= 0xFF  # Flip bits of first byte
    tampered_model_path = tmp_path / "tampered_1byte_model.joblib"
    tampered_model_path.write_bytes(raw_bytes)

    with pytest.raises(ValueError, match="Model artifact SHA-256 mismatch"):
        load_verified_model(tampered_model_path, manifest_path=model_man_path)


def test_load_verified_model_missing_required_fields_in_manifest(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    tmp_path: Path,
):
    """Issue #53: Fail closed if manifest misses model sha256 or contract version."""
    _, _, model_art_path, model_man_path = synthetic_preprocessor_and_model
    man_data = json.loads(model_man_path.read_text(encoding="utf-8"))

    # Missing model_artifact_sha256
    bad_man_1 = tmp_path / "bad_man_no_sha.json"
    data_no_sha = dict(man_data)
    del data_no_sha["model_artifact_sha256"]
    bad_man_1.write_text(json.dumps(data_no_sha), encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field 'model_artifact_sha256'"):
        load_verified_model(model_art_path, manifest_path=bad_man_1)

    # Missing feature_contract_version
    bad_man_2 = tmp_path / "bad_man_no_contract.json"
    data_no_contract = dict(man_data)
    del data_no_contract["feature_contract_version"]
    bad_man_2.write_text(json.dumps(data_no_contract), encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field 'feature_contract_version'"):
        load_verified_model(model_art_path, manifest_path=bad_man_2)


def test_load_verified_model_malformed_manifest_json(tmp_path: Path):
    """Issue #53: Fail closed on malformed JSON manifest."""
    fake_model_path = tmp_path / "model_bad_json.joblib"
    joblib.dump({"dummy": "payload"}, fake_model_path)
    bad_json_man = tmp_path / "bad_syntax.json"
    bad_json_man.write_text("NOT_VALID_JSON{{{", encoding="utf-8")

    with pytest.raises(ValueError, match="Failed to parse model manifest JSON"):
        load_verified_model(fake_model_path, manifest_path=bad_json_man)


def test_load_verified_model_non_dict_manifest_json(tmp_path: Path):
    """Issue #53: Fail closed if manifest JSON is an array rather than object."""
    fake_model_path = tmp_path / "model_non_dict.joblib"
    joblib.dump({"dummy": "payload"}, fake_model_path)
    array_man = tmp_path / "array_manifest.json"
    array_man.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")

    with pytest.raises(ValueError, match="Model manifest JSON must be a dict/object"):
        load_verified_model(fake_model_path, manifest_path=array_man)


def test_predict_from_artifact_rejects_unverified_model(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
    tmp_path: Path,
):
    """Issue #53: predict_from_artifact fails closed on unverified model without manifest."""
    prep_art_path, prep_man_path, _, _ = synthetic_preprocessor_and_model
    unverified_model_path = tmp_path / "unverified_legacy.joblib"
    joblib.dump({"unsafe": True}, unverified_model_path)

    with pytest.raises(FileNotFoundError, match="Companion manifest for model not found"):
        predict_from_artifact(
            synthetic_features,
            artifact_path=unverified_model_path,
            preprocessor_artifact_path=prep_art_path,
            preprocessor_manifest_path=prep_man_path,
        )

    # Also fails closed if called completely standalone without preprocessor or manifest
    with pytest.raises((FileNotFoundError, ValueError)):
        predict_from_artifact(synthetic_features, artifact_path=unverified_model_path)


def test_predict_from_artifact_rejects_tampered_model(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
    tmp_path: Path,
):
    """Issue #53: predict_from_artifact fails closed on tampered model artifact."""
    prep_art_path, prep_man_path, model_art_path, model_man_path = synthetic_preprocessor_and_model

    # Tamper with model
    tampered_model = tmp_path / "tampered_legacy.joblib"
    raw_bytes = bytearray(model_art_path.read_bytes())
    raw_bytes[-1] ^= 0x01
    tampered_model.write_bytes(raw_bytes)

    with pytest.raises(ValueError, match="Model artifact SHA-256 mismatch"):
        predict_from_artifact(
            synthetic_features,
            artifact_path=tampered_model,
            manifest_path=model_man_path,
            preprocessor_artifact_path=prep_art_path,
            preprocessor_manifest_path=prep_man_path,
        )


def test_prohibit_unverified_deserialization_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """Issue #53: Ensure joblib.load is NEVER invoked if manifest integrity check fails."""
    fake_model = tmp_path / "probe_model.joblib"
    fake_model.write_bytes(b"probe_payload")

    joblib_called = False

    def explosive_load(*args, **kwargs):
        nonlocal joblib_called
        joblib_called = True
        raise AssertionError("CRITICAL INSECURITY: joblib.load invoked without verified manifest!")

    monkeypatch.setattr(joblib, "load", explosive_load)

    # Missing manifest: joblib.load MUST NOT be called
    with pytest.raises(FileNotFoundError):
        load_verified_model(fake_model, manifest_path=None)

    assert not joblib_called, "joblib.load was called on an unverified model!"


def test_load_verified_model_rejects_mismatched_isolation_forest_payload(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
    tmp_path: Path,
):
    """F1 regression: IsolationForest serialized with RF manifest must be rejected."""
    from sklearn.ensemble import IsolationForest

    prep_art_path, prep_man_path, _, model_man_path = synthetic_preprocessor_and_model
    base_man = json.loads(model_man_path.read_text(encoding="utf-8"))
    X_np = synthetic_features.to_numpy(dtype=np.float64)

    # Case 1: IsolationForestModel wrapper saved to disk, disguised with RF manifest
    if_model = IsolationForestModel(config={"n_estimators": 5, "random_state": 42}, threshold=0.0)
    if_model.fit(X_np)
    wrapped_path = tmp_path / "disguised_if_wrapped.joblib"
    wrapped_man = tmp_path / "disguised_if_wrapped_manifest.json"
    if_model.save(
        wrapped_path,
        wrapped_man,
        preprocessor_artifact_sha256=base_man["preprocessor_artifact_sha256"],
    )
    rf_claimed = dict(base_man)
    rf_claimed["model_type"] = "RandomForestClassifier"
    rf_claimed["model_artifact_sha256"] = _sha256_file(wrapped_path)
    wrapped_man.write_text(json.dumps(rf_claimed, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="Model type mismatch"):
        load_verified_model(
            wrapped_path,
            manifest_path=wrapped_man,
            expected_preprocessor_sha256=base_man["preprocessor_artifact_sha256"],
        )
    with pytest.raises(ValueError, match="Model type mismatch"):
        InferencePipeline.from_artifacts(
            model_artifact_path=wrapped_path,
            preprocessor_artifact_path=prep_art_path,
            model_manifest_path=wrapped_man,
            preprocessor_manifest_path=prep_man_path,
        )

    # Case 2: Raw sklearn IsolationForest estimator disguised with RF manifest
    raw_if = IsolationForest(n_estimators=5, random_state=42).fit(X_np)
    raw_path = tmp_path / "disguised_if_raw.joblib"
    joblib.dump(raw_if, raw_path)
    raw_man = tmp_path / "disguised_if_raw_manifest.json"
    raw_claimed = dict(base_man)
    raw_claimed["model_type"] = "RandomForest"
    raw_claimed["model_artifact_sha256"] = _sha256_file(raw_path)
    raw_man.write_text(json.dumps(raw_claimed, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="Model type mismatch"):
        load_verified_model(
            raw_path,
            manifest_path=raw_man,
            expected_preprocessor_sha256=base_man["preprocessor_artifact_sha256"],
        )


def test_load_verified_model_rejects_rf_with_isolation_manifest_or_missing_type(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    tmp_path: Path,
):
    """F1 regression: RF payload under IsolationForest or missing model_type manifest is rejected."""
    _, _, model_art_path, model_man_path = synthetic_preprocessor_and_model
    base_man = json.loads(model_man_path.read_text(encoding="utf-8"))

    if_claimed = dict(base_man)
    if_claimed["model_type"] = "IsolationForest"
    if_claimed["threshold"] = 0.0
    if_claimed["score_direction"] = "higher_is_more_anomalous"
    if_claimed["label_mapping"] = {"0": "Benign", "1": "Attack"}
    if_claimed["feature_columns"] = list(ML_FEATURE_COLUMNS)
    bad_man_if = tmp_path / "rf_as_if_manifest.json"
    bad_man_if.write_text(json.dumps(if_claimed, indent=2), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="Unsupported|Expected IsolationForest|Invalid model artifact payload|Model type mismatch",
    ):
        load_verified_model(
            model_art_path,
            manifest_path=bad_man_if,
            expected_preprocessor_sha256=base_man["preprocessor_artifact_sha256"],
        )

    missing_type = dict(base_man)
    missing_type.pop("model_type", None)
    bad_man_missing = tmp_path / "missing_type_manifest.json"
    bad_man_missing.write_text(json.dumps(missing_type, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="missing required field 'model_type'"):
        load_verified_model(model_art_path, manifest_path=bad_man_missing)


def test_inference_pipeline_rejects_non_binary_raw_predictions(
    synthetic_preprocessor_and_model: Tuple[Path, Path, Path, Path],
    synthetic_features: pd.DataFrame,
):
    """F1 regression: InferencePipeline.predict refuses raw {-1, 1} or non-binary predictions."""
    prep_art_path, prep_man_path, _, model_man_path = synthetic_preprocessor_and_model
    prep, prep_meta = load_verified_preprocessor(prep_art_path, prep_man_path)
    model_meta = json.loads(model_man_path.read_text(encoding="utf-8"))

    class BadPredictionModel:
        def __init__(self, values):
            self._values = values

        def predict(self, X):
            return self._values[: len(X)]

    for bad_values in (
        np.array([1, -1], dtype=np.int64),
        np.array([True, False], dtype=bool),
        np.array([1, True], dtype=object),
    ):
        pipeline = InferencePipeline(
            model=BadPredictionModel(bad_values),
            preprocessor=prep,
            model_metadata=model_meta,
            preprocessor_metadata=prep_meta,
        )
        with pytest.raises(ValueError, match="non-binary labels"):
            pipeline.predict(synthetic_features.iloc[:2])
