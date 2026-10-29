#!/usr/bin/env python3
"""Integration test — inference and preprocessing components load together."""

from network_anomaly.config import ARTIFACTS
from network_anomaly.inference.pipeline import predict_from_artifact
from network_anomaly.models.isolation_forest import build_model
from network_anomaly.preprocessing import (
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_POLICY_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
    verify_preprocessing_artifact,
)


def test_isolation_forest_load():
    m = build_model()
    assert m is not None


def test_inference_module_resolves_artifact_location():
    assert ARTIFACTS.name == "artifacts"
    assert callable(predict_from_artifact)


def test_preprocessing_pipeline_integration():
    config = PreprocessingConfig(scaler_type="none")
    preprocessor = TrainOnlyPreprocessor(config=config)
    assert preprocessor is not None
    assert preprocessor.is_fitted_ is False
    assert FEATURE_CONTRACT_VERSION == "nf-unsw-nb15-v3-baseline-47"
    assert PREPROCESSING_POLICY_VERSION == "nf-unsw-nb15-v3-preprocessing-v1"


def test_real_preprocessor_artifact_verification():
    artifact_path = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    manifest_path = (
        ARTIFACTS.parent
        / "reports"
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )
    if artifact_path.is_file() and manifest_path.is_file():
        res = verify_preprocessing_artifact(artifact_path, manifest_path=manifest_path)
        assert res["status"] == "PASS"
        assert res["metadata"]["train_row_count"] == 1655797
