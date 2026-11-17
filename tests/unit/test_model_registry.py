"""Tests for the verified model registry and score semantics.

These tests are the evidence that live inference calls real artifacts rather
than a heuristic. Artifact-dependent tests skip explicitly when the gitignored
artifacts are not present (the normal CI state).
"""

from __future__ import annotations

import numpy as np
import pytest

from network_anomaly.models.registry import (
    MODEL_KEYS,
    FeatureContractError,
    ModelReadiness,
    ModelRegistry,
)
from network_anomaly.models.scoring import (
    PERCENTILE_SEMANTICS,
    PROBABILITY_SEMANTICS,
    extract_threshold,
    normalize_anomaly_score,
    threshold_provenance_is_clean,
)


class TestMissingArtifacts:
    def test_all_models_unavailable_without_artifacts(self, tmp_path):
        registry = ModelRegistry(
            artifacts_dir=tmp_path / "artifacts",
            manifest_root=tmp_path / "manifests",
            preprocessor_path=tmp_path / "preprocessor.joblib",
            preprocessor_manifest_path=tmp_path / "preprocessor.json",
            warmup=False,
        )
        assert registry.ready_count == 0
        assert registry.validated_count == 0
        assert registry.all_ready is False
        assert registry.preprocessor_ready is False
        assert [s.readiness for s in registry.statuses()] == [ModelReadiness.UNAVAILABLE] * 4
        assert registry.predict_all_matrix(np.zeros((1, 47), dtype=float)) == {}

    def test_feature_contract_violation_is_rejected(self, tmp_path):
        registry = ModelRegistry(
            artifacts_dir=tmp_path / "artifacts",
            manifest_root=tmp_path / "manifests",
            preprocessor_path=tmp_path / "preprocessor.joblib",
            preprocessor_manifest_path=tmp_path / "preprocessor.json",
            warmup=False,
        )
        with pytest.raises(FeatureContractError):
            registry.predict_all({"OUT_BYTES": 123.0})


class TestLeakageGuard:
    def test_test_partition_threshold_is_not_accepted(self):
        manifest = {"test_summary": {"decision_threshold": 0.91}}
        threshold, source = extract_threshold(manifest)
        assert threshold is None
        assert source == "unavailable"

    def test_validation_threshold_is_accepted(self):
        manifest = {"threshold": 0.37}
        threshold, source = extract_threshold(manifest)
        assert threshold == pytest.approx(0.37)
        assert source == "manifest.threshold"

    def test_test_partition_calibration_is_rejected(self):
        assert (
            threshold_provenance_is_clean(
                {"threshold_calibration": {"calibration_partition": "test"}}
            )
            is False
        )
        assert (
            threshold_provenance_is_clean(
                {"threshold_calibration": {"calibration_partition": "validation"}}
            )
            is True
        )

    def test_percentile_normalization_is_a_rank_not_a_probability(self):
        calibration = {
            "calibration_partition": "validation",
            "score_direction": "higher_is_more_anomalous",
            "quantile_grid": [0.0, 0.5, 1.0],
            "score_values": [0.0, 10.0, 20.0],
        }
        assert normalize_anomaly_score(15.0, calibration) == pytest.approx(0.75)
        assert normalize_anomaly_score(10.0, calibration) == pytest.approx(0.5)

        wrong_direction = dict(calibration, score_direction="lower_is_more_anomalous")
        assert normalize_anomaly_score(15.0, wrong_direction) is None

        test_partition = dict(calibration, calibration_partition="test")
        assert normalize_anomaly_score(15.0, test_partition) is None


@pytest.mark.usefixtures("real_artifacts_available")
class TestRealArtifacts:
    def _registry(self, real_artifacts_available):
        if not real_artifacts_available:
            pytest.skip("model artifacts are not present in this environment")
        return ModelRegistry()

    def test_four_models_load_and_produce_distinct_real_scores(self, real_artifacts_available):
        registry = self._registry(real_artifacts_available)
        assert registry.preprocessor_ready is True
        assert registry.ready_count == 4
        assert registry.validated_count == 4

        row = {
            name: float(registry._preprocessor.imputed_values_[name])
            for name in registry.contract.feature_names
        }
        scores = registry.predict_all(row)

        assert set(scores) == set(MODEL_KEYS)
        assert scores["random_forest"].score_semantics == PROBABILITY_SEMANTICS
        assert scores["xgboost"].score_semantics == PROBABILITY_SEMANTICS
        assert scores["isolation_forest"].score_semantics == PERCENTILE_SEMANTICS
        assert scores["autoencoder"].score_semantics == PERCENTILE_SEMANTICS

        for score in scores.values():
            assert np.isfinite(score.raw_score)
            assert score.latency_us > 0.0
        for key in ("random_forest", "xgboost"):
            assert 0.0 <= scores[key].normalized_score <= 1.0
        for key in ("isolation_forest", "autoencoder"):
            assert 0.0 <= scores[key].normalized_score <= 1.0

        # Supervised probability must equal the artifact's own predict_proba.
        transformed = registry.transform_features(row)
        expected = float(
            registry._backends["random_forest"].estimator.predict_proba(transformed)[0, 1]
        )
        assert scores["random_forest"].raw_score == pytest.approx(expected, rel=1e-9)

        # Unsupervised scores come from the model, not from the supervised value.
        assert scores["isolation_forest"].raw_score != pytest.approx(
            scores["random_forest"].raw_score
        )

    def test_status_reports_threshold_source_and_semantics(self, real_artifacts_available):
        registry = self._registry(real_artifacts_available)
        summary = registry.summary()
        assert summary["ai_ready"] is True
        for model in summary["models"]:
            assert model["readiness"] in {"VALIDATED", "LOADED"}
            assert model["threshold"] is not None
            assert model["threshold_source"] != "unavailable"
            assert model["score_semantics"] in {
                PROBABILITY_SEMANTICS,
                PERCENTILE_SEMANTICS,
            }
