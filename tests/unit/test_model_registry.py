"""Tests for the verified model registry and score semantics.

These tests are the evidence that live inference calls real artifacts rather
than a heuristic. Artifact-dependent tests skip explicitly when the gitignored
artifacts are not present (the normal CI state).
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from network_anomaly.models.registry import (
    MODEL_KEYS,
    FeatureContractError,
    ModelReadiness,
    ModelRegistry,
    _evaluate_manifest_readiness_tiers,
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
            assert model["artifact_verified"] is True
            assert model["in_domain_evaluated"] is True
            assert model["cross_source_validated"] is False
            assert model["deployment_tier"] == "RESEARCH_ONLY"
        assert summary["production_ready"] is False
        assert summary["cross_source_validated_count"] == 0
        assert "not_production_certified" in summary["ai_ready_semantics"]

    def test_mismatched_split_manifest_sha256_is_rejected(self, real_artifacts_available, tmp_path):
        if not real_artifacts_available:
            pytest.skip("model artifacts are not present in this environment")
        src_manifests = Path("reports/models")
        tmp_manifests = tmp_path / "manifests"
        tmp_manifests.mkdir()
        for fname in (
            "random_forest_manifest.json",
            "xgboost_manifest.json",
            "isolation_forest_manifest.json",
            "autoencoder_manifest.json",
        ):
            data = json.loads((src_manifests / fname).read_text(encoding="utf-8"))
            if fname == "random_forest_manifest.json":
                data["split_manifest_sha256"] = "0" * 64
            (tmp_manifests / fname).write_text(json.dumps(data), encoding="utf-8")

        registry = ModelRegistry(manifest_root=tmp_manifests, warmup=False)
        rf_status = {s.model_key: s for s in registry.statuses()}["random_forest"]
        assert rf_status.readiness == ModelReadiness.ERROR
        assert "split_manifest_sha256 mismatch" in (rf_status.reason or "")
        assert rf_status.artifact_verified is False
        assert rf_status.deployment_tier == "RESEARCH_ONLY"


class TestReadinessTiers:
    def test_separated_readiness_tiers_never_promote_without_cross_source(self):
        base_manifest = {
            "feature_contract_version": "canonical-flow-v2-18",
            "preprocessor_artifact_sha256": "prep_sha",
            "split_manifest_sha256": "split_sha",
            "threshold_provenance": {"selected_on": "validation", "test_touched": False},
            "evaluation": {
                "ait_test": {"recall": 0.99, "false_positive_rate": 0.001},
                "ctu_echo": {"recall": 0.0264, "false_positive_rate": 0.0811},
                "ctu_windows7ad": {"recall": 0.5412, "false_positive_rate": 0.1608},
            },
        }
        # RF passing in-domain, failing cross-source -> RESEARCH_ONLY
        art, ind, cross, tier = _evaluate_manifest_readiness_tiers(
            "random_forest",
            base_manifest,
            threshold=0.5,
            threshold_source="validation_verified",
            artifact_sha256="model_sha",
            expected_prep_sha256="prep_sha",
            expected_split_sha256="split_sha",
        )
        assert (art, ind, cross, tier) == (True, True, False, "RESEARCH_ONLY")

        # Missing test metrics -> in_domain_evaluated=False
        no_eval = dict(base_manifest, evaluation={})
        art, ind, cross, tier = _evaluate_manifest_readiness_tiers(
            "random_forest",
            no_eval,
            threshold=0.5,
            threshold_source="validation_verified",
            artifact_sha256="model_sha",
            expected_prep_sha256="prep_sha",
            expected_split_sha256="split_sha",
        )
        assert (art, ind, cross, tier) == (True, False, False, "RESEARCH_ONLY")

        # Mismatched split_manifest_sha256 -> artifact_verified=False
        bad_split = dict(base_manifest, split_manifest_sha256="wrong")
        art, ind, cross, tier = _evaluate_manifest_readiness_tiers(
            "random_forest",
            bad_split,
            threshold=0.5,
            threshold_source="validation_verified",
            artifact_sha256="model_sha",
            expected_prep_sha256="prep_sha",
            expected_split_sha256="split_sha",
        )
        assert (art, ind, cross, tier) == (False, True, False, "RESEARCH_ONLY")

        # Missing split_manifest_sha256 when expected -> artifact_verified=False
        missing_split = {k: v for k, v in base_manifest.items() if k != "split_manifest_sha256"}
        art, ind, cross, tier = _evaluate_manifest_readiness_tiers(
            "random_forest",
            missing_split,
            threshold=0.5,
            threshold_source="validation_verified",
            artifact_sha256="model_sha",
            expected_prep_sha256="prep_sha",
            expected_split_sha256="split_sha",
        )
        assert (art, ind, cross, tier) == (False, True, False, "RESEARCH_ONLY")

        # Even if cross-source passes, xgboost remains RESEARCH_ONLY
        passing_cross = dict(
            base_manifest,
            evaluation={
                "ait_test": {"recall": 0.95, "false_positive_rate": 0.01},
                "ctu_echo": {"recall": 0.85, "false_positive_rate": 0.05},
                "ctu_windows7ad": {"recall": 0.80, "false_positive_rate": 0.05},
            },
        )
        _, _, xgb_cross, xgb_tier = _evaluate_manifest_readiness_tiers(
            "xgboost",
            passing_cross,
            threshold=0.5,
            threshold_source="validation_verified",
            artifact_sha256="model_sha",
            expected_prep_sha256="prep_sha",
            expected_split_sha256="split_sha",
        )
        assert xgb_cross is True
        assert xgb_tier == "RESEARCH_ONLY"

        # RF promotes only when artifact + in-domain + cross-source all pass
        _, _, rf_cross, rf_tier = _evaluate_manifest_readiness_tiers(
            "random_forest",
            passing_cross,
            threshold=0.5,
            threshold_source="validation_verified",
            artifact_sha256="model_sha",
            expected_prep_sha256="prep_sha",
            expected_split_sha256="split_sha",
        )
        assert (rf_cross, rf_tier) == (True, "PRODUCTION_ELIGIBLE")
