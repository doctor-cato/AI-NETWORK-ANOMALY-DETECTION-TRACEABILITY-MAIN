"""Tests that live inference calls real model artifacts and never fabricates scores."""

from __future__ import annotations

import numpy as np
import pytest

from network_anomaly.ml.ood_gate import OODRejectionGate
from network_anomaly.models.registry import MODEL_KEYS, ModelRegistry
from network_anomaly.streaming.realtime_inference import (
    ENSEMBLE_SCORE_SEMANTICS,
    RealtimeInferenceEngine,
)


class _Event:
    def __init__(self, event_id: str = "evt-test"):
        self.event_id = event_id


def _empty_registry(tmp_path) -> ModelRegistry:
    return ModelRegistry(
        artifacts_dir=tmp_path / "artifacts",
        manifest_root=tmp_path / "manifests",
        preprocessor_path=tmp_path / "preprocessor.joblib",
        preprocessor_manifest_path=tmp_path / "preprocessor.json",
        warmup=False,
    )


class TestUnavailable:
    def test_no_artifact_means_no_model_score(self, tmp_path, baseline_features):
        engine = RealtimeInferenceEngine(registry=_empty_registry(tmp_path))
        decision = engine.infer_event(_Event(), baseline_features())

        assert decision.inference_mode == "UNAVAILABLE"
        assert decision.model_predictions == {}
        assert decision.participating_models == []
        assert decision.ensemble_score == 0.0
        assert len(decision.unavailable_models) == 4
        assert engine.total_unavailable_events == 1

    def test_demo_heuristic_is_explicitly_labelled(self, tmp_path, baseline_features):
        engine = RealtimeInferenceEngine(registry=_empty_registry(tmp_path), demo_heuristics=True)
        decision = engine.infer_event(_Event(), baseline_features(OUT_BYTES=200_000.0))

        assert decision.inference_mode == "DEMO_HEURISTIC"
        assert decision.ensemble_score_semantics == "demo_heuristic_score_not_model_output"
        assert set(decision.model_predictions) == set(MODEL_KEYS)
        assert all(
            prediction["score_semantics"] == "demo_heuristic_score_not_model_output"
            for prediction in decision.model_predictions.values()
        )
        assert engine.total_demo_decisions == 1


class TestOODGate:
    def test_unfitted_gate_is_reported_not_guessed(self, tmp_path, baseline_features):
        engine = RealtimeInferenceEngine(registry=_empty_registry(tmp_path))
        assert engine.ood_gate_status == "NOT_FITTED"
        decision = engine.infer_event(_Event(), baseline_features())
        assert decision.is_ood is False
        assert decision.ood_gate_status == "NOT_FITTED"

    def test_fitted_gate_abstains_on_out_of_distribution_row(self, tmp_path, baseline_features):
        rng = np.random.default_rng(42)
        gate = OODRejectionGate()
        gate.fit(rng.normal(size=(200, 47)), list(baseline_features().keys()))

        engine = RealtimeInferenceEngine(registry=_empty_registry(tmp_path), ood_gate=gate)
        assert engine.ood_gate_status == "FITTED"

        decision = engine.infer_event(_Event(), baseline_features(OUT_BYTES=1e12, IN_BYTES=1e12))
        assert decision.is_ood is True
        assert decision.abstained_due_to_ood is True
        assert decision.ensemble_is_anomaly is False


class TestRealInference:
    def test_all_four_artifacts_are_invoked_per_event(
        self, tmp_path, baseline_features, real_artifacts_available
    ):
        if not real_artifacts_available:
            pytest.skip("model artifacts are not present in this environment")

        registry = ModelRegistry()
        engine = RealtimeInferenceEngine(registry=registry)
        row = {
            name: float(registry._preprocessor.imputed_values_[name])
            for name in registry.contract.feature_names
        }
        decision = engine.infer_event(_Event(), row)

        assert decision.inference_mode == "REAL_MODELS"
        assert set(decision.model_predictions) == set(MODEL_KEYS)
        assert set(decision.participating_models) == set(MODEL_KEYS)
        assert decision.ensemble_score_semantics == ENSEMBLE_SCORE_SEMANTICS
        assert decision.total_inference_latency_us > 0.0
        for key in MODEL_KEYS:
            assert registry.status(key).inference_count == 1
            assert decision.per_model_latency_us[key] > 0.0
            assert "score_semantics" in decision.model_predictions[key]
