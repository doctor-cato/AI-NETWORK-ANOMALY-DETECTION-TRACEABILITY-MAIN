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
        engine = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            demo_heuristics=True,
            runtime_mode="research",
        )
        decision = engine.infer_event(_Event(), baseline_features(bytes_out=200_000.0))

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
        engine = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            runtime_mode="research",
        )
        assert engine.ood_gate_status == "NOT_FITTED"
        decision = engine.infer_event(_Event(), baseline_features())
        assert decision.is_ood is False
        assert decision.ood_gate_status == "NOT_FITTED"

    def test_deployment_mode_fails_closed_when_ood_gate_missing(self, tmp_path, baseline_features):
        engine = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            runtime_mode="deployment",
            demo_heuristics=True,
        )
        assert engine.ood_gate_status == "NOT_FITTED"
        assert engine.model_ready is False
        readiness = engine.readiness()
        assert readiness["runtime_mode"] == "deployment"
        assert readiness["require_ood_gate"] is True
        assert readiness["ai_ready"] is False
        assert readiness["inference_mode"] == "UNAVAILABLE"

        decision = engine.infer_event(_Event(), baseline_features(bytes_out=200_000.0))
        assert decision.inference_mode == "UNAVAILABLE"
        assert decision.ensemble_is_anomaly is False
        assert decision.abstained_due_to_ood is True
        assert decision.is_ood is True
        assert decision.ood_gate_status == "NOT_FITTED"
        assert "deployment_mode" in (decision.ood_reason or "")

        with pytest.raises(ValueError, match="require_ood_gate cannot be False"):
            RealtimeInferenceEngine(
                registry=_empty_registry(tmp_path),
                runtime_mode="deployment",
                require_ood_gate=False,
                demo_heuristics=True,
            )

    def test_corrupted_ood_gate_file_fails_closed_even_in_research_mode(
        self, tmp_path, baseline_features
    ):
        gate_file = tmp_path / "artifacts" / "ml" / "ood_reference_gate.json"
        gate_file.parent.mkdir(parents=True, exist_ok=True)
        gate_file.write_text("{corrupt json", encoding="utf-8")

        engine = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            runtime_mode="research",
            demo_heuristics=True,
        )
        assert engine.ood_gate_status == "ERROR"
        assert engine.ood_gate_error is not None
        assert engine.readiness()["inference_mode"] == "UNAVAILABLE"

        decision = engine.infer_event(_Event(), baseline_features(bytes_out=200_000.0))
        assert decision.inference_mode == "UNAVAILABLE"
        assert decision.ensemble_is_anomaly is False
        assert decision.abstained_due_to_ood is True
        assert decision.is_ood is True
        assert decision.ood_gate_status == "ERROR"
        assert "ood_gate_invalid" in (decision.ood_reason or "")

    def test_fitted_gate_abstains_on_out_of_distribution_row(self, tmp_path, baseline_features):
        rng = np.random.default_rng(42)
        gate = OODRejectionGate()
        gate.fit(rng.normal(size=(200, 18)), list(baseline_features().keys()))

        engine = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            ood_gate=gate,
            runtime_mode="research",
        )
        assert engine.ood_gate_status == "FITTED"

        decision = engine.infer_event(_Event(), baseline_features(bytes_out=1e12, bytes_in=1e12))
        assert decision.is_ood is True
        assert decision.abstained_due_to_ood is True
        assert decision.ensemble_is_anomaly is False

    def test_real_artifacts_reject_ood_gate_with_mismatched_preprocessor_sha(
        self, tmp_path, baseline_features, real_artifacts_available
    ):
        import json
        from pathlib import Path

        if not real_artifacts_available:
            pytest.skip("model artifacts are not present in this environment")

        src_gate = Path("artifacts/ml/ood_reference_gate.json")
        gate_payload = json.loads(src_gate.read_text(encoding="utf-8"))
        gate_payload["provenance"]["preprocessor_artifact_sha256"] = "0" * 64
        alt_artifacts = tmp_path / "artifacts"
        alt_gate = alt_artifacts / "ml" / "ood_reference_gate.json"
        alt_gate.parent.mkdir(parents=True, exist_ok=True)
        alt_gate.write_text(json.dumps(gate_payload), encoding="utf-8")

        real_prep = Path("artifacts/preprocessing/v2_flow_preprocessor.joblib").resolve()
        real_prep_man = Path("reports/preprocessing/v2_flow_preprocessing_manifest.json").resolve()
        registry = ModelRegistry(
            artifacts_dir=alt_artifacts,
            preprocessor_path=real_prep,
            preprocessor_manifest_path=real_prep_man,
            warmup=False,
        )
        engine = RealtimeInferenceEngine(registry=registry, runtime_mode="research")
        assert engine.ood_gate_status == "ERROR"
        assert "preprocessor_artifact_sha256 mismatch" in (engine.ood_gate_error or "")
        decision = engine.infer_event(_Event(), baseline_features())
        assert decision.inference_mode == "UNAVAILABLE"
        assert decision.abstained_due_to_ood is True

    def test_fake_fitted_object_without_provenance_is_rejected(self, tmp_path, baseline_features):
        from types import SimpleNamespace

        fake_gate = SimpleNamespace(is_fitted=True)
        engine = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            ood_gate=fake_gate,  # type: ignore[arg-type]
            runtime_mode="research",
            demo_heuristics=True,
        )
        assert engine.ood_gate_status == "ERROR"
        assert engine.ood_gate is None
        assert "OODRejectionGate instance" in (engine.ood_gate_error or "")
        assert engine.readiness()["inference_mode"] == "UNAVAILABLE"

        manual_gate = OODRejectionGate()
        manual_gate.is_fitted = True
        manual_gate.feature_names = list(baseline_features().keys())
        manual_gate.means = np.zeros(len(manual_gate.feature_names))
        manual_gate.stds = np.ones(len(manual_gate.feature_names))
        manual_gate.min_bounds = -np.ones(len(manual_gate.feature_names))
        manual_gate.max_bounds = np.ones(len(manual_gate.feature_names))
        manual_engine = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            ood_gate=manual_gate,
            runtime_mode="research",
            demo_heuristics=True,
        )
        assert manual_engine.ood_gate_status == "ERROR"
        assert "provenance" in (manual_engine.ood_gate_error or "")
        dec = manual_engine.infer_event(_Event(), baseline_features())
        assert dec.inference_mode == "UNAVAILABLE"
        assert dec.abstained_due_to_ood is True
        assert dec.ood_gate_status == "ERROR"

    def test_injected_gate_with_mismatched_features_or_non_finite_arrays_is_rejected(
        self, tmp_path, baseline_features
    ):
        rng = np.random.default_rng(17)
        wrong_feat_gate = OODRejectionGate().fit(rng.normal(size=(50, 4)), ["a", "b", "c", "d"])
        eng_wrong_feat = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            ood_gate=wrong_feat_gate,
            runtime_mode="research",
        )
        assert eng_wrong_feat.ood_gate_status == "ERROR"
        assert "feature_names mismatch" in (eng_wrong_feat.ood_gate_error or "")

        nan_gate = OODRejectionGate().fit(
            rng.normal(size=(50, 18)), list(baseline_features().keys())
        )
        nan_gate.stds[2] = float("nan")
        eng_nan = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            ood_gate=nan_gate,
            runtime_mode="research",
        )
        assert eng_nan.ood_gate_status == "ERROR"
        assert "non-finite" in (eng_nan.ood_gate_error or "")

        bad_shape_gate = OODRejectionGate().fit(
            rng.normal(size=(50, 18)), list(baseline_features().keys())
        )
        bad_shape_gate.max_bounds = np.ones(5)
        eng_shape = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            ood_gate=bad_shape_gate,
            runtime_mode="research",
        )
        assert eng_shape.ood_gate_status == "ERROR"
        assert "shape mismatch" in (eng_shape.ood_gate_error or "")

    def test_injected_gate_with_wrong_preprocessor_sha_is_rejected(
        self, tmp_path, baseline_features
    ):
        rng = np.random.default_rng(19)
        registry = _empty_registry(tmp_path)
        registry._preprocessor_metadata = {"artifact_sha256": "a" * 64}

        wrong_sha_gate = OODRejectionGate().fit(
            rng.normal(size=(50, 18)),
            list(baseline_features().keys()),
            provenance={"fit_rows": 50, "preprocessor_artifact_sha256": "b" * 64},
        )
        engine = RealtimeInferenceEngine(
            registry=registry,
            ood_gate=wrong_sha_gate,
            runtime_mode="research",
        )
        assert engine.ood_gate_status == "ERROR"
        assert "preprocessor_artifact_sha256 mismatch" in (engine.ood_gate_error or "")

        missing_sha_gate = OODRejectionGate().fit(
            rng.normal(size=(50, 18)),
            list(baseline_features().keys()),
        )
        engine_missing_sha = RealtimeInferenceEngine(
            registry=registry,
            ood_gate=missing_sha_gate,
            runtime_mode="research",
        )
        assert engine_missing_sha.ood_gate_status == "ERROR"
        assert "missing preprocessor_artifact_sha256" in (engine_missing_sha.ood_gate_error or "")

    def test_deployment_mode_rejects_injected_gate_and_accepts_verified_persisted_artifact(
        self, tmp_path, baseline_features, monkeypatch
    ):
        import hashlib
        import json

        rng = np.random.default_rng(23)
        in_memory_gate = OODRejectionGate().fit(
            rng.normal(size=(50, 18)),
            list(baseline_features().keys()),
            provenance={"fit_rows": 50, "preprocessor_artifact_sha256": "a" * 64},
        )
        registry = _empty_registry(tmp_path)
        registry._preprocessor_metadata = {"artifact_sha256": "a" * 64}

        rejected_engine = RealtimeInferenceEngine(
            registry=registry,
            ood_gate=in_memory_gate,
            runtime_mode="deployment",
            demo_heuristics=True,
        )
        assert rejected_engine.ood_gate_status == "ERROR"
        assert "disallowed" in (rejected_engine.ood_gate_error or "")
        assert rejected_engine.readiness()["ai_ready"] is False
        assert rejected_engine.readiness()["inference_mode"] == "UNAVAILABLE"
        dec = rejected_engine.infer_event(_Event(), baseline_features())
        assert dec.inference_mode == "UNAVAILABLE"
        assert dec.abstained_due_to_ood is True

        gate_path = registry.artifacts_dir / "ml" / "ood_reference_gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        payload = in_memory_gate.to_artifact(
            {
                "dataset_name": "AIT-NDS-v2",
                "partition": "train",
                "fit_rows": 50,
                "preprocessor_artifact_sha256": "a" * 64,
            }
        )
        gate_bytes = json.dumps(payload).encode("utf-8")
        gate_path.write_bytes(gate_bytes)
        expected_gate_sha = hashlib.sha256(gate_bytes).hexdigest()

        # Missing trusted expected SHA in deployment mode must fail closed even if unsigned
        # co-located EMBEDDED_ARTIFACTS_MANIFEST.json claims to endorse the artifact.
        (tmp_path / "EMBEDDED_ARTIFACTS_MANIFEST.json").write_text(
            json.dumps({"ood_gate": {"status": "FITTED", "sha256": expected_gate_sha}}),
            encoding="utf-8",
        )
        monkeypatch.delenv("NETFLOW_OOD_GATE_SHA256", raising=False)
        unanchored_engine = RealtimeInferenceEngine(
            registry=registry,
            runtime_mode="deployment",
            demo_heuristics=True,
        )
        assert unanchored_engine.ood_gate_status == "ERROR"
        assert unanchored_engine.ood_gate_trust_anchor == "missing_trusted_expected_sha256"
        assert "expected_ood_gate_sha256" in (unanchored_engine.ood_gate_error or "")
        assert unanchored_engine.readiness()["inference_mode"] == "UNAVAILABLE"
        assert (
            unanchored_engine.infer_event(_Event(), baseline_features()).inference_mode
            == "UNAVAILABLE"
        )

        # With explicit trusted expected SHA + matching preprocessor SHA -> PASS
        verified_engine = RealtimeInferenceEngine(
            registry=registry,
            runtime_mode="deployment",
            expected_ood_gate_sha256=expected_gate_sha,
        )
        assert verified_engine.ood_gate_status == "FITTED"
        assert verified_engine.ood_gate_error is None
        assert verified_engine.ood_gate_sha256 == expected_gate_sha
        assert verified_engine.ood_gate_trust_anchor == "explicit_expected_sha256"
        assert verified_engine.readiness()["runtime_mode"] == "deployment"
        assert verified_engine.readiness()["ood_gate_status"] == "FITTED"
        assert verified_engine.readiness()["ood_gate_trust_anchor"] == "explicit_expected_sha256"

        # Via NETFLOW_OOD_GATE_SHA256 env var -> PASS
        monkeypatch.setenv("NETFLOW_OOD_GATE_SHA256", expected_gate_sha)
        env_engine = RealtimeInferenceEngine(registry=registry, runtime_mode="deployment")
        assert env_engine.ood_gate_status == "FITTED"
        assert env_engine.ood_gate_trust_anchor == "env:NETFLOW_OOD_GATE_SHA256"
        monkeypatch.delenv("NETFLOW_OOD_GATE_SHA256", raising=False)

    def test_persisted_ood_gate_expected_sha_rejects_mismatch_and_valid_json_tamper(
        self, tmp_path, baseline_features
    ):
        import hashlib
        import json

        rng = np.random.default_rng(31)
        gate = OODRejectionGate().fit(rng.normal(size=(50, 18)), list(baseline_features().keys()))
        registry = _empty_registry(tmp_path)
        registry._preprocessor_metadata = {"artifact_sha256": "a" * 64}

        gate_path = registry.artifacts_dir / "ml" / "ood_reference_gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        payload = gate.to_artifact(
            {
                "dataset_name": "AIT-NDS-v2",
                "partition": "train",
                "fit_rows": 50,
                "preprocessor_artifact_sha256": "a" * 64,
            }
        )
        gate_bytes = json.dumps(payload).encode("utf-8")
        gate_path.write_bytes(gate_bytes)
        expected_gate_sha = hashlib.sha256(gate_bytes).hexdigest()

        # Wrong expected SHA -> REJECT
        wrong_sha_engine = RealtimeInferenceEngine(
            registry=registry,
            runtime_mode="deployment",
            expected_ood_gate_sha256="f" * 64,
            demo_heuristics=True,
        )
        assert wrong_sha_engine.ood_gate_status == "ERROR"
        assert "SHA-256 mismatch" in (wrong_sha_engine.ood_gate_error or "")
        assert (
            wrong_sha_engine.infer_event(_Event(), baseline_features()).inference_mode
            == "UNAVAILABLE"
        )

        # Structurally valid JSON edit (fit_rows changed from 50 -> 51) -> REJECT
        tampered_payload = json.loads(json.dumps(payload))
        tampered_payload["provenance"]["fit_rows"] = 51
        gate_path.write_text(json.dumps(tampered_payload), encoding="utf-8")
        tampered_engine = RealtimeInferenceEngine(
            registry=registry,
            runtime_mode="deployment",
            expected_ood_gate_sha256=expected_gate_sha,
        )
        assert tampered_engine.ood_gate_status == "ERROR"
        assert "SHA-256 mismatch" in (tampered_engine.ood_gate_error or "")

        # Matching tampered SHA but wrong preprocessor SHA -> REJECT
        tampered_sha = hashlib.sha256(gate_path.read_bytes()).hexdigest()
        registry._preprocessor_metadata = {"artifact_sha256": "b" * 64}
        bad_prep_engine = RealtimeInferenceEngine(
            registry=registry,
            runtime_mode="deployment",
            expected_ood_gate_sha256=tampered_sha,
        )
        assert bad_prep_engine.ood_gate_status == "ERROR"
        assert "preprocessor_artifact_sha256 mismatch" in (bad_prep_engine.ood_gate_error or "")

    def test_research_mode_unanchored_and_same_boundary_manifest_mismatch(
        self, tmp_path, baseline_features
    ):
        import hashlib
        import json

        rng = np.random.default_rng(37)
        gate = OODRejectionGate().fit(rng.normal(size=(50, 18)), list(baseline_features().keys()))
        registry = _empty_registry(tmp_path)
        registry._preprocessor_metadata = {"artifact_sha256": "a" * 64}

        gate_path = registry.artifacts_dir / "ml" / "ood_reference_gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        payload = gate.to_artifact(
            {
                "dataset_name": "AIT-NDS-v2",
                "partition": "train",
                "fit_rows": 50,
                "preprocessor_artifact_sha256": "a" * 64,
            }
        )
        gate_bytes = json.dumps(payload).encode("utf-8")
        gate_path.write_bytes(gate_bytes)
        actual_sha = hashlib.sha256(gate_bytes).hexdigest()

        # Research mode without expected_ood_gate_sha256 still works per contract
        res_engine = RealtimeInferenceEngine(registry=registry, runtime_mode="research")
        assert res_engine.ood_gate_status == "FITTED"
        assert res_engine.ood_gate_trust_anchor == "unanchored_local_artifact"

        # If co-located EMBEDDED_ARTIFACTS_MANIFEST.json mismatches actual artifact -> REJECT
        (tmp_path / "EMBEDDED_ARTIFACTS_MANIFEST.json").write_text(
            json.dumps({"ood_gate": {"status": "FITTED", "sha256": "0" * 64}}),
            encoding="utf-8",
        )
        mismatch_engine = RealtimeInferenceEngine(registry=registry, runtime_mode="research")
        assert mismatch_engine.ood_gate_status == "ERROR"
        assert "EMBEDDED_ARTIFACTS_MANIFEST.json" in (mismatch_engine.ood_gate_error or "")

        # Matching co-located manifest records honest unanchored_same_boundary_manifest
        (tmp_path / "EMBEDDED_ARTIFACTS_MANIFEST.json").write_text(
            json.dumps({"ood_gate": {"status": "FITTED", "sha256": actual_sha}}),
            encoding="utf-8",
        )
        matched_engine = RealtimeInferenceEngine(registry=registry, runtime_mode="research")
        assert matched_engine.ood_gate_status == "FITTED"
        assert matched_engine.ood_gate_trust_anchor == "unanchored_same_boundary_manifest"

    def test_ood_runtime_error_during_evaluate_sample_fails_closed(
        self, tmp_path, baseline_features
    ):
        rng = np.random.default_rng(29)
        gate = OODRejectionGate().fit(rng.normal(size=(50, 18)), list(baseline_features().keys()))
        engine = RealtimeInferenceEngine(
            registry=_empty_registry(tmp_path),
            ood_gate=gate,
            runtime_mode="research",
            demo_heuristics=True,
        )
        assert engine.ood_gate_status == "FITTED"

        def _boom(_features):
            raise RuntimeError("corrupted runtime state")

        engine.ood_gate.evaluate_sample = _boom  # type: ignore[method-assign]
        dec = engine.infer_event(_Event(), baseline_features())
        assert dec.inference_mode == "UNAVAILABLE"
        assert dec.abstained_due_to_ood is True
        assert dec.ood_gate_status == "ERROR"
        assert "ood_gate_runtime_error" in (dec.ood_reason or "")
        assert engine.total_inference_errors == 1

    def test_live_orchestrator_forwards_runtime_mode_and_rejects_mismatched_engine(
        self, tmp_path, monkeypatch
    ):
        from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator
        from network_anomaly.streaming.live_service import LiveTelemetryService

        orch_deploy = LiveSystemOrchestrator(
            runtime_mode="deployment",
            expected_ood_gate_sha256="e" * 64,
        )
        assert orch_deploy.inference_engine.runtime_mode == "deployment"
        assert orch_deploy.inference_engine.require_ood_gate is True
        assert orch_deploy.inference_engine.expected_ood_gate_sha256 == "e" * 64

        svc_deploy = LiveTelemetryService(
            db_path=tmp_path / "svc.db",
            keystore_dir=tmp_path / "keys",
            runtime_mode="deployment",
            expected_ood_gate_sha256="e" * 64,
        )
        assert svc_deploy.orchestrator.inference_engine.runtime_mode == "deployment"
        assert svc_deploy.orchestrator.inference_engine.require_ood_gate is True
        assert svc_deploy.orchestrator.inference_engine.expected_ood_gate_sha256 == "e" * 64

        monkeypatch.setenv("NETFLOW_RUNTIME_MODE", "research")
        orch_research = LiveSystemOrchestrator()
        assert orch_research.inference_engine.runtime_mode == "research"
        assert orch_research.inference_engine.require_ood_gate is False

        with pytest.raises(ValueError, match="runtime_mode"):
            LiveSystemOrchestrator(
                inference_engine=orch_research.inference_engine,
                runtime_mode="deployment",
            )
        with pytest.raises(ValueError, match="expected_ood_gate_sha256"):
            LiveSystemOrchestrator(
                inference_engine=orch_deploy.inference_engine,
                expected_ood_gate_sha256="f" * 64,
            )


class TestRealInference:
    def test_all_four_artifacts_are_invoked_per_event(
        self, tmp_path, baseline_features, real_artifacts_available
    ):
        import hashlib
        from pathlib import Path

        if not real_artifacts_available:
            pytest.skip("model artifacts are not present in this environment")

        gate_sha = hashlib.sha256(
            Path("artifacts/ml/ood_reference_gate.json").read_bytes()
        ).hexdigest()
        registry = ModelRegistry()
        engine = RealtimeInferenceEngine(
            registry=registry,
            runtime_mode="deployment",
            expected_ood_gate_sha256=gate_sha,
        )
        assert engine.readiness()["runtime_mode"] == "deployment"
        assert engine.readiness()["production_ready"] is False
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


class TestProductRuntimeEntryPointPolicy:
    def test_engine_and_live_runtime_default_fail_closed_to_deployment(self, tmp_path, monkeypatch):
        from network_anomaly.api.live_runtime import LiveRuntime

        monkeypatch.delenv("NETFLOW_RUNTIME_MODE", raising=False)
        monkeypatch.delenv("NETFLOW_REQUIRE_OOD_GATE", raising=False)
        monkeypatch.delenv("NETFLOW_OOD_GATE_SHA256", raising=False)
        monkeypatch.delenv("NETFLOW_EMBEDDED_OOD_GATE_SHA256", raising=False)

        engine = RealtimeInferenceEngine(registry=_empty_registry(tmp_path))
        assert engine.runtime_mode == "deployment"
        assert engine.require_ood_gate is True
        assert engine.runtime_policy_source == "default_fail_closed:deployment"
        assert engine.readiness()["production_ready"] is False

        rt = LiveRuntime(db_path=tmp_path / "rt.db", keystore_dir=tmp_path / "keys")
        assert rt.runtime_mode == "deployment"
        assert rt.require_ood_gate is True
        pre_status = rt.status()
        assert pre_status["inference"]["runtime_mode"] == "deployment"
        assert pre_status["inference"]["require_ood_gate"] is True
        assert pre_status["inference"]["ood_gate_trust_anchor"] == "missing_trusted_expected_sha256"
        assert pre_status["inference"]["inference_mode"] == "UNAVAILABLE"

        # Downgrade from deployment to research must fail closed
        with pytest.raises(ValueError, match="Cannot downgrade"):
            rt.start(host="127.0.0.1", port=0, runtime_mode="research")
        with pytest.raises(ValueError, match="require_ood_gate cannot be False"):
            rt.start(host="127.0.0.1", port=0, require_ood_gate=False)

        try:
            started = rt.start(host="127.0.0.1", port=0)
            inf = started["inference"]
            assert inf["runtime_mode"] == "deployment"
            assert inf["require_ood_gate"] is True
            assert inf["ai_ready"] is False
            assert inf["inference_mode"] == "UNAVAILABLE"
            assert inf["production_ready"] is False
            if rt._service is not None:
                eng = rt._service.orchestrator.inference_engine
                assert eng.runtime_mode == "deployment"
                assert eng.require_ood_gate is True
        finally:
            rt.shutdown()

    def test_live_runtime_deployment_loads_valid_sha_and_rejects_tampered_or_wrong_sha(
        self, tmp_path, baseline_features, monkeypatch
    ):
        import hashlib
        import json
        from pathlib import Path

        from network_anomaly.api.live_runtime import LiveRuntime
        from network_anomaly.config import resolve_artifacts_dir

        real_prep_man = Path("reports/preprocessing/v2_flow_preprocessing_manifest.json")
        if not real_prep_man.is_file():
            pytest.skip("Preprocessor manifest unavailable")
        prep_sha = json.loads(real_prep_man.read_text(encoding="utf-8"))["artifact_sha256"]

        rng = np.random.default_rng(77)
        gate = OODRejectionGate().fit(rng.normal(size=(40, 18)), list(baseline_features().keys()))
        payload = gate.to_artifact(
            {
                "dataset_name": "AIT-NDS-v2",
                "partition": "train",
                "fit_rows": 40,
                "preprocessor_artifact_sha256": prep_sha,
            }
        )
        art_dir = tmp_path / "artifacts"
        gate_path = art_dir / "ml" / "ood_reference_gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_bytes = json.dumps(payload).encode("utf-8")
        gate_path.write_bytes(gate_bytes)
        expected_sha = hashlib.sha256(gate_bytes).hexdigest()

        # Copy real preprocessor & models if absent? No, test against temp artifacts dir via env
        monkeypatch.setenv("NETWORK_ANOMALY_ARTIFACTS_DIR", str(art_dir))
        assert resolve_artifacts_dir() == art_dir.resolve()
        monkeypatch.delenv("NETFLOW_RUNTIME_MODE", raising=False)
        monkeypatch.delenv("NETFLOW_OOD_GATE_SHA256", raising=False)

        # 1. Missing trusted SHA in deployment mode -> blocked UNAVAILABLE
        rt_missing = LiveRuntime(db_path=tmp_path / "missing.db", keystore_dir=tmp_path / "k1")
        try:
            st = rt_missing.start(host="127.0.0.1", port=0)
            assert st["inference"]["runtime_mode"] == "deployment"
            assert st["inference"]["ood_gate_status"] == "ERROR"
            assert st["inference"]["ood_gate_trust_anchor"] == "missing_trusted_expected_sha256"
            assert st["inference"]["inference_mode"] == "UNAVAILABLE"
            assert st["inference"]["ai_ready"] is False
        finally:
            rt_missing.shutdown()

        # 2. Incorrect expected SHA -> rejected ERROR
        rt_wrong = LiveRuntime(
            db_path=tmp_path / "wrong.db",
            keystore_dir=tmp_path / "k2",
            expected_ood_gate_sha256="f" * 64,
        )
        try:
            st = rt_wrong.start(host="127.0.0.1", port=0)
            assert st["inference"]["ood_gate_status"] == "ERROR"
            assert "SHA-256 mismatch" in (st["inference"]["ood_gate_error"] or "")
            assert st["inference"]["inference_mode"] == "UNAVAILABLE"
        finally:
            rt_wrong.shutdown()

        # 3. Matching build-embedded SHA -> FITTED & trust_anchor="build_embedded_sha256"
        monkeypatch.setenv("NETFLOW_EMBEDDED_OOD_GATE_SHA256", expected_sha)
        rt_embedded = LiveRuntime(db_path=tmp_path / "emb.db", keystore_dir=tmp_path / "k3")
        try:
            st = rt_embedded.start(host="127.0.0.1", port=0)
            assert st["inference"]["runtime_mode"] == "deployment"
            assert st["inference"]["ood_gate_status"] == "FITTED"
            assert st["inference"]["ood_gate_sha256"] == expected_sha
            assert st["inference"]["ood_gate_trust_anchor"] == "build_embedded_sha256"
            assert st["inference"]["expected_ood_gate_sha256_configured"] is True
            assert st["inference"]["production_ready"] is False
        finally:
            rt_embedded.shutdown()
        monkeypatch.delenv("NETFLOW_EMBEDDED_OOD_GATE_SHA256", raising=False)

        # 4. Tampered OOD artifact against matching expected SHA -> rejected ERROR
        tampered = json.loads(gate_bytes.decode("utf-8"))
        tampered["provenance"]["fit_rows"] = 41
        gate_path.write_text(json.dumps(tampered), encoding="utf-8")
        rt_tampered = LiveRuntime(
            db_path=tmp_path / "tamper.db",
            keystore_dir=tmp_path / "k4",
            expected_ood_gate_sha256=expected_sha,
        )
        try:
            st = rt_tampered.start(host="127.0.0.1", port=0)
            assert st["inference"]["ood_gate_status"] == "ERROR"
            assert "SHA-256 mismatch" in (st["inference"]["ood_gate_error"] or "")
            assert st["inference"]["inference_mode"] == "UNAVAILABLE"
        finally:
            rt_tampered.shutdown()

    def test_research_mode_requires_explicit_selection_and_run_api_defaults_to_deployment(
        self, tmp_path, monkeypatch
    ):
        import sys

        import uvicorn

        from network_anomaly.api.live_runtime import LiveRuntime
        from scripts import run_api

        monkeypatch.delenv("NETFLOW_RUNTIME_MODE", raising=False)
        monkeypatch.delenv("NETFLOW_REQUIRE_OOD_GATE", raising=False)
        monkeypatch.delenv("NETFLOW_OOD_GATE_SHA256", raising=False)

        # Explicit research profile works and reports itself transparently
        rt_research = LiveRuntime(
            db_path=tmp_path / "res.db",
            keystore_dir=tmp_path / "kr",
            runtime_mode="research",
        )
        try:
            st = rt_research.start(host="127.0.0.1", port=0, demo_heuristics=True)
            assert st["inference"]["runtime_mode"] == "research"
            assert st["inference"]["runtime_policy_source"] == "explicit_argument"
            assert st["inference"]["require_ood_gate"] is False
        finally:
            rt_research.shutdown()

        # run_api.py defaults to deployment when --runtime-mode / env absent
        captured = {}

        def _fake_uvicorn_run(app_obj, host, port, reload):
            captured["app"] = app_obj
            captured["host"] = host
            captured["port"] = port

        monkeypatch.setattr(uvicorn, "run", _fake_uvicorn_run)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "run_api.py",
                "--host",
                "127.0.0.1",
                "--port",
                "8123",
                "--db-path",
                str(tmp_path / "api.db"),
            ],
        )
        run_api.main()
        rt_from_api = captured["app"].state.live_runtime
        assert rt_from_api.runtime_mode == "deployment"
        assert rt_from_api.require_ood_gate is True
        rt_from_api.shutdown()

        # run_api.py honors explicit --runtime-mode research
        monkeypatch.delenv("NETFLOW_RUNTIME_MODE", raising=False)
        monkeypatch.delenv("NETFLOW_REQUIRE_OOD_GATE", raising=False)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "run_api.py",
                "--host",
                "127.0.0.1",
                "--port",
                "8124",
                "--db-path",
                str(tmp_path / "api2.db"),
                "--runtime-mode",
                "research",
            ],
        )
        run_api.main()
        rt_research_api = captured["app"].state.live_runtime
        assert rt_research_api.runtime_mode == "research"
        assert rt_research_api.require_ood_gate is False
        rt_research_api.shutdown()
