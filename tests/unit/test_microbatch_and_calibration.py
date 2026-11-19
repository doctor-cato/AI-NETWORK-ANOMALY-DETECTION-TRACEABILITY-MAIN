"""Tests for vectorized micro-batch processing, threshold profiles, OOD-aware aggregation,
and local benign baseline calibration.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List, Mapping, Tuple

import numpy as np
import pandas as pd
import pytest

from network_anomaly.api.db import DatabaseManager
from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.crypto.encrypted_storage import EncryptedStorageVault
from network_anomaly.crypto.key_manager import KeyManager
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.ml.local_calibration import LocalBenignCalibrator
from network_anomaly.ml.ood_gate import OODRejectionGate
from network_anomaly.models.registry import (
    MODEL_KEYS,
    SUPPORTED_THRESHOLD_PROFILES,
    VALIDATED_YOUDEN_J_THRESHOLDS,
    ModelReadiness,
    ModelRegistry,
    ModelStatus,
    _SupervisedBackend,
    _ThresholdBackend,
)
from network_anomaly.risk.aggregation import (
    AggregationPolicy,
    MultiModelDecisionAggregator,
)
from network_anomaly.streaming.alert_manager import LiveAlertManager
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator
from network_anomaly.streaming.realtime_inference import RealtimeInferenceEngine


def _make_flow_event(
    event_id: str,
    features: Mapping[str, float],
    *,
    entity_id: str = "host-10.0.0.5",
    dest_port: int = 443,
    offset_sec: int = 0,
    attack_category: str | None = None,
) -> CanonicalSecurityEvent:
    ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_sec)
    return CanonicalSecurityEvent(
        event_id=event_id,
        event_timestamp=ts,
        event_kind=EventKind.FLOW,
        source_id="unit-test-flow",
        entity_id=entity_id,
        source_ip="10.0.0.5",
        source_port=50000 + offset_sec,
        dest_ip="10.0.0.20",
        dest_port=dest_port,
        protocol="TCP",
        flow_metrics=FlowMetrics(
            duration_ms=float(features["duration_ms"]),
            bytes_in=int(features["bytes_in"]),
            bytes_out=int(features["bytes_out"]),
            pkts_in=int(features["pkts_in"]),
            pkts_out=int(features["pkts_out"]),
            tcp_flags=24,
        ),
        raw_provenance=RawProvenance(
            source_file="unit-test",
            line_or_offset=offset_sec,
            adapter_name="unit-test-adapter",
        ),
        attack_category=attack_category,
        ml_features={k: float(v) for k, v in features.items()},
        is_ml_complete=True,
    )


class _DummyPreprocessor:
    def transform(self, frame: pd.DataFrame) -> pd.DataFrame:
        return frame.astype(float)


class _DummyClassifier:
    def predict_proba(self, X: Any) -> np.ndarray:
        arr = np.asarray(X, dtype=float)
        # Positive class score driven by bytes_out column (index 2)
        p1 = 1.0 / (1.0 + np.exp(-(arr[:, 2] - 5000.0) / 1000.0))
        return np.column_stack([1.0 - p1, p1])


class _DummyThresholdModel:
    def anomaly_scores(self, X: Any) -> np.ndarray:
        arr = np.asarray(X, dtype=float)
        return arr[:, 2] / 10000.0


class _DummyStage2Classifier:
    def __init__(self, label: str = "Network_Scan", conf: float = 0.91) -> None:
        self.label = label
        self.conf = conf
        self.batch_calls = 0
        self.one_calls = 0

    def predict_one(self, X_row: Any) -> Tuple[str, float]:
        arr = np.asarray(X_row, dtype=float)
        assert arr.ndim == 1 and arr.shape[0] == 18
        self.one_calls += 1
        return self.label, self.conf

    def predict_batch(self, X_mat: Any) -> List[Tuple[str, float]]:
        arr = np.asarray(X_mat, dtype=float)
        assert arr.ndim == 2 and arr.shape[1] == 18
        self.batch_calls += 1
        return [(self.label, self.conf) for _ in range(arr.shape[0])]


def _make_mock_registry(tmp_path: Path, *, high_scores: bool = False) -> ModelRegistry:
    registry = ModelRegistry(
        artifacts_dir=tmp_path / "missing_artifacts",
        manifest_root=tmp_path / "missing_manifests",
        preprocessor_path=tmp_path / "missing_prep.joblib",
        preprocessor_manifest_path=tmp_path / "missing_prep.json",
        warmup=False,
    )
    registry._preprocessor = _DummyPreprocessor()
    registry._preprocessor_metadata = {"artifact_sha256": "a" * 64}
    registry._preprocessor_error = None

    calibration = {
        "calibration_partition": "validation",
        "score_direction": "higher_is_more_anomalous",
        "quantile_grid": [0.0, 0.5, 1.0],
        "score_values": [0.0, 0.5, 1.0] if not high_scores else [0.0, 0.1, 0.2],
    }

    registry._backends = {
        "random_forest": _SupervisedBackend(_DummyClassifier(), 0.5, None),
        "xgboost": _SupervisedBackend(_DummyClassifier(), 0.5, None),
        "isolation_forest": _ThresholdBackend(_DummyThresholdModel(), 0.5, calibration),
        "autoencoder": _ThresholdBackend(_DummyThresholdModel(), 0.5, calibration),
    }
    for key in MODEL_KEYS:
        registry._statuses[key] = ModelStatus(
            model_key=key,
            display_name=key,
            model_type=key,
            readiness=ModelReadiness.VALIDATED,
            artifact_path=f"mock/{key}",
            threshold=0.5,
            threshold_source="mock",
            score_semantics="probability" if key in ("random_forest", "xgboost") else "percentile",
            validated=True,
        )
    return registry


class TestOODBatchEquivalence:
    def test_evaluate_batch_requires_fit_and_handles_empty(self):
        gate = OODRejectionGate()
        with pytest.raises(RuntimeError, match="must be fitted"):
            gate.evaluate_batch([{"a": 1.0}])

        gate.fit(np.array([[1.0, 2.0], [1.5, 2.5]]), ["a", "b"])
        assert gate.evaluate_batch([]) == []

    def test_evaluate_batch_matches_evaluate_sample_across_all_paths(self):
        rng = np.random.default_rng(123)
        feats = list(ML_FEATURE_COLUMNS)
        X_train = rng.normal(loc=10.0, scale=1.0, size=(300, len(feats)))
        gate = OODRejectionGate(std_margin=3.0, statistical_threshold=2.5).fit(X_train, feats)

        in_dist = {f: 10.1 for f in feats}
        bounds_breach = {f: 10.0 for f in feats}
        for f in feats[:4]:
            bounds_breach[f] = 999.0
        stat_outlier = {f: 13.0 for f in feats}
        # Only 2 features breach bounds (<3), but mean z-score > statistical_threshold
        stat_outlier[feats[0]] = 50.0
        stat_outlier[feats[1]] = 50.0
        missing_row = {feats[0]: 10.0}
        nan_row = dict(in_dist, **{feats[2]: float("nan")})
        inf_row = dict(in_dist, **{feats[3]: float("inf")})

        batch = [in_dist, bounds_breach, stat_outlier, missing_row, nan_row, inf_row]
        batch_decisions = gate.evaluate_batch(batch)
        sample_decisions = [gate.evaluate_sample(dict(row)) for row in batch]

        assert len(batch_decisions) == len(sample_decisions)
        for bd, sd in zip(batch_decisions, sample_decisions):
            assert bd.action == sd.action
            assert bd.is_ood == sd.is_ood
            assert bd.ood_score == pytest.approx(sd.ood_score, abs=1e-12)
            assert bd.reason == sd.reason
            assert bd.offending_features == sd.offending_features
            assert bd.metadata == sd.metadata


class TestRegistryBatchAndProfiles:
    def test_invalid_threshold_profile_rejected(self, tmp_path):
        assert "frozen_default" in SUPPORTED_THRESHOLD_PROFILES
        assert "validation_youden_j" in SUPPORTED_THRESHOLD_PROFILES
        with pytest.raises(ValueError, match="Unsupported threshold_profile"):
            ModelRegistry(
                artifacts_dir=tmp_path / "a",
                manifest_root=tmp_path / "m",
                preprocessor_path=tmp_path / "p.joblib",
                warmup=False,
                threshold_profile="test_set_cheating",
            )

    def test_mock_predict_batch_all_matches_predict_all(self, tmp_path, baseline_features):
        registry = _make_mock_registry(tmp_path)
        assert registry.predict_batch_all([]) == []
        assert registry.summary()["threshold_profile"] == "frozen_default"

        rows = [
            baseline_features(bytes_out=100.0),
            baseline_features(bytes_out=5_500.0),
            baseline_features(bytes_out=25_000.0),
        ]
        batch_scores = registry.predict_batch_all(rows)
        assert len(batch_scores) == 3

        for row, b_map in zip(rows, batch_scores):
            s_map = registry.predict_all(row)
            assert set(b_map) == set(s_map) == set(MODEL_KEYS)
            for key in MODEL_KEYS:
                assert b_map[key].raw_score == pytest.approx(s_map[key].raw_score, rel=1e-12)
                assert b_map[key].normalized_score == pytest.approx(
                    s_map[key].normalized_score, rel=1e-12
                )
                assert b_map[key].is_anomaly is s_map[key].is_anomaly
                assert b_map[key].threshold == s_map[key].threshold
                assert b_map[key].score_semantics == s_map[key].score_semantics

    def test_real_artifacts_batch_equivalence_and_youden_j_profile(
        self, real_artifacts_available, baseline_features
    ):
        if not real_artifacts_available:
            pytest.skip("model artifacts are not present in this environment")

        reg_default = ModelRegistry(threshold_profile="frozen_default")
        reg_youden = ModelRegistry(threshold_profile="validation_youden_j")

        assert reg_default.summary()["threshold_profile"] == "frozen_default"
        assert reg_youden.summary()["threshold_profile"] == "validation_youden_j"
        for key, expected_thresh in VALIDATED_YOUDEN_J_THRESHOLDS.items():
            st = reg_youden.status(key)
            assert st is not None
            assert st.threshold == pytest.approx(expected_thresh)
            assert st.threshold_source == "ait_val_youden_j_profile"

        rows = [
            baseline_features(),
            baseline_features(bytes_out=150_000.0, bytes_in=200.0, pkts_out=80.0),
            baseline_features(duration_ms=5000.0, bytes_in=80_000.0, bytes_out=500.0),
        ]
        batch_scores = reg_default.predict_batch_all(rows)
        assert len(batch_scores) == len(rows)

        for row, b_map in zip(rows, batch_scores):
            s_map = reg_default.predict_all(row)
            assert set(b_map) == set(s_map) == set(MODEL_KEYS)
            for key in MODEL_KEYS:
                assert b_map[key].raw_score == pytest.approx(s_map[key].raw_score, rel=1e-9)
                assert b_map[key].normalized_score == pytest.approx(
                    s_map[key].normalized_score, rel=1e-9
                )
                assert b_map[key].is_anomaly is s_map[key].is_anomaly


class TestOODAwareAggregation:
    def test_ood_aware_ensemble_shifts_weights_when_ood_score_high(self):
        agg = MultiModelDecisionAggregator(policy=AggregationPolicy.OOD_AWARE_ENSEMBLE)

        # Below 0.35 -> uses DEFAULT_WEIGHTS: 0.4*1 + 0.3*0 + 0.15*0 + 0.15*0 = 0.40
        low_ood = agg.aggregate(
            rf_prob=1.0, xgb_prob=0.0, if_score=0.0, ae_error_norm=0.0, ood_score=0.20
        )
        assert low_ood.combined_probability == pytest.approx(0.40)
        assert low_ood.is_anomaly is False

        # At/above 0.35 -> uses OOD_SHIFT_WEIGHTS:
        # RF=0.15*0.0 + XGB=0.40*0.9 + IF=0.35*0.8 + AE=0.10*0.0 = 0.36 + 0.28 = 0.64
        high_ood = agg.aggregate(
            rf_prob=0.0, xgb_prob=0.9, if_score=0.8, ae_error_norm=0.0, ood_score=0.35
        )
        assert high_ood.combined_probability == pytest.approx(0.64)
        assert high_ood.is_anomaly is True
        assert high_ood.policy_used == AggregationPolicy.OOD_AWARE_ENSEMBLE


class TestRealtimeInferenceBatchAndStage2:
    def test_infer_batch_vectorized_with_partial_contract_error_and_stage2(
        self, tmp_path, baseline_features
    ):
        registry = _make_mock_registry(tmp_path)
        stage2 = _DummyStage2Classifier(label="Brute_Force", conf=0.8842)
        engine = RealtimeInferenceEngine(
            registry=registry,
            runtime_mode="research",
            stage2_classifier=stage2,
            enable_stage2_multiclass=True,
        )

        f_benign = baseline_features(bytes_out=100.0)
        f_bad = {"duration_ms": 10.0}  # missing mandatory features
        f_attack = baseline_features(bytes_out=25_000.0)

        events = [
            _make_flow_event("evt-1", f_benign, offset_sec=0),
            _make_flow_event("evt-2", f_attack, offset_sec=1),  # will carry bad dict below
            _make_flow_event("evt-3", f_attack, offset_sec=2),
        ]
        decisions = engine.infer_batch(events, [f_benign, f_bad, f_attack])

        assert len(decisions) == 3
        assert decisions[0].inference_mode == "REAL_MODELS"
        assert decisions[0].ensemble_is_anomaly is False
        assert decisions[0].predicted_attack_category is None
        assert decisions[0].stage2_classifier_status == "DISABLED"

        # Bad row fails isolated to itself without breaking valid rows
        assert decisions[1].inference_mode == "UNAVAILABLE"
        assert "feature contract violation" in (decisions[1].ood_reason or "")

        # Attack row gets Stage-2 classification via predict_batch
        assert decisions[2].inference_mode == "REAL_MODELS"
        assert decisions[2].ensemble_is_anomaly is True
        assert decisions[2].predicted_attack_category == "Brute_Force"
        assert decisions[2].attack_category_confidence == pytest.approx(0.8842)
        assert decisions[2].stage2_classifier_status == "ACTIVE"
        assert stage2.batch_calls == 1

    def test_real_stage2_multiclass_lazy_load_in_infer_event_and_batch(
        self, tmp_path, baseline_features
    ):
        manifest_path = Path("reports/experiments/ml/multiclass_stage2_manifest.json")
        if not manifest_path.is_file():
            pytest.skip("Stage-2 multiclass manifest not present")

        registry = _make_mock_registry(tmp_path)
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_data.get("preprocessor_artifact_sha256"):
            registry._preprocessor_metadata["artifact_sha256"] = manifest_data[
                "preprocessor_artifact_sha256"
            ]
        engine = RealtimeInferenceEngine(
            registry=registry,
            runtime_mode="research",
            enable_stage2_multiclass=True,
        )
        f_attack = baseline_features(bytes_out=25_000.0)
        ev1 = _make_flow_event("evt-s2-1", f_attack, offset_sec=0)
        ev2 = _make_flow_event("evt-s2-2", f_attack, offset_sec=1)

        dec_one = engine.infer_event(ev1, f_attack)
        assert dec_one.ensemble_is_anomaly is True
        assert dec_one.stage2_classifier_status == "ACTIVE"
        assert dec_one.predicted_attack_category is not None
        assert 0.0 <= float(dec_one.attack_category_confidence or 0.0) <= 1.0

        dec_batch = engine.infer_batch([ev1, ev2], [f_attack, f_attack])
        assert len(dec_batch) == 2
        assert all(d.stage2_classifier_status == "ACTIVE" for d in dec_batch)
        assert dec_batch[0].predicted_attack_category == dec_one.predicted_attack_category


class TestOrchestratorBatchAndStorage:
    def test_alert_manager_behavioral_vector_boost_and_batch_persist(
        self, tmp_path, baseline_features
    ):
        db_path = tmp_path / "alerts.db"
        mgr = LiveAlertManager(db_path=db_path, risk_threshold_alert=45.0)
        ev = _make_flow_event("evt-beh", baseline_features(bytes_out=100.0), dest_port=22)

        bv_proxy = SimpleNamespace(
            named_features={
                "dns_intensity": 1.2,
                "port_entropy": 3.0,
                "auth_failure_ratio": 0.6,
            }
        )
        risk, alert = mgr.process_event_risk(
            ev, inference_decision=None, behavioral_vector=bv_proxy, persist=False
        )
        assert alert is not None
        assert risk.component_breakdown["behavioral_deviation"] > 15.0
        assert risk.component_breakdown["auth_failures"] == 10.0

        # persist=False should not have written to sqlite yet
        with sqlite3.connect(db_path) as conn:
            count_before = conn.execute("SELECT COUNT(*) FROM live_alerts").fetchone()[0]
        assert count_before == 0

        mgr.persist_alerts_batch([alert])
        with sqlite3.connect(db_path) as conn:
            count_after = conn.execute("SELECT COUNT(*) FROM live_alerts").fetchone()[0]
        assert count_after == 1

    def test_orchestrator_process_batch_persists_all_tables(self, tmp_path, baseline_features):
        db_path = tmp_path / "orch.db"
        keystore_dir = tmp_path / "keys"
        registry = _make_mock_registry(tmp_path)
        stage2 = _DummyStage2Classifier(label="Exfiltration", conf=0.93)

        f_benign = baseline_features(bytes_out=100.0)
        f_attack = baseline_features(bytes_out=80_000.0)
        gate_rows = np.array(
            [
                [float(f_benign[c]) for c in ML_FEATURE_COLUMNS],
                [float(f_attack[c]) for c in ML_FEATURE_COLUMNS],
            ],
            dtype=np.float64,
        )
        gate = OODRejectionGate(std_margin=10.0, statistical_threshold=10.0).fit(
            gate_rows,
            list(ML_FEATURE_COLUMNS),
            provenance={"fit_rows": 2, "preprocessor_artifact_sha256": "a" * 64},
        )
        engine = RealtimeInferenceEngine(
            registry=registry,
            ood_gate=gate,
            runtime_mode="research",
            stage2_classifier=stage2,
        )
        orch = LiveSystemOrchestrator(
            db_path=db_path,
            keystore_dir=keystore_dir,
            inference_engine=engine,
            runtime_mode="research",
            encrypt_at_rest=True,
        )

        dns_event = CanonicalSecurityEvent(
            event_id="evt-dns-1",
            event_timestamp=datetime(2026, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
            event_kind=EventKind.DNS,
            source_id="unit-test-dns",
            entity_id="host-10.0.0.5",
            raw_provenance=RawProvenance(source_file="unit-test", adapter_name="dns"),
        )
        events = [
            _make_flow_event("evt-b1", f_benign, offset_sec=0),
            _make_flow_event("evt-a1", f_attack, dest_port=445, offset_sec=1),
            dns_event,
        ]

        results = orch.process_batch(events)
        assert len(results) == 3
        assert results[1].predicted_attack_category == "Exfiltration"
        assert results[1].attack_type == "Exfiltration"
        assert results[1].attack_category_confidence == pytest.approx(0.93)
        assert results[2].feature_status == "ROUTE_ONLY"

        # Behavioral vectors batch-stored & decryptable
        assert all(r.behavioral_vector_id is not None for r in results)
        loaded_vec = orch.vault.load_behavioral_vector(results[1].behavioral_vector_id)
        assert loaded_vec is not None
        assert len(loaded_vec) == 16

        # Unified events batch-stored
        rows = orch._db_manager.query_unified_security_events(limit=10)
        assert {row["event_id"] for row in rows} == {"evt-b1", "evt-a1", "evt-dns-1"}

        # Alerts batch-stored when raised
        if results[1].alert_generated is not None:
            with sqlite3.connect(db_path) as conn:
                alert_count = conn.execute("SELECT COUNT(*) FROM live_alerts").fetchone()[0]
            assert alert_count >= 1

    def test_db_and_vault_batch_helpers(self, tmp_path):
        db = DatabaseManager(tmp_path / "batch.db")
        assert db.insert_unified_security_events_batch([]) == 0
        inserted = db.insert_unified_security_events_batch(
            [
                {
                    "event_id": f"e-{i}",
                    "event_timestamp": f"2026-01-01T00:00:0{i}+00:00",
                    "event_kind": "flow",
                    "source_id": "test-src",
                    "entity_id": "host-1",
                    "is_ml_complete": True,
                }
                for i in range(3)
            ]
        )
        assert inserted == 3
        assert len(db.query_unified_security_events(limit=10)) == 3

        km = KeyManager(keystore_dir=tmp_path / "km")
        vault = EncryptedStorageVault(km, tmp_path / "vault.db")
        assert vault.store_behavioral_vectors_batch([]) == []
        items = [
            {
                "entity_id": f"host-{i}",
                "window_start": "2026-01-01T00:00:00+00:00",
                "window_end": "2026-01-01T00:01:00+00:00",
                "vector": [0.1 * (i + 1)] * 16,
            }
            for i in range(4)
        ]
        enc_ids = vault.store_behavioral_vectors_batch(items, encrypt=True)
        plain_ids = vault.store_behavioral_vectors_batch(items[:2], encrypt=False)
        assert len(enc_ids) == 4
        assert len(plain_ids) == 2
        assert vault.load_behavioral_vector(enc_ids[2]) == pytest.approx([0.3] * 16)
        assert vault.load_behavioral_vector(plain_ids[1]) == pytest.approx([0.2] * 16)
        key_id, _ = km.get_active_key(domain="behavioral")
        assert km._metadata[key_id].records_encrypted_count == 4


class TestLocalBenignCalibrator:
    def test_fit_save_load_and_tamper_detection(self, tmp_path, baseline_features):
        registry = _make_mock_registry(tmp_path)
        rows = [
            baseline_features(bytes_out=float(200 + i * 50), bytes_in=float(500 + i * 20))
            for i in range(100)
        ]
        benign_df = pd.DataFrame(rows, columns=list(ML_FEATURE_COLUMNS))

        calibrator = LocalBenignCalibrator(target_fpr=0.05)
        calibrator.fit(benign_df, registry, source_label="campus_benign_sample")

        assert calibrator.is_fitted is True
        assert calibrator.fit_rows == 100
        assert calibrator.ood_gate is not None and calibrator.ood_gate.is_fitted
        assert set(calibrator.calibrated_thresholds) == set(MODEL_KEYS)

        # Verify exact quantile computation
        X_t = registry.transform_features_batch(rows)
        for key in MODEL_KEYS:
            raw_scores = np.array(
                [t[0] for t in registry._backends[key].score_batch_detailed(X_t)],
                dtype=float,
            )
            expected_q = round(float(np.quantile(raw_scores, 0.95)), 6)
            assert calibrator.calibrated_thresholds[key] == pytest.approx(expected_q)

        profile_path = tmp_path / "profiles" / "site_local.json"
        saved_path = calibrator.save_profile(profile_path)
        assert saved_path.is_file()
        file_sha = hashlib.sha256(saved_path.read_bytes()).hexdigest()

        loaded = LocalBenignCalibrator.load_profile(
            saved_path,
            expected_sha256=file_sha,
            expected_preprocessor_sha256="a" * 64,
        )
        assert loaded.calibrated_thresholds == calibrator.calibrated_thresholds
        assert loaded.fit_rows == 100
        assert loaded.ood_gate is not None and loaded.ood_gate.is_fitted
        assert loaded.to_dict()["source_label"] == "campus_benign_sample"

        # Tampering with calibrated threshold triggers payload_sha256 failure
        tampered = json.loads(saved_path.read_text(encoding="utf-8"))
        tampered["calibrated_thresholds"]["random_forest"] = 0.999999
        tampered_path = tmp_path / "profiles" / "tampered.json"
        tampered_path.write_text(json.dumps(tampered, indent=2), encoding="utf-8")
        with pytest.raises(ValueError, match="payload_sha256 integrity mismatch"):
            LocalBenignCalibrator.load_profile(tampered_path)

    def test_real_artifacts_local_calibration_non_destructive(
        self, tmp_path, real_artifacts_available, baseline_features
    ):
        if not real_artifacts_available:
            pytest.skip("model artifacts are not present in this environment")

        registry = ModelRegistry()
        rf_path = Path("artifacts/models/random_forest/random_forest_baseline.joblib")
        rf_sha_before = hashlib.sha256(rf_path.read_bytes()).hexdigest()

        rows = [
            baseline_features(
                duration_ms=float(20 + i),
                bytes_in=float(1000 + i * 15),
                bytes_out=float(1800 + i * 25),
            )
            for i in range(40)
        ]
        df = pd.DataFrame(rows, columns=list(ML_FEATURE_COLUMNS))
        cal = LocalBenignCalibrator(target_fpr=0.01).fit(df, registry, source_label="real_smoke")
        assert set(cal.calibrated_thresholds) == set(MODEL_KEYS)
        out = cal.save_profile(tmp_path / "real_local_profile.json")
        reloaded = LocalBenignCalibrator.load_profile(
            out, expected_preprocessor_sha256=registry.preprocessor_sha256
        )
        assert reloaded.calibrated_thresholds == cal.calibrated_thresholds

        rf_sha_after = hashlib.sha256(rf_path.read_bytes()).hexdigest()
        assert rf_sha_before == rf_sha_after
