"""Unit tests for ApiService business logic, health check behavior, and lifecycle management."""

from __future__ import annotations

import json
import math
from pathlib import Path
from unittest.mock import MagicMock, patch

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.errors import ModelNotReadyError
from network_anomaly.api.schemas import HealthResponse
from network_anomaly.api.service import ApiService
from network_anomaly.data.v2_schema import CATEGORICAL_CODED_COLUMNS, ML_FEATURE_COLUMNS
from network_anomaly.inference.predict import _sha256_file
from network_anomaly.preprocessing import (
    FEATURE_CONTRACT_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)

TEST_V2_DATASET_SHA256 = "cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf"


@pytest.fixture
def api_service(tmp_path: Path) -> ApiService:
    """Fixture providing ApiService backed by an isolated SQLite database."""
    db_path = tmp_path / "test_service.db"
    db = DatabaseManager(db_path)
    return ApiService(db)


def test_health_check_fails_safe_when_artifacts_absent(api_service: ApiService):
    """Verify health check never claims model/data ready when artifacts are missing."""
    with patch("network_anomaly.api.service.ARTIFACTS", Path("/non_existent_artifacts_dir")):
        health = api_service.check_health()
        assert health.process_alive is True
        assert health.db_ready is True
        # CRITICAL ACCEPTANCE CRITERIA:
        assert health.model_ready is False
        assert health.preprocessor_ready is False
        assert health.status == "degraded"


def test_health_check_rejects_unverified_artifacts(api_service: ApiService, tmp_path: Path):
    """Existing files without valid manifests do not make the service healthy."""
    fake_artifacts = tmp_path / "fake_artifacts"
    (fake_artifacts / "models" / "random_forest").mkdir(parents=True)
    (fake_artifacts / "preprocessing").mkdir(parents=True)

    fake_model = fake_artifacts / "models" / "random_forest" / "random_forest_baseline.joblib"
    fake_model.write_text("model placeholder")

    fake_prep = fake_artifacts / "preprocessing" / "v2_flow_preprocessor.joblib"
    fake_prep.write_text("preprocessor placeholder")

    with patch("network_anomaly.api.service.ARTIFACTS", fake_artifacts):
        health = api_service.check_health()
        assert health.process_alive is True
        assert health.model_ready is False
        assert health.preprocessor_ready is False
        assert health.status == "degraded"


def test_health_check_accepts_verified_pipeline(api_service: ApiService):
    """A successfully loaded verified model and preprocessor mark health ready."""
    with patch.object(api_service, "_load_inference_pipeline", return_value=object()):
        health = api_service.check_health()
    assert health.model_ready is True
    assert health.preprocessor_ready is True
    assert health.status == "healthy"


def test_health_check_accepts_real_verified_fixture(api_service: ApiService, tmp_path: Path):
    """Health loads synthetic artifacts through the actual verification path."""
    artifact_root = tmp_path / "artifacts"
    prep_path = artifact_root / "preprocessing" / "v2_flow_preprocessor.joblib"
    model_path = artifact_root / "models" / "random_forest" / "random_forest_baseline.joblib"
    prep_manifest = (
        tmp_path / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
    )
    model_manifest = tmp_path / "reports" / "models" / "random_forest_manifest.json"
    prep_path.parent.mkdir(parents=True)
    model_path.parent.mkdir(parents=True)
    prep_manifest.parent.mkdir(parents=True)
    model_manifest.parent.mkdir(parents=True)

    data = {
        col: (
            np.arange(10, dtype=float) + 1
            if col not in CATEGORICAL_CODED_COLUMNS
            else np.arange(10) % 3
        )
        for col in ML_FEATURE_COLUMNS
    }
    features = pd.DataFrame(data)
    preprocessor = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256=TEST_V2_DATASET_SHA256,
        split_manifest_sha256="b" * 64,
    )
    preprocessor.fit(features)
    prep_sha = preprocessor.save(prep_path, prep_manifest)
    model = RandomForestClassifier(n_estimators=3, random_state=42)
    model.fit(preprocessor.transform(features), np.arange(10) % 2)
    joblib.dump(model, model_path)
    model_manifest.write_text(
        json.dumps(
            {
                "model_type": "RandomForestClassifier",
                "model_artifact_sha256": _sha256_file(model_path),
                "preprocessor_artifact_sha256": prep_sha,
                "feature_contract_version": FEATURE_CONTRACT_VERSION,
            }
        ),
        encoding="utf-8",
    )
    with (
        patch("network_anomaly.api.service.ARTIFACTS", artifact_root),
        patch("network_anomaly.api.service.PROJECT_ROOT", tmp_path),
    ):
        health = api_service.check_health()
    assert health.status == "healthy"
    assert health.model_ready and health.preprocessor_ready


def test_ingest_events_atomicity_and_idempotency(api_service: ApiService):
    """Verify event ingestion persists records and deduplicates with idempotency key."""
    events = [
        {
            "timestamp": "2026-10-20T10:00:00Z",
            "source_ip": "192.168.1.50",
            "dest_ip": "10.0.0.5",
            "features": {"IN_BYTES": 4096, "OUT_BYTES": 8192},
        },
        {
            "timestamp": "2026-10-20T10:00:01Z",
            "source_ip": "192.168.1.51",
            "dest_ip": "10.0.0.5",
            "features": {"IN_BYTES": 512, "OUT_BYTES": 256},
        },
    ]

    # First ingest
    count, ids, sess = api_service.ingest_events(
        events, session_id="sess_batch_1", idempotency_key="idempotent_ingest_1"
    )
    assert count == 2
    assert len(ids) == 2
    assert sess == "sess_batch_1"

    # Second ingest with same idempotency key must return cached result
    # without inserting duplicate rows
    count2, ids2, sess2 = api_service.ingest_events(
        events, session_id="sess_batch_1", idempotency_key="idempotent_ingest_1"
    )
    assert count2 == 2
    assert ids2 == ids

    # Check total events in database is strictly 2
    with api_service.db.transaction() as conn:
        from network_anomaly.api.repositories import EventRepository

        assert EventRepository.count(conn) == 2


def test_health_check_rejects_unverified_isolation_forest(api_service: ApiService, tmp_path: Path):
    """An unverified Isolation Forest file does not imply model readiness."""
    fake_artifacts = tmp_path / "fake_artifacts_if"
    (fake_artifacts / "models" / "isolation_forest").mkdir(parents=True)
    (fake_artifacts / "preprocessing").mkdir(parents=True)

    fake_model = fake_artifacts / "models" / "isolation_forest" / "isolation_forest.joblib"
    fake_model.write_text("iforest placeholder")

    fake_prep = fake_artifacts / "preprocessing" / "v2_flow_preprocessor.joblib"
    fake_prep.write_text("preprocessor placeholder")

    with patch("network_anomaly.api.service.ARTIFACTS", fake_artifacts):
        health = api_service.check_health()
        assert health.process_alive is True
        assert health.model_ready is False
        assert health.preprocessor_ready is False
        assert health.status == "degraded"


def test_isolation_forest_artifact_naming_parity(api_service: ApiService):
    """Verify isolation forest artifact path resolves strictly to isolation_forest.joblib."""
    model_path, _, _, _ = api_service._resolve_artifact_paths("isolation_forest")
    assert model_path.name == "isolation_forest.joblib"
    assert "isolation_forest_model.joblib" not in str(model_path)


def test_analyze_flows_fails_closed_when_fallback_disabled(api_service: ApiService):
    """Verify analyze_flows fails closed with ModelNotReadyError (HTTP 503) by default."""
    flows = [
        {"features": {"IN_BYTES": 500, "OUT_BYTES": 500}},
    ]
    with pytest.raises(ModelNotReadyError) as exc_info:
        api_service.analyze_flows(flows, allow_heuristic_fallback=False)
    assert exc_info.value.status_code == 503
    assert "heuristic fallback is disabled" in str(exc_info.value.detail).lower()


def test_analyze_flows_with_heuristic_and_incident_creation(api_service: ApiService):
    """Verify analysis creates incident alert and transparent metadata when fallback allowed."""
    flows = [
        # Normal flow
        {"features": {"bytes_in": 500, "bytes_out": 500, "pkts_in": 5, "pkts_out": 5}},
        # Abnormal high-volume flooding flow
        {"features": {"bytes_in": 2_500_000, "bytes_out": 100, "pkts_in": 2500, "pkts_out": 0}},
    ]

    res = api_service.analyze_flows(
        flows, threshold=0.5, create_incidents=True, allow_heuristic_fallback=True
    )
    assert res.model_ready is False
    assert res.inference_mode == "heuristic_fallback"
    assert res.model_sha256 is None
    assert res.count == 2
    assert res.anomalies_detected == 1
    assert res.results[0].is_anomaly is False
    assert res.results[0].inference_mode == "heuristic_fallback"
    assert res.results[1].is_anomaly is True
    assert res.results[1].incident_created is True
    assert res.results[1].incident_id is not None
    assert res.results[1].inference_mode == "heuristic_fallback"

    # Check that incident is stored in repository
    incidents = api_service.list_incidents(limit=10)
    assert incidents.total == 1
    assert incidents.items[0].incident_id == res.results[1].incident_id


def test_analyze_flows_with_verified_pipeline_provenance(api_service: ApiService, monkeypatch):
    """Verify verified inference pipeline outputs full provenance traceability metadata."""
    mock_pipeline = MagicMock()
    mock_pipeline.model_metadata = {
        "model_artifact_sha256": "rf_sha256_mock_provenance_verified",
        "model_type": "RandomForestClassifier",
    }
    mock_pipeline.preprocessor_metadata = {
        "artifact_sha256": "prep_sha256_mock_provenance_verified",
    }
    mock_pipeline.predict.return_value = pd.DataFrame(
        {
            "row_id": [0, 1],
            "prediction": [0, 1],
            "probability_Attack": [0.12, 0.88],
            "run_id": ["run_trace_verified_service_002", "run_trace_verified_service_002"],
        }
    )

    monkeypatch.setattr(
        api_service,
        "check_health",
        lambda: HealthResponse(
            status="healthy",
            process_alive=True,
            model_ready=True,
            preprocessor_ready=True,
            db_ready=True,
            version="0.1.0",
            git_commit="head_sha_verified",
            timestamp="2026-11-09T00:00:00Z",
            details={},
        ),
    )
    monkeypatch.setattr(
        api_service,
        "_load_inference_pipeline",
        lambda model_name: mock_pipeline,
    )

    flows = [
        {"features": {"IN_BYTES": 200, "OUT_BYTES": 200}},
        {"features": {"IN_BYTES": 200000, "OUT_BYTES": 1000}},
    ]

    res = api_service.analyze_flows(
        flows,
        model_name="random_forest",
        threshold=0.95,
        create_incidents=True,
        allow_heuristic_fallback=False,
    )
    assert res.model_ready is True
    assert res.inference_mode == "verified_model"
    assert res.model_sha256 == "rf_sha256_mock_provenance_verified"
    assert res.preprocessor_sha256 == "prep_sha256_mock_provenance_verified"
    assert res.run_id == "run_trace_verified_service_002"
    assert res.count == 2
    assert res.anomalies_detected == 1
    assert res.results[0].inference_mode == "verified_model"
    assert res.results[0].model_sha256 == "rf_sha256_mock_provenance_verified"
    assert res.anomaly_scores == [0.12, 0.88]
    assert res.probabilities == [
        {"Benign": 0.88, "Attack": 0.12},
        {"Benign": 0.12, "Attack": 0.88},
    ]
    assert res.results[1].probabilities == {"Benign": 0.12, "Attack": 0.88}
    assert res.results[1].is_anomaly is True
    assert res.results[1].incident_created is True
    from network_anomaly.api.repositories import EvidenceRepository

    with api_service.db.transaction() as conn:
        evidence = EvidenceRepository.list_by_incident(conn, res.results[1].incident_id)
    assert len(evidence) == 1
    details = evidence[0]["details"]
    assert details["threshold"] is None
    assert details["threshold_source"] == "verified_model"


def test_verified_inference_keeps_calibrated_prediction(api_service: ApiService, monkeypatch):
    """An API request threshold cannot reclassify a verified model's output."""
    mock_pipeline = MagicMock()
    mock_pipeline.model_metadata = {"model_artifact_sha256": "a" * 64}
    mock_pipeline.preprocessor_metadata = {"artifact_sha256": "b" * 64}
    mock_pipeline.predict.return_value = pd.DataFrame(
        {"prediction": [0, 1], "anomaly_score": [0.8, 0.2]}
    )
    monkeypatch.setattr(api_service, "_load_inference_pipeline", lambda _: mock_pipeline)
    results, *_ = api_service._analyze_with_verified_pipeline(
        [{"features": {}}, {"features": {}}], "isolation_forest", threshold=0.5
    )
    assert [item.prediction for item in results] == [0, 1]
    assert [item.is_anomaly for item in results] == [False, True]


def test_key_rotation_lifecycle_cooldown_and_idempotency(api_service: ApiService):
    """Verify key rotation enforces cooldown and records audit log."""
    # Rotation 1: Successful
    rot1 = api_service.rotate_key(
        triggered_by="operator_alice",
        dry_run=True,
        reason="Scheduled test rotation",
        idempotency_key="rot_key_alpha",
    )
    assert rot1.status == "SUCCESS"
    assert rot1.dry_run is True
    assert rot1.new_key_id is not None

    # Immediate Rotation 2 (different key): rejected by cooldown
    with pytest.raises(ValueError, match="minimum cooldown interval"):
        api_service.rotate_key(triggered_by="operator_bob", dry_run=True)

    # Calling again with same idempotency key: succeeds by returning cached result
    rot_cached = api_service.rotate_key(
        triggered_by="operator_alice",
        dry_run=True,
        reason="Scheduled test rotation",
        idempotency_key="rot_key_alpha",
    )
    assert rot_cached.rotation_id == rot1.rotation_id
    assert rot_cached.new_key_id == rot1.new_key_id

    # Verify audit log recorded both SUCCESS and BLOCKED_COOLDOWN
    audits = api_service.list_rotation_audits(limit=10)
    assert audits.total >= 2


def test_timeline_chronological_ordering(api_service: ApiService):
    """Verify timeline aggregates and orders events chronologically descending."""
    # 1. Ingest event
    api_service.ingest_events(
        [{"timestamp": "2026-10-20T08:00:00Z", "features": {"IN_BYTES": 100}}],
        session_id="sess_time_1",
    )
    # 2. Add incident
    with api_service.db.transaction() as conn:
        from network_anomaly.api.repositories import IncidentRepository

        IncidentRepository.create(
            conn,
            {
                "incident_id": "inc_timeline_1",
                "title": "Alert at 09:00",
                "severity": "HIGH",
                "anomaly_score": 0.9,
                "created_at": "2026-10-20T09:00:00Z",
            },
        )

    timeline = api_service.get_timeline(limit=10)
    assert timeline.total >= 2
    # Verify descending ordering
    timestamps = [item.timestamp for item in timeline.items]
    assert timestamps == sorted(timestamps, reverse=True)


def _setup_synthetic_artifact_tree(
    root: Path,
    *,
    include_rf: bool = True,
    include_if: bool = False,
    include_xgb: bool = False,
    include_ae: bool = False,
) -> dict[str, Path]:
    """Create isolated preprocessor + model artifact tree for ApiService F4/F6 tests."""
    from network_anomaly.models.isolation_forest import IsolationForestModel

    art_root = root / "artifacts"
    prep_path = art_root / "preprocessing" / "v2_flow_preprocessor.joblib"
    prep_manifest = (
        root / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
    )
    rf_path = art_root / "models" / "random_forest" / "random_forest_baseline.joblib"
    rf_manifest = root / "reports" / "models" / "random_forest_manifest.json"
    if_path = art_root / "models" / "isolation_forest" / "isolation_forest.joblib"
    if_manifest = root / "reports" / "models" / "isolation_forest_manifest.json"
    xgb_path = art_root / "models" / "xgboost" / "xgboost_baseline.joblib"
    xgb_manifest = root / "reports" / "models" / "xgboost_manifest.json"
    ae_path = art_root / "models" / "autoencoder" / "autoencoder_model.joblib"
    ae_manifest = art_root / "models" / "autoencoder" / "autoencoder_manifest.json"

    prep_path.parent.mkdir(parents=True, exist_ok=True)
    prep_manifest.parent.mkdir(parents=True, exist_ok=True)
    rf_manifest.parent.mkdir(parents=True, exist_ok=True)

    data = {
        col: (
            np.arange(12, dtype=float) + 1
            if col not in CATEGORICAL_CODED_COLUMNS
            else np.arange(12) % 3
        )
        for col in ML_FEATURE_COLUMNS
    }
    features = pd.DataFrame(data)
    preprocessor = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256=TEST_V2_DATASET_SHA256,
        split_manifest_sha256="b" * 64,
    )
    preprocessor.fit(features)
    prep_sha = preprocessor.save(prep_path, prep_manifest)
    X_trans = preprocessor.transform(features)

    if include_rf:
        rf_path.parent.mkdir(parents=True, exist_ok=True)
        rf = RandomForestClassifier(n_estimators=3, random_state=42)
        rf.fit(X_trans, np.arange(12) % 2)
        joblib.dump(rf, rf_path)
        rf_manifest.write_text(
            json.dumps(
                {
                    "run_id": "test-rf-service-run",
                    "model_type": "RandomForestClassifier",
                    "model_artifact_sha256": _sha256_file(rf_path),
                    "preprocessor_artifact_sha256": prep_sha,
                    "feature_contract_version": FEATURE_CONTRACT_VERSION,
                }
            ),
            encoding="utf-8",
        )

    if include_if:
        if_path.parent.mkdir(parents=True, exist_ok=True)
        iso = IsolationForestModel(config={"n_estimators": 5, "random_state": 42}, threshold=0.0)
        iso.fit(X_trans)
        iso.save(if_path, if_manifest, preprocessor_artifact_sha256=prep_sha)

    if include_xgb:
        from xgboost import XGBClassifier

        xgb_path.parent.mkdir(parents=True, exist_ok=True)
        xgb = XGBClassifier(n_estimators=5, max_depth=3, random_state=42, eval_metric="logloss")
        xgb.fit(X_trans, np.arange(12) % 2)
        joblib.dump(
            {"estimator": xgb, "model_type": "XGBoost", "classes": [0, 1]},
            xgb_path,
        )
        xgb_manifest.write_text(
            json.dumps(
                {
                    "run_id": "test-xgb-service-run",
                    "model_type": "XGBoost",
                    "model_artifact_sha256": _sha256_file(xgb_path),
                    "preprocessor_artifact_sha256": prep_sha,
                    "feature_contract_version": FEATURE_CONTRACT_VERSION,
                    "class_mapping": {"0": "Benign", "1": "Attack"},
                }
            ),
            encoding="utf-8",
        )

    if include_ae:
        from network_anomaly.models.autoencoder import build_model as build_ae_model
        from network_anomaly.models.autoencoder import fit_model as fit_ae_model

        ae_path.parent.mkdir(parents=True, exist_ok=True)
        ae_hparams = {
            "hidden_layer_sizes": [8, 4, 8],
            "max_iter": 10,
            "random_state": 42,
        }
        ae = build_ae_model({"hidden_layer_sizes": (8, 4, 8), "max_iter": 10, "random_state": 42})
        fit_ae_model(ae, X_trans)
        joblib.dump(ae, ae_path)
        cfg_path = ae_path.parent / "model_config.json"
        cfg_path.write_text(json.dumps(ae_hparams), encoding="utf-8")
        th_payload = {
            "threshold": 0.5,
            "threshold_frozen": True,
            "calibration_split": "validation_benign",
        }
        th_path = ae_path.parent / "threshold.json"
        th_path.write_text(json.dumps(th_payload), encoding="utf-8")
        ae_manifest.write_text(
            json.dumps(
                {
                    "artifact_type": "autoencoder-anomaly-detector",
                    "schema_version": "1.0",
                    "run_id": "test-ae-service-run",
                    "model_file": ae_path.name,
                    "model_sha256": _sha256_file(ae_path),
                    "config_file": cfg_path.name,
                    "config_sha256": _sha256_file(cfg_path),
                    "threshold_file": th_path.name,
                    "threshold_sha256": _sha256_file(th_path),
                    "preprocessor_sha256": prep_sha,
                    "feature_contract_version": FEATURE_CONTRACT_VERSION,
                    "hyperparameters": ae_hparams,
                    "model_architecture": {
                        "class": "MLPRegressor",
                        "hidden_layer_sizes": [8, 4, 8],
                        "input_dimension": len(ML_FEATURE_COLUMNS),
                        "output_dimension": len(ML_FEATURE_COLUMNS),
                    },
                    "threshold": 0.5,
                    "threshold_calibration": th_payload,
                }
            ),
            encoding="utf-8",
        )

    return {
        "artifacts": art_root,
        "rf_path": rf_path,
        "rf_manifest": rf_manifest,
        "if_path": if_path,
        "if_manifest": if_manifest,
        "xgb_path": xgb_path,
        "xgb_manifest": xgb_manifest,
        "ae_path": ae_path,
        "ae_manifest": ae_manifest,
    }


def test_health_check_does_not_mask_missing_default_rf_with_if_ready(
    api_service: ApiService, tmp_path: Path
):
    """F4 regression: ready auxiliary IF model must not mark default RF health as healthy."""
    paths = _setup_synthetic_artifact_tree(tmp_path, include_rf=False, include_if=True)
    sample_flow = [{"features": {col: 1.0 for col in ML_FEATURE_COLUMNS}}]

    with (
        patch("network_anomaly.api.service.ARTIFACTS", paths["artifacts"]),
        patch("network_anomaly.api.service.PROJECT_ROOT", tmp_path),
    ):
        health_default = api_service.check_health()
        assert health_default.status == "degraded"
        assert health_default.model_ready is False
        assert health_default.preprocessor_ready is True
        assert health_default.details["default_model"] == "random_forest"
        assert health_default.details["default_analysis_ready"] is False
        assert health_default.details["models_ready"] == {
            "random_forest": False,
            "xgboost": False,
            "isolation_forest": True,
            "autoencoder": False,
        }

        with pytest.raises(ModelNotReadyError):
            api_service.analyze_flows(sample_flow)

        health_if = api_service.check_health(model_name="isolation_forest")
        assert health_if.status == "healthy"
        assert health_if.model_ready is True
        assert health_if.details["target_model"] == "isolation_forest"
        assert health_if.details["default_analysis_ready"] is False

        res_if = api_service.analyze_flows(sample_flow, model_name="isolation_forest")
        assert res_if.model_ready is True
        assert res_if.inference_mode == "verified_model"
        assert res_if.results[0].prediction in (0, 1)


def test_pipeline_caching_avoids_redundant_loads_and_invalidates_on_change(
    api_service: ApiService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F6 regression: reuse digest-verified cached pipeline and invalidate when artifacts change."""
    from network_anomaly.inference.predict import InferencePipeline

    paths = _setup_synthetic_artifact_tree(tmp_path, include_rf=True, include_if=False)
    sample_flow = [{"features": {col: 1.0 for col in ML_FEATURE_COLUMNS}}]

    original_from_artifacts = InferencePipeline.from_artifacts
    load_calls: list[Path] = []

    def counting_from_artifacts(*args, **kwargs):
        load_calls.append(Path(kwargs["model_artifact_path"]))
        return original_from_artifacts(*args, **kwargs)

    monkeypatch.setattr(InferencePipeline, "from_artifacts", counting_from_artifacts)

    with (
        patch("network_anomaly.api.service.ARTIFACTS", paths["artifacts"]),
        patch("network_anomaly.api.service.PROJECT_ROOT", tmp_path),
    ):
        health = api_service.check_health()
        assert health.status == "healthy"
        assert len(load_calls) == 1

        for _ in range(3):
            res = api_service.analyze_flows(sample_flow, model_name="random_forest")
            assert res.model_ready is True
            assert res.inference_mode == "verified_model"
        assert len(load_calls) == 1

        api_service.invalidate_pipeline_cache("random_forest")
        api_service.analyze_flows(sample_flow, model_name="random_forest")
        assert len(load_calls) == 2

        # Updating manifest run_id changes manifest SHA-256 and triggers one clean reload.
        manifest_data = json.loads(paths["rf_manifest"].read_text(encoding="utf-8"))
        manifest_data["run_id"] = "test-rf-service-run-v2"
        paths["rf_manifest"].write_text(json.dumps(manifest_data), encoding="utf-8")
        api_service.analyze_flows(sample_flow, model_name="random_forest")
        assert len(load_calls) == 3
        cached_pipe = api_service._load_inference_pipeline("random_forest")
        assert cached_pipe.model_metadata["run_id"] == "test-rf-service-run-v2"
        assert len(load_calls) == 3

        # Tampering with model bytes invalidates cache and fails closed (no stale pipeline).
        paths["rf_path"].write_bytes(paths["rf_path"].read_bytes() + b"\x00tamper")
        with pytest.raises(ModelNotReadyError):
            api_service.analyze_flows(sample_flow, model_name="random_forest")


def test_four_model_families_health_and_verified_inference(api_service: ApiService, tmp_path: Path):
    """Verify check_health and analyze_flows across RF, XGBoost, Isolation Forest, and Autoencoder."""
    paths = _setup_synthetic_artifact_tree(
        tmp_path, include_rf=True, include_if=True, include_xgb=True, include_ae=True
    )
    sample_flow = [{"features": {col: 1.0 for col in ML_FEATURE_COLUMNS}}]

    with (
        patch("network_anomaly.api.service.ARTIFACTS", paths["artifacts"]),
        patch("network_anomaly.api.service.PROJECT_ROOT", tmp_path),
    ):
        health = api_service.check_health()
        assert health.status == "healthy"
        assert health.details["models_ready"] == {
            "random_forest": True,
            "xgboost": True,
            "isolation_forest": True,
            "autoencoder": True,
        }

        for model_key, expect_proba in (
            ("random_forest", True),
            ("xgboost", True),
            ("isolation_forest", False),
            ("autoencoder", False),
        ):
            res = api_service.analyze_flows(sample_flow, model_name=model_key)
            assert res.model_ready is True
            assert res.inference_mode == "verified_model"
            item = res.results[0]
            assert item.model_used == model_key
            assert item.inference_mode == "verified_model"
            assert item.prediction in (0, 1)
            assert math.isfinite(item.anomaly_score)
            assert item.raw_anomaly_score == item.anomaly_score
            if expect_proba:
                assert item.score_type == "attack_probability"
                assert item.attack_probability is not None
                assert 0.0 <= item.attack_probability <= 1.0
                assert item.probabilities is not None
                assert set(item.probabilities) == {"Benign", "Attack"}
                assert item.normalized_anomaly_score == item.attack_probability
            else:
                assert item.attack_probability is None
                assert item.probabilities is None
                assert item.normalized_anomaly_score is None
                assert item.score_direction == "higher_is_more_anomalous"
                assert item.decision_threshold is not None
                if model_key == "autoencoder":
                    assert item.score_type == "reconstruction_error_mse"
                else:
                    assert item.score_type in {
                        "isolation_forest_anomaly_score",
                        "isolation_forest_decision_score",
                    }


def test_f1_strict_model_allowlist_aliases_and_rejects_unsupported_names(
    tmp_path: Path, api_service: ApiService
):
    """F1: Canonical aliases normalize deterministically; unsupported names fail closed without RF fallback."""
    paths = _setup_synthetic_artifact_tree(tmp_path)

    for raw_alias, expected_canonical in (
        (None, "random_forest"),
        ("rf", "random_forest"),
        ("Random Forest", "random_forest"),
        ("xgb", "xgboost"),
        ("XGBoost", "xgboost"),
        ("if", "isolation_forest"),
        ("Isolation-Forest", "isolation_forest"),
        ("ae", "autoencoder"),
        ("AutoEncoder", "autoencoder"),
    ):
        assert api_service._canonical_model_key(raw_alias) == expected_canonical

    for bad_name in ("lightgbm", "catboost", "random_forest_v2", "my_custom_rf", "", "   "):
        with pytest.raises(ValueError, match=r"(Unsupported model|cannot be empty)"):
            api_service._canonical_model_key(bad_name)

        with (
            patch("network_anomaly.api.service.ARTIFACTS", paths["artifacts"]),
            patch("network_anomaly.api.service.PROJECT_ROOT", tmp_path),
        ):
            with pytest.raises(ValueError, match=r"(Unsupported model|cannot be empty)"):
                api_service.analyze_flows([{"features": {"IN_BYTES": 100}}], model_name=bad_name)


def test_f1_rejects_manifest_model_type_mismatch_on_load_and_health(
    tmp_path: Path, api_service: ApiService
):
    """F1: Health check and loader refuse a manifest whose declared model_type mismatches requested model."""
    paths = _setup_synthetic_artifact_tree(tmp_path, include_xgb=True)
    xgb_manifest_path = paths["xgb_manifest"]
    xgb_manifest = json.loads(xgb_manifest_path.read_text(encoding="utf-8"))
    xgb_manifest["model_type"] = "RandomForestClassifier"
    xgb_manifest_path.write_text(json.dumps(xgb_manifest), encoding="utf-8")

    sample_flow = [
        {
            "features": {
                col: ("6" if col in CATEGORICAL_CODED_COLUMNS else 1.0)
                for col in ML_FEATURE_COLUMNS
            }
        }
    ]
    with (
        patch("network_anomaly.api.service.ARTIFACTS", paths["artifacts"]),
        patch("network_anomaly.api.service.PROJECT_ROOT", tmp_path),
    ):
        health = api_service.check_health("xgb")
        assert health.preprocessor_ready is True
        assert health.model_ready is False
        assert health.status == "degraded"
        assert health.details["models_ready"]["xgboost"] is False
        assert health.details["artifact_verification_error"] == "artifact verification failed"

        with pytest.raises(ValueError, match="mismatch"):
            api_service._load_inference_pipeline("xgb")

        with pytest.raises(ModelNotReadyError):
            api_service.analyze_flows(
                sample_flow,
                model_name="xgb",
                allow_heuristic_fallback=False,
            )

        # Even if heuristic fallback is explicitly allowed, provenance stays heuristic, never 'xgboost'
        fb = api_service.analyze_flows(
            sample_flow,
            model_name="xgb",
            allow_heuristic_fallback=True,
        )
        assert fb.results[0].model_used == "heuristic_baseline_artifact_missing"
        assert fb.model_ready is False


def test_f2_ae_sidecar_tamper_invalidates_service_cache_and_fails_closed(
    tmp_path: Path, api_service: ApiService
):
    """F2: Tampering AE threshold.json sidecar invalidates cache and drops AE health to blocked."""
    paths = _setup_synthetic_artifact_tree(tmp_path, include_ae=True)
    sample_flow = [
        {
            "event_id": "evt_ae_cache",
            "features": {
                col: ("6" if col in CATEGORICAL_CODED_COLUMNS else 10.0)
                for col in ML_FEATURE_COLUMNS
            },
        }
    ]
    th_path = paths["ae_path"].parent / "threshold.json"

    with (
        patch("network_anomaly.api.service.ARTIFACTS", paths["artifacts"]),
        patch("network_anomaly.api.service.PROJECT_ROOT", tmp_path),
    ):
        res_ok = api_service.analyze_flows(sample_flow, model_name="ae")
        assert res_ok.model_ready is True
        assert res_ok.results[0].model_used == "autoencoder"

        # Tamper threshold.json on disk -> cache key includes sidecar digest, so cached entry is invalidated
        tampered = json.loads(th_path.read_text(encoding="utf-8"))
        tampered["threshold"] = 99.0
        th_path.write_text(json.dumps(tampered), encoding="utf-8")

        health_tampered = api_service.check_health("autoencoder")
        assert health_tampered.preprocessor_ready is True
        assert health_tampered.model_ready is False
        assert health_tampered.status == "degraded"
        assert health_tampered.details["models_ready"]["autoencoder"] is False

        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            api_service._load_inference_pipeline("autoencoder")

        with pytest.raises(ModelNotReadyError):
            api_service.analyze_flows(
                sample_flow,
                model_name="autoencoder",
                allow_heuristic_fallback=False,
            )


def test_f3_preserves_unclamped_negative_and_gt_one_scores_with_calibrated_and_null_normalization(
    api_service: ApiService,
):
    """F3: Unsupervised raw scores <0 and >1 remain unclamped; probability stays null; threshold drives prediction."""
    mock_pipeline = MagicMock()
    mock_pipeline.model_metadata = {
        "model_type": "IsolationForest",
        "model_artifact_sha256": "if_sha_123",
        "threshold": 0.0,
        "raw_manifest": {"threshold": 0.0},
    }
    mock_pipeline.preprocessor_metadata = {"artifact_sha256": "prep_sha_123"}
    # Rows preserve order; row 0 negative (<0 -> benign), rows 1 & 2 positive (>1 -> attack)
    mock_pipeline.predict.return_value = pd.DataFrame(
        {
            "row_id": [0, 1, 2],
            "prediction": [0, 1, 1],
            "anomaly_score": [-0.35, 1.85, 4.75],
            "run_id": ["run_if_raw"] * 3,
        }
    )

    events = [
        {"event_id": "e0", "features": {"IN_BYTES": 10}},
        {"event_id": "e1", "features": {"IN_BYTES": 20}},
        {"event_id": "e2", "features": {"IN_BYTES": 30}},
    ]

    with patch.object(api_service, "_load_inference_pipeline", return_value=mock_pipeline):
        res_uncal = api_service.analyze_flows(events, model_name="if", create_incidents=False)

    assert [r.model_used for r in res_uncal.results] == ["isolation_forest"] * 3
    assert [r.index for r in res_uncal.results] == [0, 1, 2]
    assert [r.event_id for r in res_uncal.results] == ["e0", "e1", "e2"]
    assert [r.raw_anomaly_score for r in res_uncal.results] == [-0.35, 1.85, 4.75]
    assert [r.anomaly_score for r in res_uncal.results] == [-0.35, 1.85, 4.75]
    assert [r.prediction for r in res_uncal.results] == [0, 1, 1]
    for r in res_uncal.results:
        assert r.normalized_anomaly_score is None
        assert r.attack_probability is None
        assert r.probabilities is None
        assert r.score_type == "isolation_forest_anomaly_score"
        assert r.score_direction == "higher_is_more_anomalous"
        assert r.decision_threshold == 0.0

    # With valid validation score_normalization calibration: display score maps to [0, 1], raw stays unclamped
    mock_pipeline.model_metadata["raw_manifest"]["score_normalization"] = {
        "calibration_partition": "validation",
        "score_direction": "higher_is_more_anomalous",
        "quantile_grid": [0.0, 0.5, 1.0],
        "score_values": [-0.5, 1.0, 4.0],
    }
    with patch.object(api_service, "_load_inference_pipeline", return_value=mock_pipeline):
        res_cal = api_service.analyze_flows(
            events, model_name="isolation_forest", create_incidents=False
        )

    assert [r.raw_anomaly_score for r in res_cal.results] == [-0.35, 1.85, 4.75]
    assert res_cal.results[0].normalized_anomaly_score == pytest.approx(0.05)
    assert 0.5 < res_cal.results[1].normalized_anomaly_score < 1.0
    assert res_cal.results[2].normalized_anomaly_score == 1.0
    assert all(r.attack_probability is None for r in res_cal.results)


def test_f3_rejects_non_finite_raw_anomaly_scores_fail_closed(api_service: ApiService):
    """F3: Non-finite (NaN / Inf) model scores raise ValueError instead of silent sanitization."""
    mock_pipeline = MagicMock()
    mock_pipeline.model_metadata = {"model_type": "AutoencoderModel", "threshold": 0.5}
    mock_pipeline.preprocessor_metadata = {"artifact_sha256": "prep_sha"}
    mock_pipeline.predict.return_value = pd.DataFrame(
        {
            "row_id": [0],
            "prediction": [1],
            "anomaly_score": [float("nan")],
            "run_id": ["run_nan"],
        }
    )

    with patch.object(api_service, "_load_inference_pipeline", return_value=mock_pipeline):
        with pytest.raises(ValueError, match="non-finite"):
            api_service._analyze_with_verified_pipeline(
                [{"features": {"IN_BYTES": 10}}],
                model_name="autoencoder",
                threshold=0.5,
                pipeline=mock_pipeline,
            )
        with pytest.raises(ModelNotReadyError, match="non-finite"):
            api_service.analyze_flows(
                [{"features": {"IN_BYTES": 10}}],
                model_name="autoencoder",
                allow_heuristic_fallback=False,
                create_incidents=False,
            )


def test_p2_health_reports_preprocessor_ready_true_when_all_models_missing(
    tmp_path: Path, api_service: ApiService
):
    """P2: Preprocessor READY is surfaced independently even when all 4 model binaries are absent."""
    paths = _setup_synthetic_artifact_tree(
        tmp_path, include_rf=False, include_xgb=False, include_if=False, include_ae=False
    )
    with (
        patch("network_anomaly.api.service.ARTIFACTS", paths["artifacts"]),
        patch("network_anomaly.api.service.PROJECT_ROOT", tmp_path),
    ):
        health = api_service.check_health("random_forest")
        assert health.preprocessor_ready is True
        assert health.model_ready is False
        assert health.status == "degraded"
        assert health.details["preprocessor_status"] == "READY"
        for k in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
            assert health.details["models_ready"][k] is False
