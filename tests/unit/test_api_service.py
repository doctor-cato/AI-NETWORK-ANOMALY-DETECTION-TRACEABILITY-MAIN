"""Unit tests for ApiService business logic, health check behavior, and lifecycle management."""

from __future__ import annotations

import json
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
from network_anomaly.data.nf_unsw_nb15_v3 import CATEGORICAL_CODED_COLUMNS, ML_FEATURE_COLUMNS
from network_anomaly.inference.predict import _sha256_file
from network_anomaly.preprocessing import (
    FEATURE_CONTRACT_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)
from network_anomaly.preprocessing.pipeline import EXPECTED_DATASET_SHA256


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

    fake_prep = fake_artifacts / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
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
    prep_path = artifact_root / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    model_path = artifact_root / "models" / "random_forest" / "random_forest_baseline.joblib"
    prep_manifest = (
        tmp_path / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
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
        dataset_sha256=EXPECTED_DATASET_SHA256,
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

    fake_prep = fake_artifacts / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
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
        {"features": {"IN_BYTES": 500, "OUT_BYTES": 500, "IN_PKTS": 5, "OUT_PKTS": 5}},
        # Abnormal high-volume flooding flow
        {"features": {"IN_BYTES": 2_500_000, "OUT_BYTES": 100, "IN_PKTS": 2500, "OUT_PKTS": 0}},
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
) -> dict[str, Path]:
    """Create isolated preprocessor + model artifact tree for ApiService F4/F6 tests."""
    from network_anomaly.models.isolation_forest import IsolationForestModel

    art_root = root / "artifacts"
    prep_path = art_root / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    prep_manifest = (
        root / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )
    rf_path = art_root / "models" / "random_forest" / "random_forest_baseline.joblib"
    rf_manifest = root / "reports" / "models" / "random_forest_manifest.json"
    if_path = art_root / "models" / "isolation_forest" / "isolation_forest.joblib"
    if_manifest = root / "reports" / "models" / "isolation_forest_manifest.json"

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
        dataset_sha256=EXPECTED_DATASET_SHA256,
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

    return {
        "artifacts": art_root,
        "rf_path": rf_path,
        "rf_manifest": rf_manifest,
        "if_path": if_path,
        "if_manifest": if_manifest,
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
        assert health_default.preprocessor_ready is False
        assert health_default.details["default_model"] == "random_forest"
        assert health_default.details["default_analysis_ready"] is False
        assert health_default.details["models_ready"] == {
            "random_forest": False,
            "isolation_forest": True,
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
