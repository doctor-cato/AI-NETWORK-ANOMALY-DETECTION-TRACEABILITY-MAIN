"""Regression tests for P1/P2 audit fixes (SPA mount, Stage-2 alert wiring, streaming memory bounds)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import joblib
import pytest
from fastapi.testclient import TestClient

import network_anomaly.api.main as api_main
from network_anomaly.api.live_runtime import LiveRuntime
from network_anomaly.behavioral.vector import BehavioralVectorBuilder
from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.crypto.key_manager import KeyManager
from network_anomaly.crypto.rotation import KeyRotationPolicy
from network_anomaly.models.stage2_multiclass import (
    CANONICAL_6_CLASSES,
    Stage2MulticlassClassifier,
)
from network_anomaly.streaming.alert_manager import LiveAlertManager
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator
from network_anomaly.streaming.pipeline import StreamingEventPipeline
from network_anomaly.streaming.realtime_inference import (
    LiveInferenceDecision,
    RealtimeInferenceEngine,
)
from network_anomaly.trace.graph import EntityKind, EntityRelationshipGraph, RelationType


def _make_event(
    event_id: str,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    bytes_out: int = 100_000,
) -> CanonicalSecurityEvent:
    return CanonicalSecurityEvent(
        event_id=event_id,
        event_timestamp=datetime.now(timezone.utc),
        event_kind=EventKind.FLOW,
        source_id="unit-test",
        entity_id=f"host:{src_ip}",
        source_ip=src_ip,
        dest_ip=dst_ip,
        dest_port=445,
        protocol="TCP",
        flow_metrics=FlowMetrics(
            duration_ms=120.0,
            bytes_in=500,
            bytes_out=bytes_out,
            pkts_in=4,
            pkts_out=20,
        ),
        raw_provenance=RawProvenance(
            source_file="unit-test",
            adapter_name="unit-test",
        ),
    )


def test_app_spa_mount_exempt_from_token_while_api_protected(tmp_path: Path, monkeypatch) -> None:
    dist_dir = tmp_path / "desktop" / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "index.html").write_text("<html><body>Sentinel SPA</body></html>", encoding="utf-8")

    monkeypatch.setattr(api_main, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("NETWORK_ANOMALY_API_TOKEN", "audit-secret-token")

    app = api_main.create_app(db_path=tmp_path / "audit_test.db")
    with TestClient(app) as client:
        spa_resp = client.get("/app/")
        assert spa_resp.status_code == 200
        assert "Sentinel SPA" in spa_resp.text

        unauth_api = client.get("/api/v1/live/status")
        assert unauth_api.status_code == 401

        auth_api = client.get(
            "/api/v1/live/status",
            headers={"X-Sentinel-Session-Token": "audit-secret-token"},
        )
        assert auth_api.status_code == 200


def test_streaming_pipeline_bounds_batch_sizes_and_latencies() -> None:
    pipeline = StreamingEventPipeline(capacity=100, batch_size=1)
    for idx in range(1200):
        ev = _make_event(f"ev-pipe-{idx}")
        assert pipeline.enqueue(ev) is True
        batch = pipeline.fetch_micro_batch(timeout_sec=0.05)
        assert len(batch) == 1

    assert len(pipeline._batch_sizes) <= 1000
    assert len(pipeline._latencies) <= 1000
    metrics = pipeline.get_metrics()
    assert metrics.total_processed == 1200
    assert metrics.avg_batch_size == 1.0


def test_entity_graph_evict_entity_cleans_nodes_edges_and_adjacency() -> None:
    graph = EntityRelationshipGraph()
    graph.add_node("host:10.0.0.1", EntityKind.IP, label="10.0.0.1")
    graph.add_node("ip:10.0.0.1", EntityKind.IP, label="10.0.0.1")
    graph.add_node("ip:10.0.0.2", EntityKind.IP, label="10.0.0.2")
    edge = graph.add_edge(
        source_id="ip:10.0.0.1",
        target_id="ip:10.0.0.2",
        relation_type=RelationType.CONNECTS_TO,
    )

    graph.evict_entity("host:10.0.0.1")

    assert "host:10.0.0.1" not in graph.nodes
    assert "ip:10.0.0.1" not in graph.nodes
    assert "ip:10.0.0.2" not in graph.nodes
    assert edge.edge_id not in graph.edges
    assert "ip:10.0.0.1" not in graph._adj
    assert "ip:10.0.0.1" not in graph._rev_adj
    assert "ip:10.0.0.2" not in graph._rev_adj


def test_live_alert_manager_persists_stage2_category_and_caps_event_ids(tmp_path: Path) -> None:
    db_path = tmp_path / "alerts.db"
    mgr = LiveAlertManager(db_path=db_path, dedup_window_sec=60.0, risk_threshold_alert=50.0)
    decision = LiveInferenceDecision(
        event_id="ev-0",
        inference_mode="deployment",
        ensemble_is_anomaly=True,
        ensemble_score=0.95,
        ensemble_score_semantics="probability",
        is_ood=False,
        ood_reason=None,
        model_predictions={},
        total_inference_latency_us=100.0,
        per_model_latency_us={},
        predicted_attack_category="DDoS_or_DoS",
        attack_category_confidence=0.91,
        stage2_classifier_status="ACTIVE",
    )

    alert = None
    for idx in range(250):
        ev = _make_event(f"ev-{idx}", src_ip="10.0.0.99", bytes_out=100_000)
        _, alert = mgr.process_event_risk(ev, inference_decision=decision, persist=(idx == 249))

    assert alert is not None
    assert alert.predicted_attack_category == "DDoS_or_DoS"
    assert alert.attack_category_confidence == 0.91
    assert len(alert.associated_event_ids) <= 200

    reloaded = LiveAlertManager(db_path=db_path, dedup_window_sec=60.0, risk_threshold_alert=50.0)
    loaded_alerts = reloaded.list_alerts(limit=10)
    assert len(loaded_alerts) == 1
    assert loaded_alerts[0].predicted_attack_category == "DDoS_or_DoS"
    assert loaded_alerts[0].attack_category_confidence == 0.91
    assert len(loaded_alerts[0].associated_event_ids) <= 200


def test_stage2_from_manifest_rejects_missing_model_artifact_sha256(tmp_path: Path) -> None:
    artifact_path = tmp_path / "stage2.joblib"
    joblib.dump({"dummy": True}, artifact_path)

    manifest_path = tmp_path / "stage2_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "classes": list(CANONICAL_6_CLASSES),
                "class_centroids": {c: [0.0] * 18 for c in CANONICAL_6_CLASSES},
                "class_stds": {c: [1.0] * 18 for c in CANONICAL_6_CLASSES},
                "model_artifact_sha256": "",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing model_artifact_sha256"):
        Stage2MulticlassClassifier.from_manifest(
            manifest_path=manifest_path,
            artifact_path=artifact_path,
        )


def test_realtime_inference_passes_preprocessor_sha256_and_rejects_mismatch(
    tmp_path: Path, monkeypatch
) -> None:
    import network_anomaly.models.stage2_multiclass as stage2_mod

    manifest_path = tmp_path / "stage2_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "classes": list(CANONICAL_6_CLASSES),
                "class_centroids": {c: [0.0] * 18 for c in CANONICAL_6_CLASSES},
                "class_stds": {c: [1.0] * 18 for c in CANONICAL_6_CLASSES},
                "preprocessor_artifact_sha256": "a" * 64,
            }
        ),
        encoding="utf-8",
    )
    absent_artifact = tmp_path / "absent.joblib"

    monkeypatch.setattr(stage2_mod, "DEFAULT_STAGE2_MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(stage2_mod, "DEFAULT_STAGE2_ARTIFACT_PATH", absent_artifact)

    # Also update try_load_default defaults via wrapper because default args bind at def time
    orig_try_load = Stage2MulticlassClassifier.try_load_default
    captured: list[str | None] = []

    def _spy_try_load(**kwargs):
        captured.append(kwargs.get("expected_preprocessor_sha256"))
        return orig_try_load(
            artifact_path=absent_artifact,
            manifest_path=manifest_path,
            expected_preprocessor_sha256=kwargs.get("expected_preprocessor_sha256"),
        )

    monkeypatch.setattr(Stage2MulticlassClassifier, "try_load_default", staticmethod(_spy_try_load))

    mismatched_registry = SimpleNamespace(
        preprocessor_sha256="b" * 64,
        statuses=lambda: [],
        available_models=lambda: [],
    )
    engine_bad = RealtimeInferenceEngine(
        registry=mismatched_registry,
        runtime_mode="research",
        require_ood_gate=False,
        enable_stage2_multiclass=True,
    )
    assert engine_bad._get_stage2_classifier() is None
    assert captured[-1] == "b" * 64

    matching_registry = SimpleNamespace(
        preprocessor_sha256="a" * 64,
        statuses=lambda: [],
        available_models=lambda: [],
    )
    engine_ok = RealtimeInferenceEngine(
        registry=matching_registry,
        runtime_mode="research",
        require_ood_gate=False,
        enable_stage2_multiclass=True,
    )
    clf = engine_ok._get_stage2_classifier()
    assert clf is not None
    assert captured[-1] == "a" * 64


def test_live_runtime_and_api_preserve_stage2_category_and_handle_legacy_db(tmp_path: Path) -> None:
    # 1. Migrated schema with predicted_attack_category & attack_category_confidence
    db_path = tmp_path / "live_migrated.db"
    mgr = LiveAlertManager(db_path=db_path, dedup_window_sec=60.0, risk_threshold_alert=50.0)
    decision = LiveInferenceDecision(
        event_id="ev-s2",
        inference_mode="deployment",
        ensemble_is_anomaly=True,
        ensemble_score=0.95,
        ensemble_score_semantics="probability",
        is_ood=False,
        ood_reason=None,
        model_predictions={},
        total_inference_latency_us=100.0,
        per_model_latency_us={},
        predicted_attack_category="Brute_Force",
        attack_category_confidence=0.88,
        stage2_classifier_status="ACTIVE",
    )
    ev = _make_event("ev-s2", src_ip="10.0.0.42", bytes_out=100_000)
    _, alert = mgr.process_event_risk(ev, inference_decision=decision, persist=True)
    assert alert is not None

    runtime = LiveRuntime(db_path=db_path)
    persisted = runtime._read_persisted_alerts(limit=10)
    assert len(persisted) == 1
    assert persisted[0]["predicted_attack_category"] == "Brute_Force"
    assert persisted[0]["attack_category_confidence"] == pytest.approx(0.88)

    app = api_main.create_app(db_path=db_path)
    with TestClient(app) as client:
        resp = client.get("/api/v1/live/alerts?limit=10")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["predicted_attack_category"] == "Brute_Force"
        assert body["items"][0]["attack_category_confidence"] == pytest.approx(0.88)

    # 2. Legacy schema without predicted_attack_category / attack_category_confidence
    legacy_db = tmp_path / "live_legacy.db"
    with sqlite3.connect(legacy_db) as conn:
        conn.execute("""
            CREATE TABLE live_alerts (
                alert_id TEXT PRIMARY KEY,
                created_at_utc TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                trigger_reason TEXT NOT NULL,
                status TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL,
                first_seen_utc TEXT NOT NULL,
                last_seen_utc TEXT NOT NULL,
                associated_event_ids TEXT NOT NULL,
                adaptive_key_rotated INTEGER NOT NULL,
                detection_latency_ms REAL NOT NULL
            )
            """)
        conn.execute(
            """
            INSERT INTO live_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "alert-legacy-1",
                "2026-01-01T00:00:00+00:00",
                "host:10.0.0.88",
                80.0,
                "HIGH",
                "Legacy alert",
                "NEW",
                1,
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
                '["ev-leg-1"]',
                0,
                1.5,
            ),
        )
    legacy_runtime = LiveRuntime(db_path=legacy_db)
    legacy_alerts = legacy_runtime._read_persisted_alerts(limit=10)
    assert len(legacy_alerts) == 1
    assert legacy_alerts[0]["predicted_attack_category"] is None
    assert legacy_alerts[0]["attack_category_confidence"] is None


def test_dedup_escalation_updates_risk_level_and_triggers_key_rotation(tmp_path: Path) -> None:
    db_path = tmp_path / "dedup_escalate.db"
    km = KeyManager(keystore_dir=tmp_path / "keys")
    rotator = KeyRotationPolicy(key_manager=km, db_path=db_path, adaptive_risk_threshold=85.0)
    mgr = LiveAlertManager(
        db_path=db_path,
        dedup_window_sec=60.0,
        risk_threshold_alert=70.0,
        key_rotator=rotator,
    )

    # First event: HIGH (~72.5 = 0.85*50 + 0.60*25 + 15(port 445))
    ev1 = _make_event("ev-hi", src_ip="10.0.0.55", bytes_out=20_000)
    dec1 = LiveInferenceDecision(
        event_id="ev-hi",
        inference_mode="deployment",
        ensemble_is_anomaly=True,
        ensemble_score=0.85,
        ensemble_score_semantics="probability",
        is_ood=False,
        ood_reason=None,
        model_predictions={},
        total_inference_latency_us=50.0,
        per_model_latency_us={},
    )
    risk1, alert1 = mgr.process_event_risk(ev1, inference_decision=dec1)
    assert alert1 is not None
    assert risk1.severity.value == "HIGH"
    assert alert1.risk_level == "HIGH"
    assert alert1.adaptive_key_rotated is False

    # Second event within 60s: CRITICAL (>= 85.0)
    ev2 = _make_event("ev-crit", src_ip="10.0.0.55", bytes_out=100_000)
    dec2 = LiveInferenceDecision(
        event_id="ev-crit",
        inference_mode="deployment",
        ensemble_is_anomaly=True,
        ensemble_score=0.98,
        ensemble_score_semantics="probability",
        is_ood=False,
        ood_reason=None,
        model_predictions={},
        total_inference_latency_us=50.0,
        per_model_latency_us={},
    )
    risk2, alert2 = mgr.process_event_risk(ev2, inference_decision=dec2)
    assert alert2 is not None
    assert alert2.alert_id == alert1.alert_id
    assert risk2.severity.value == "CRITICAL"
    assert alert2.risk_level == "CRITICAL"
    assert alert2.risk_score >= 85.0
    assert alert2.adaptive_key_rotated is True


def test_behavioral_features_and_baseline_deviation_boost_beh_score(tmp_path: Path) -> None:
    mgr = LiveAlertManager(db_path=tmp_path / "beh.db", risk_threshold_alert=50.0)
    ev = _make_event("ev-beh-real", src_ip="10.0.0.77", bytes_out=100)

    # Real BehavioralVectorBuilder.FEATURE_NAMES: unique_ports_norm, log_pkts_out, dns_intensity, auth_failure_ratio
    bv_proxy = SimpleNamespace(
        feature_names=BehavioralVectorBuilder.FEATURE_NAMES,
        features=[0.0] * len(BehavioralVectorBuilder.FEATURE_NAMES),
    )
    idx_ports = BehavioralVectorBuilder.FEATURE_NAMES.index("unique_ports_norm")
    idx_pkts = BehavioralVectorBuilder.FEATURE_NAMES.index("log_pkts_out")
    bv_proxy.features[idx_ports] = 0.6
    bv_proxy.features[idx_pkts] = 0.7

    risk_feats, _ = mgr.process_event_risk(
        ev, inference_decision=None, behavioral_vector=bv_proxy, persist=False
    )
    assert risk_feats.component_breakdown["behavioral_deviation"] > 10.0

    # baseline_deviation_score=0.90 should boost behavioral_deviation to 0.90 * 25.0 = 22.5
    risk_base, _ = mgr.process_event_risk(
        ev,
        inference_decision=None,
        behavioral_vector=None,
        baseline_deviation_score=0.90,
        persist=False,
    )
    assert risk_base.component_breakdown["behavioral_deviation"] == pytest.approx(22.5)

    # Orchestrator instantiates EntityBaselineProfiler
    orch = LiveSystemOrchestrator(
        inference_engine=RealtimeInferenceEngine(
            registry=SimpleNamespace(
                preprocessor_sha256=None,
                statuses=lambda: [],
                available_models=lambda: [],
            ),
            runtime_mode="research",
            require_ood_gate=False,
        )
    )
    assert hasattr(orch, "baseline_profiler")


def test_entity_graph_evict_entity_prunes_orphan_ip_and_user_nodes() -> None:
    graph = EntityRelationshipGraph()
    graph.add_node("host:10.0.0.1", EntityKind.IP, label="10.0.0.1")
    graph.add_node("ip:10.0.0.1", EntityKind.IP, label="10.0.0.1")
    graph.add_node("ip:10.0.0.2", EntityKind.IP, label="10.0.0.2")
    graph.add_node("user:alice", EntityKind.USER, label="alice")
    graph.add_node("ip:10.0.0.3", EntityKind.IP, label="10.0.0.3")
    graph.add_node("ip:10.0.0.4", EntityKind.IP, label="10.0.0.4")

    graph.add_edge("ip:10.0.0.1", "ip:10.0.0.2", RelationType.CONNECTS_TO)
    graph.add_edge("ip:10.0.0.1", "user:alice", RelationType.AUTHENTICATES_AS)
    # Shared destination ip:10.0.0.3 also connected from ip:10.0.0.4
    graph.add_edge("ip:10.0.0.1", "ip:10.0.0.3", RelationType.CONNECTS_TO)
    graph.add_edge("ip:10.0.0.4", "ip:10.0.0.3", RelationType.CONNECTS_TO)

    graph.evict_entity("host:10.0.0.1")

    assert "host:10.0.0.1" not in graph.nodes
    assert "ip:10.0.0.1" not in graph.nodes
    # Orphan degree-0 nodes are pruned
    assert "ip:10.0.0.2" not in graph.nodes
    assert "user:alice" not in graph.nodes
    assert "ip:10.0.0.2" not in graph._adj
    assert "ip:10.0.0.2" not in graph._rev_adj
    assert "user:alice" not in graph._adj
    assert "user:alice" not in graph._rev_adj
    # Shared node with remaining degree > 0 is preserved
    assert "ip:10.0.0.3" in graph.nodes
    assert "ip:10.0.0.4" in graph.nodes


def test_orchestrator_evicts_oldest_entity_from_baseline_profiler_windows() -> None:
    orch = LiveSystemOrchestrator(
        inference_engine=RealtimeInferenceEngine(
            registry=SimpleNamespace(
                preprocessor_sha256=None,
                ready_count=0,
                statuses=lambda: [],
                available_models=lambda: [],
            ),
            runtime_mode="research",
            require_ood_gate=False,
        ),
        max_active_entities=2,
    )

    ev1 = _make_event("ev-lru-1", src_ip="10.0.0.1")
    ev2 = _make_event("ev-lru-2", src_ip="10.0.0.2")
    ev3 = _make_event("ev-lru-3", src_ip="10.0.0.3")

    orch.process_event(ev1)
    orch.process_event(ev2)
    assert "host:10.0.0.1" in orch.baseline_profiler._windows
    assert "host:10.0.0.2" in orch.baseline_profiler._windows

    # Processing a 3rd entity exceeds max_active_entities=2 and evicts host:10.0.0.1
    orch.process_event(ev3)
    assert "host:10.0.0.1" not in orch.baseline_profiler._windows
    assert "host:10.0.0.2" in orch.baseline_profiler._windows
    assert "host:10.0.0.3" in orch.baseline_profiler._windows
