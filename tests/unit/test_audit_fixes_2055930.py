"""Regression tests for P1/P2 audit fixes (SPA mount, Stage-2 alert wiring, streaming memory bounds)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

import network_anomaly.api.main as api_main
from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.streaming.alert_manager import LiveAlertManager
from network_anomaly.streaming.pipeline import StreamingEventPipeline
from network_anomaly.streaming.realtime_inference import LiveInferenceDecision
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
    assert edge.edge_id not in graph.edges
    assert "ip:10.0.0.1" not in graph._adj
    assert "ip:10.0.0.1" not in graph._rev_adj
    assert edge.edge_id not in graph._rev_adj["ip:10.0.0.2"]


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
