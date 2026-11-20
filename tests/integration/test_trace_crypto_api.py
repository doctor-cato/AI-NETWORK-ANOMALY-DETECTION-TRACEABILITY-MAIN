"""Regression integration tests for Trace, Benchmark Report, and Auth Warning APIs."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from network_anomaly.api import main as api_main
from network_anomaly.api.main import create_app


def test_trace_graph_handles_live_runtime_nodes_and_edges(tmp_path: Path, monkeypatch) -> None:
    """Verify /api/v1/trace/graph populates graph via add_node/add_edge without AttributeError."""
    monkeypatch.setenv("NETWORK_ANOMALY_API_TOKEN", "trace-graph-test-token")
    headers = {"X-Sentinel-Session-Token": "trace-graph-test-token"}
    app = create_app(db_path=tmp_path / "trace_graph.db")

    # Empty graph branch must return EMPTY and truncated=False
    with TestClient(app) as client:
        empty_resp = client.get("/api/v1/trace/graph?entity_id=10.0.0.99&depth=2", headers=headers)
        assert empty_resp.status_code == 200
        empty_body = empty_resp.json()
        assert empty_body["data_status"] == "EMPTY"
        assert empty_body["truncated"] is False

        # Mock LiveRuntime.entity_graph() returning both nodes and edges
        live_graph_payload = {
            "node_count": 3,
            "edge_count": 2,
            "nodes": [
                {
                    "node_id": "ip:198.51.100.1",
                    "kind": "IP",
                    "label": "198.51.100.1",
                    "properties": {},
                },
                {"node_id": "ip:10.0.0.5", "kind": "IP", "label": "10.0.0.5", "properties": {}},
                {"node_id": "port:443", "kind": "PORT", "label": "Port 443", "properties": {}},
            ],
            "edges": [
                {
                    "edge_id": "e:ip:198.51.100.1->CONNECTS_TO->ip:10.0.0.5",
                    "source_id": "ip:198.51.100.1",
                    "target_id": "ip:10.0.0.5",
                    "relation_type": "CONNECTS_TO",
                    "confidence": 1.0,
                    "is_observed": True,
                    "evidence_id": "ev-live-1",
                },
                {
                    "edge_id": "e:ip:10.0.0.5->CONNECTS_TO->port:443",
                    "source_id": "ip:10.0.0.5",
                    "target_id": "port:443",
                    "relation_type": "CONNECTS_TO",
                    "confidence": 0.9,
                    "is_observed": False,
                    "evidence_id": "ev-live-2",
                },
            ],
        }
        monkeypatch.setattr(app.state.live_runtime, "entity_graph", lambda: live_graph_payload)

        resp = client.get("/api/v1/trace/graph?entity_id=ip:198.51.100.1&depth=1", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["data_status"] == "CONNECTED"
        assert body["node_count"] >= 2
        assert body["edge_count"] >= 1
        assert body["truncated"] is True


def test_trace_timeline_pagination_offset_and_limit(tmp_path: Path, monkeypatch) -> None:
    """Verify /api/v1/trace/timeline slices stages with offset/limit and preserves total_stages."""
    monkeypatch.setenv("NETWORK_ANOMALY_API_TOKEN", "trace-tl-test-token")
    headers = {"X-Sentinel-Session-Token": "trace-tl-test-token"}
    app = create_app(db_path=tmp_path / "trace_tl.db")

    with TestClient(app) as client:
        ingest = client.post(
            "/api/v1/ingest",
            headers=headers,
            json={
                "session_id": "sess-paginated",
                "events": [
                    {
                        "event_id": f"ev-page-{i}",
                        "timestamp": f"2026-11-18T10:0{i}:00Z",
                        "source_ip": f"198.51.100.{10 + i}",
                        "dest_ip": f"10.0.0.{20 + i}",
                        "source_port": 50000 + i,
                        "dest_port": 443,
                        "protocol": "TCP",
                        "features": {"IN_BYTES": 500 + i * 100},
                    }
                    for i in range(3)
                ],
            },
        )
        assert ingest.status_code == 200

        full_resp = client.get(
            "/api/v1/trace/timeline?campaign_name=sess-paginated&limit=50&offset=0",
            headers=headers,
        )
        assert full_resp.status_code == 200
        full_data = full_resp.json()
        assert full_data["total_stages"] == 3
        assert len(full_data["stages"]) == 3

        page_resp = client.get(
            "/api/v1/trace/timeline?campaign_name=sess-paginated&limit=1&offset=1",
            headers=headers,
        )
        assert page_resp.status_code == 200
        page_data = page_resp.json()
        assert page_data["total_stages"] == 3
        assert len(page_data["stages"]) == 1
        assert page_data["stages"][0]["stage_id"] == full_data["stages"][1]["stage_id"]
        assert page_data["provenance"]["offset"] == 1
        assert page_data["provenance"]["limit"] == 1


def test_investigation_report_includes_artifact_version(tmp_path: Path, monkeypatch) -> None:
    """Verify /api/v1/trace/investigation/generate returns artifact_version == '2.0.0'."""
    monkeypatch.setenv("NETWORK_ANOMALY_API_TOKEN", "inv-ver-test-token")
    headers = {"X-Sentinel-Session-Token": "inv-ver-test-token"}
    app = create_app(db_path=tmp_path / "trace_inv.db")

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/trace/investigation/generate",
            headers=headers,
            json={
                "incident_id": "INC-VER-001",
                "title": "Artifact Version Check",
                "severity": "HIGH",
                "root_cause_summary": "Verified report artifact versioning.",
                "events": [
                    {
                        "timestamp": "2026-11-18T12:00:00Z",
                        "source_ip": "198.51.100.5",
                        "dest_ip": "10.0.0.10",
                        "attack_type": "Reconnaissance",
                        "dest_port": 22,
                    }
                ],
                "evidence_records": [],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["artifact_version"] == "2.0.0"
        assert body["artifact_hash"] != ""
        assert "2.0.0" in body["markdown_content"]


def test_model_benchmark_report_real_and_missing_files(tmp_path: Path, monkeypatch) -> None:
    """Verify /api/v1/models/benchmark-report returns real metrics and gracefully handles missing files."""
    monkeypatch.setenv("NETWORK_ANOMALY_API_TOKEN", "bench-test-token")
    headers = {"X-Sentinel-Session-Token": "bench-test-token"}
    app = create_app(db_path=tmp_path / "bench.db")

    with TestClient(app) as client:
        real_resp = client.get("/api/v1/models/benchmark-report", headers=headers)
        assert real_resp.status_code == 200
        real_body = real_resp.json()
        assert real_body["data_status"] == "CONNECTED"
        assert len(real_body["models"]) == 4
        assert {m["model_key"] for m in real_body["models"]} == {
            "random_forest",
            "xgboost",
            "isolation_forest",
            "autoencoder",
        }
        for model in real_body["models"]:
            assert model["deployment_tier"] == "RESEARCH_ONLY"
            assert model["in_domain"] is not None
            assert model["in_domain"]["roc_auc"] is not None
            assert {cs["dataset"] for cs in model["cross_source"]} == {
                "CTU-Echo",
                "CTU-Win7AD",
                "UWF-ZeekData24",
            }
            assert len(model["top_features"]) > 0
        assert len(real_body["sources_loaded"]) == 3

        # Missing reports directory -> EMPTY without crashing
        monkeypatch.setattr(api_main, "PROJECT_ROOT", tmp_path)
        empty_resp = client.get("/api/v1/models/benchmark-report", headers=headers)
        assert empty_resp.status_code == 200
        empty_body = empty_resp.json()
        assert empty_body["data_status"] == "EMPTY"
        assert empty_body["models"] == []
        assert empty_body["sources_loaded"] == []


def test_missing_api_token_logs_warning_and_run_api_prints_warning(
    tmp_path: Path, monkeypatch, caplog, capsys
) -> None:
    """Verify dev-mode security warning is emitted when NETWORK_ANOMALY_API_TOKEN is empty."""
    monkeypatch.delenv("NETWORK_ANOMALY_API_TOKEN", raising=False)
    with caplog.at_level(logging.WARNING, logger="network_anomaly.api.main"):
        create_app(db_path=tmp_path / "no_token.db")
    assert any("NETWORK_ANOMALY_API_TOKEN is not set" in rec.message for rec in caplog.records)

    scripts_dir = Path(__file__).resolve().parents[2] / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import run_api  # noqa: E402

    monkeypatch.setattr(sys, "argv", ["run_api.py", "--db-path", str(tmp_path / "cli.db")])
    monkeypatch.setattr(run_api.uvicorn, "run", lambda *args, **kwargs: None)
    run_api.main()
    captured = capsys.readouterr()
    assert "[SECURITY WARNING] NETWORK_ANOMALY_API_TOKEN is unset" in captured.out
