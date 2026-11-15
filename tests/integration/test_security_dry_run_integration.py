"""Integration tests for Issue #27 dry-run policy simulation on real demo artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from network_anomaly.api.main import create_app
from network_anomaly.config import ARTIFACTS, PROJECT_ROOT

DEMO_FLOWS = PROJECT_ROOT / "data" / "demo" / "demo_flows.csv"
RF_MODEL = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
IF_MODEL = ARTIFACTS / "models" / "isolation_forest" / "isolation_forest.joblib"
PREP_ARTIFACT = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"


@pytest.mark.skipif(
    not (DEMO_FLOWS.is_file() and RF_MODEL.is_file() and PREP_ARTIFACT.is_file()),
    reason="Verified Random Forest / Preprocessor / Demo CSV artifacts not present.",
)
def test_real_demo_analyze_then_server_verified_dry_run_and_anti_spoof(tmp_path: Path):
    """End-to-end flow: CSV analyze -> server-verified dry-run -> tamper fail-closed -> SQLite restart."""
    db_path = tmp_path / "dry_run_e2e.db"
    app = create_app(db_path=db_path)
    with TestClient(app, raise_server_exceptions=False) as client:
        analyze_resp = client.post(
            "/api/v1/csv/analyze",
            json={
                "file_path": str(DEMO_FLOWS),
                "model_name": "random_forest",
                "create_incidents": False,
            },
        )
        assert analyze_resp.status_code == 200, analyze_resp.text
        analyzed = analyze_resp.json()
        analysis_id = analyzed["analysis_id"]
        assert analyzed["ood_flagged_count"] == 2

        # Server-verified simulation using analysis_id
        sim_resp = client.post(
            "/api/v1/security/simulate-response",
            json={"analysis_id": analysis_id, "triggered_by": "e2e_test", "dry_run": True},
        )
        assert sim_resp.status_code == 200, sim_resp.text
        sim = sim_resp.json()
        assert sim["provenance_verification"] == "server_verified_analysis"
        assert sim["execution_mode"] == "DRY_RUN_SIMULATION"
        assert sim["executed"] is False
        assert sim["os_firewall_touched"] is False
        assert sim["real_key_rotated"] is False
        assert sim["total_flows"] == analyzed["total_rows"] == 200
        assert sim["ood_abstained_flows"] == 2
        assert sim["evaluated_flows"] == 198
        assert sim["action_counts"]["ISOLATE_RECOMMENDED"] > 0

        # Every OOD row in the real demo batch must NOT receive isolation
        ood_recs = [r for r in sim["recommendations"] if r["is_ood_flagged"]]
        assert len(ood_recs) == 2
        for rec in ood_recs:
            assert rec["action"] != "ISOLATE_RECOMMENDED"
            assert rec["containment_allowed"] is False
            assert rec["executed"] is False

        # Anti-spoofing: tampered rows submitted under valid analysis_id fail closed
        tampered_rows = list(analyzed["results"])
        tampered_rows[0] = {**tampered_rows[0], "predicted_class": "Attack", "risk_score": 99.9}
        spoof_resp = client.post(
            "/api/v1/security/simulate-response",
            json={"analysis_id": analysis_id, "results": tampered_rows, "dry_run": True},
        )
        assert spoof_resp.status_code == 400

    # Simulate app restart against same SQLite DB and verify persistence, volatile analysis_id
    # fail-closed behavior (F-04), and safe export under tmp_path (F-05).
    app2 = create_app(db_path=db_path)
    export_out = tmp_path / "test_issue27_real_demo_e2e.json"
    with TestClient(app2, raise_server_exceptions=False) as client2:
        stale_resp = client2.post(
            "/api/v1/security/simulate-response",
            json={"analysis_id": analysis_id, "dry_run": True},
        )
        assert stale_resp.status_code == 400
        assert "Unknown or expired analysis_id" in stale_resp.text

        hist = client2.get("/api/v1/security/simulations").json()
        assert hist["total"] == 1
        assert hist["items"][0]["simulation_id"] == sim["simulation_id"]
        assert hist["items"][0]["executed"] is False

        exp_resp = client2.post(
            "/api/v1/security/simulations/export",
            json={"output_path": str(export_out), "simulation_id": sim["simulation_id"]},
        )
        assert exp_resp.status_code == 200
        exported = json.loads(Path(exp_resp.json()["json_path"]).read_text(encoding="utf-8"))
        assert exported["provenance"]["source_provenance_verified"] is True
        assert exported["executed"] is False


@pytest.mark.skipif(
    not (DEMO_FLOWS.is_file() and IF_MODEL.is_file() and PREP_ARTIFACT.is_file()),
    reason="Isolation Forest / Preprocessor / Demo CSV artifacts not present.",
)
def test_real_demo_isolation_forest_research_only_blocks_isolate_and_rotation(tmp_path: Path):
    """F-01 real-artifact regression: RESEARCH_ONLY Isolation Forest never gets ISOLATE or rotation."""
    app = create_app(db_path=tmp_path / "if_research_only.db")
    with TestClient(app, raise_server_exceptions=False) as client:
        analyze_resp = client.post(
            "/api/v1/csv/analyze",
            json={
                "file_path": str(DEMO_FLOWS),
                "model_name": "isolation_forest",
                "create_incidents": False,
            },
        )
        assert analyze_resp.status_code == 200, analyze_resp.text
        analyzed = analyze_resp.json()
        assert analyzed["compatibility_gate"]["compatibility_status"] == "RESEARCH_ONLY"
        assert analyzed["compatibility_gate"]["eligibility_status"] == "RESEARCH_ONLY"
        assert analyzed["compatibility_gate"]["eligible"] is True

        sim_resp = client.post(
            "/api/v1/security/simulate-response",
            json={"analysis_id": analyzed["analysis_id"], "dry_run": True},
        )
        assert sim_resp.status_code == 200, sim_resp.text
        sim = sim_resp.json()
        assert sim["provenance_verification"] == "server_verified_analysis"
        assert sim["action_counts"]["ISOLATE_RECOMMENDED"] == 0
        assert all(r["containment_allowed"] is False for r in sim["recommendations"])
        assert sim["key_rotation_simulation"]["decision"] == "HOLD_RESEARCH_ONLY_MODEL"
        assert sim["key_rotation_simulation"]["recommended"] is False
        assert sim["key_rotation_simulation"]["would_rotate"] is False
