"""End-to-end localhost desktop workflow tests (Gate B / M6 Desktop integration)."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pandas as pd
import pytest

from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS

DEMO_FLOWS = PROJECT_ROOT / "data" / "demo" / "demo_flows.csv"
DEMO_LABELS = PROJECT_ROOT / "data" / "demo" / "demo_labels.csv"
RF_MODEL = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
IF_MODEL = ARTIFACTS / "models" / "isolation_forest" / "isolation_forest.joblib"
PREP_ARTIFACT = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"


def _find_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _spawn_localhost_api(db_file: Path) -> tuple[subprocess.Popen[bytes], str]:
    port = _find_free_loopback_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    proc = subprocess.Popen(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "run_api.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--db-path",
            str(db_file),
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc, f"http://127.0.0.1:{port}"


def _wait_for_health(proc: subprocess.Popen[bytes], base_url: str, timeout_s: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"run_api.py exited prematurely ({proc.returncode})")
        try:
            r = httpx.get(f"{base_url}/health", timeout=1.0)
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            time.sleep(0.25)
    raise AssertionError(f"Backend failed to become healthy within {timeout_s}s")


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def test_run_api_refuses_non_loopback_host_without_flag():
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "run_api.py"), "--host", "0.0.0.0"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        timeout=15,
    )
    assert proc.returncode != 0
    assert "non-loopback" in (proc.stderr + proc.stdout).lower()


def test_m6_desktop_localhost_synthetic_inspect_and_blocked_model_ci(tmp_path: Path):
    """Verify live loopback API health, 47-feature CSV inspect, and 503 blocked-model guard without .joblib."""
    n_rows = 4
    synth: dict[str, list[object]] = {
        "row_id": [1, 2, 3, 4],
        "FLOW_START_MILLISECONDS": [1_700_000_001_000 + i * 1000 for i in range(n_rows)],
        "FLOW_END_MILLISECONDS": [1_700_000_001_500 + i * 1000 for i in range(n_rows)],
        "IPV4_SRC_ADDR": ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3"],
        "IPV4_DST_ADDR": ["192.168.1.10"] * n_rows,
        "L4_SRC_PORT": [50001, 50002, 50003, 50004],
        "L4_DST_PORT": [443, 80, 443, 22],
        "Label": [0, 1, 0, 1],
    }
    for col in ML_FEATURE_COLUMNS:
        if col == "MIN_TTL":
            synth[col] = [64.0, 0.0, 64.0, 128.0]
        elif col == "MAX_TTL":
            synth[col] = [64.0, 0.0, 64.0, 128.0]
        elif col == "LONGEST_FLOW_PKT":
            synth[col] = [512.0] * n_rows
        elif col == "SHORTEST_FLOW_PKT":
            synth[col] = [64.0] * n_rows
        elif col == "MAX_IP_PKT_LEN":
            synth[col] = [512.0] * n_rows
        elif col == "MIN_IP_PKT_LEN":
            synth[col] = [64.0] * n_rows
        else:
            synth[col] = [1.0 + i for i in range(n_rows)]

    synth_csv = tmp_path / "synthetic_47_features.csv"
    pd.DataFrame(synth).to_csv(synth_csv, index=False)

    proc, base_url = _spawn_localhost_api(tmp_path / "ci_synthetic.db")
    try:
        health_json = _wait_for_health(proc, base_url)
        assert health_json["db_ready"] is True

        models_resp = httpx.get(f"{base_url}/api/v1/models", timeout=5.0)
        assert models_resp.status_code == 200
        models = models_resp.json()
        model_map = {m["model_key"]: m for m in models}
        assert set(model_map.keys()) == {
            "random_forest",
            "xgboost",
            "isolation_forest",
            "autoencoder",
        }
        assert model_map["autoencoder"]["ready"] is False
        assert model_map["autoencoder"]["status"] == "BLOCKED / NOT READY"

        ins_resp = httpx.post(
            f"{base_url}/api/v1/csv/inspect",
            json={"file_path": str(synth_csv), "preview_limit": 10},
            timeout=15.0,
        )
        assert ins_resp.status_code == 200
        ins = ins_resp.json()
        assert ins["row_count"] == n_rows
        assert ins["ml_feature_count"] == 47
        assert ins["ml_features_valid"] is True
        assert ins["target_columns_excluded"] == ["Label"]
        assert ins["ood_report"]["zero_ttl_count"] == 1
        assert len(ins["models_status"]) == 4

        blocked_resp = httpx.post(
            f"{base_url}/api/v1/csv/analyze",
            json={"file_path": str(synth_csv), "model_name": "autoencoder"},
            timeout=10.0,
        )
        assert blocked_resp.status_code == 503
    finally:
        _terminate_process(proc)


@pytest.mark.skipif(
    not (
        DEMO_FLOWS.is_file()
        and DEMO_LABELS.is_file()
        and RF_MODEL.is_file()
        and IF_MODEL.is_file()
        and PREP_ARTIFACT.is_file()
    ),
    reason="Offline verified model artifacts or demo CSV not present in this checkout.",
)
def test_m6_desktop_localhost_e2e_14_step_flow(tmp_path: Path):
    """Spawn real FastAPI backend via run_api.py and execute full M6 CSV E2E flow."""
    proc, base_url = _spawn_localhost_api(tmp_path / "e2e_desktop.db")
    try:
        # Step 1-2: Wait for localhost /health readiness
        health_json = _wait_for_health(proc, base_url)
        assert health_json["preprocessor_ready"] is True
        assert health_json["db_ready"] is True

        # Step 3: Verify 4-model allowlist readiness honestly
        models = httpx.get(f"{base_url}/api/v1/models", timeout=5.0).json()
        model_map = {m["model_key"]: m for m in models}
        assert model_map["random_forest"]["status"] == "READY"
        assert model_map["isolation_forest"]["status"] == "READY"
        assert model_map["xgboost"]["status"] == "BLOCKED / NOT READY"
        assert model_map["autoencoder"]["status"] == "BLOCKED / NOT READY"

        # Step 4: Blocked model must fail closed with 503
        blocked_resp = httpx.post(
            f"{base_url}/api/v1/csv/analyze",
            json={"file_path": str(DEMO_FLOWS), "model_name": "autoencoder"},
            timeout=10.0,
        )
        assert blocked_resp.status_code == 503

        # Step 5: Inspect demo_flows.csv (47 features valid, OOD MIN_TTL=0 surfaced)
        ins_resp = httpx.post(
            f"{base_url}/api/v1/csv/inspect",
            json={"file_path": str(DEMO_FLOWS), "preview_limit": 20},
            timeout=15.0,
        )
        assert ins_resp.status_code == 200
        ins = ins_resp.json()
        assert ins["row_count"] == 200
        assert ins["ml_features_valid"] is True
        assert ins["ood_report"]["zero_ttl_count"] == 2

        # Step 6-7: Run Random Forest inference
        rf_resp = httpx.post(
            f"{base_url}/api/v1/csv/analyze",
            json={"file_path": str(DEMO_FLOWS), "model_name": "random_forest", "batch_size": 100},
            timeout=30.0,
        )
        assert rf_resp.status_code == 200
        rf = rf_resp.json()
        assert rf["total_rows"] == 200
        assert rf["abstained_risk_count"] == 2
        assert rf["ood_flagged_count"] == 2
        assert rf["benign_count"] + rf["attack_count"] + rf["ood_flagged_count"] == 200
        assert rf["compatibility_gate"]["source_id"] == "source:nf-v3-canonical"
        assert rf["compatibility_gate"]["provenance_verified"] is True
        assert rf["compatibility_gate"]["compatibility_status"] == "MODEL_VALIDATED"
        assert len(rf["timeline"]) == 200

        # Step 8-9: Run Isolation Forest inference (unclamped raw scores on non-OOD, null on OOD)
        if_resp = httpx.post(
            f"{base_url}/api/v1/csv/analyze",
            json={
                "file_path": str(DEMO_FLOWS),
                "model_name": "isolation_forest",
                "batch_size": 100,
            },
            timeout=30.0,
        )
        assert if_resp.status_code == 200
        iso = if_resp.json()
        assert iso["total_rows"] == 200
        assert all(item["attack_probability"] is None for item in iso["results"])
        assert all(
            item["raw_anomaly_score"] is not None
            for item in iso["results"]
            if not item["is_ood_flagged"]
        )
        assert all(
            item["predicted_label"] is None
            and item["predicted_class"] == "ABSTAINED_OOD"
            and item["raw_anomaly_score"] is None
            for item in iso["results"]
            if item["is_ood_flagged"]
        )

        # Step 10-11: Evaluate RF predictions against separate demo_labels.csv
        ev_resp = httpx.post(
            f"{base_url}/api/v1/csv/evaluate",
            json={"labels_path": str(DEMO_LABELS), "predictions": rf["results"]},
            timeout=15.0,
        )
        assert ev_resp.status_code == 200
        ev = ev_resp.json()
        assert ev["matched_rows"] == 198
        assert ev["abstained_rows"] == 2
        assert ev["accuracy"] >= 0.99

        # Step 12-13: Export predictions CSV & metadata JSON
        export_path = tmp_path / "e2e_rf_export.csv"
        exp_resp = httpx.post(
            f"{base_url}/api/v1/csv/export",
            json={
                "output_path": str(export_path),
                "source_csv_path": str(DEMO_FLOWS),
                "model_key": "random_forest",
                "model_type": "RandomForest",
                "run_id": rf["run_id"],
                "model_sha256": rf["model_sha256"],
                "preprocessor_sha256": rf["preprocessor_sha256"],
                "results": rf["results"],
                "evaluation": ev,
            },
            timeout=15.0,
        )
        assert exp_resp.status_code == 200
        exp = exp_resp.json()
        assert Path(exp["csv_path"]).is_file()
        meta = json.loads(Path(exp["metadata_path"]).read_text(encoding="utf-8"))
        assert meta["rows_exported"] == 200
        assert meta["model_artifact_sha256"] == rf["model_sha256"]
    finally:
        _terminate_process(proc)
