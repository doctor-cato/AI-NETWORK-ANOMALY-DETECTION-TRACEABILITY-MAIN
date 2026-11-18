"""Integrity regression & 4-model real-data E2E tests for NetFlow Sentinel Stable."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from network_anomaly.api import service as service_mod
from network_anomaly.api.desktop_csv import resolve_csv_source_provenance
from network_anomaly.api.main import create_app
from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.inference.predict import InferencePipeline

DEMO_FLOWS = PROJECT_ROOT / "data" / "demo" / "demo_flows.csv"
DEMO_LABELS = PROJECT_ROOT / "data" / "demo" / "demo_labels.csv"
PREP_ARTIFACT = ARTIFACTS / "preprocessing" / "v2_flow_preprocessor.joblib"
PREP_MANIFEST = PROJECT_ROOT / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
MODEL_FILES = {
    "random_forest": (
        ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib",
        PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json",
    ),
    "xgboost": (
        ARTIFACTS / "models" / "xgboost" / "xgboost_baseline.joblib",
        PROJECT_ROOT / "reports" / "models" / "xgboost_manifest.json",
    ),
    "isolation_forest": (
        ARTIFACTS / "models" / "isolation_forest" / "isolation_forest.joblib",
        PROJECT_ROOT / "reports" / "models" / "isolation_forest_manifest.json",
    ),
    "autoencoder": (
        ARTIFACTS / "models" / "autoencoder" / "autoencoder_model.joblib",
        PROJECT_ROOT / "reports" / "models" / "autoencoder_manifest.json",
    ),
}


def _make_sample_csv(csv_path: Path, ood_hard: bool = False) -> None:
    rows: dict[str, list[object]] = {
        "row_id": [101, 102, 103],
        "timestamp_ms": [1735689601000, 1735689602000, 1735689603000],
        "source_ip": ["10.0.0.10", "10.0.0.11", "10.0.0.12"],
        "dest_ip": ["192.168.1.20", "192.168.1.21", "192.168.1.22"],
        "source_port": [51001, 51002, 51003],
        "dest_port": [443, 80, 22],
    }
    for col in ML_FEATURE_COLUMNS:
        if col == "duration_ms":
            rows[col] = [100.0, 200.0, -50.0 if ood_hard else 300.0]
        elif col == "protocol_num":
            rows[col] = [6.0, 6.0, 17.0]
        elif col in ("bytes_in_ratio", "pkts_in_ratio"):
            rows[col] = [0.33, 0.4, 1.5 if ood_hard else 0.5]
        elif col in ("has_response", "is_tcp", "is_udp"):
            rows[col] = [1.0, 1.0, 0.0]
        else:
            rows[col] = [100.0, 200.0, 300.0]
    pd.DataFrame(rows).to_csv(csv_path, index=False)


def test_missing_and_tampered_artifacts_block_fail_closed_no_rf_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Missing, tampered, or manifest-mismatched artifacts must block (503), never fallback."""
    empty_root = tmp_path / "clean_root"
    empty_art = empty_root / "artifacts"
    empty_art.mkdir(parents=True)
    (empty_root / "reports" / "models").mkdir(parents=True)
    monkeypatch.setattr(service_mod, "PROJECT_ROOT", empty_root)
    monkeypatch.setattr(service_mod, "ARTIFACTS", empty_art)

    sample_csv = tmp_path / "sample.csv"
    _make_sample_csv(sample_csv)

    with TestClient(create_app(tmp_path / "missing.db")) as client:
        models_resp = client.get("/api/v1/models")
        assert models_resp.status_code == 200
        models = {m["model_key"]: m for m in models_resp.json()}
        assert len(models) == 4
        for key in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
            assert models[key]["ready"] is False
            assert models[key]["status"] == "BLOCKED / NOT READY"
            resp = client.post(
                "/api/v1/csv/analyze",
                json={"file_path": str(sample_csv), "model_name": key},
            )
            assert resp.status_code == 503

        # Tampered artifact bytes + mismatched manifest must also fail closed without fallback
        bad_dir = empty_art / "models" / "xgboost"
        bad_dir.mkdir(parents=True)
        bad_model = bad_dir / "xgboost_baseline.joblib"
        bad_model.write_bytes(b"corrupted-not-a-joblib")
        (empty_root / "reports" / "models" / "xgboost_manifest.json").write_text(
            json.dumps({"model_sha256": "0" * 64, "model_type": "XGBoost"}),
            encoding="utf-8",
        )
        tampered_models = {m["model_key"]: m for m in client.get("/api/v1/models").json()}
        assert tampered_models["xgboost"]["ready"] is False
        assert tampered_models["xgboost"]["status"] == "BLOCKED / NOT READY"
        bad_resp = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(sample_csv), "model_name": "xgboost"},
        )
        assert bad_resp.status_code == 503


def test_source_spoofing_and_evaluation_tampering_fail_closed(tmp_path: Path):
    """Client-spoofed provenance metadata or altered ground truth summary must fail closed."""
    sample_csv = tmp_path / "spoof_unsw_v3_validation.csv"
    _make_sample_csv(sample_csv, ood_hard=True)

    # Filename masquerading as validation dataset must NOT verify as canonical provenance
    sample_sha = hashlib.sha256(sample_csv.read_bytes()).hexdigest()
    _, verified, _ = resolve_csv_source_provenance(sample_csv, file_sha256=sample_sha, row_count=3)
    assert verified is False

    with TestClient(create_app(tmp_path / "spoof.db")) as client:
        ins = client.post("/api/v1/csv/inspect", json={"file_path": str(sample_csv)})
        assert ins.status_code == 200
        ins_body = ins.json()
        # Hard OOD invariant (negative duration_ms and ratio > 1.0) must trip
        assert ins_body["ood_report"]["hard_violation_count"] >= 1

        out_csv = tmp_path / "spoofed_export.csv"
        fake_row = {
            "row_id": 101,
            "row_index": 0,
            "predicted_label": 0,
            "predicted_class": "Benign",
            "attack_probability": 0.05,
            "raw_anomaly_score": 0.05,
            "normalized_anomaly_score": 0.05,
            "decision_threshold": 0.5,
            "score_type": "attack_probability",
            "score_direction": "higher_is_more_anomalous",
            "risk_score": 5.0,
            "risk_level": "LOW",
            "is_ood_flagged": False,
            "ood_reason": None,
        }
        # Forged server analysis_id must fail closed (400), and client-only export with
        # fabricated SHA-256 digests cannot receive server_verified_* provenance.
        forged_id_resp = client.post(
            "/api/v1/csv/export",
            json={
                "output_path": str(out_csv),
                "analysis_id": "forged_analysis_id",
                "source_csv_path": str(sample_csv),
                "model_key": "xgboost",
                "model_type": "XGBoost",
                "run_id": "forged-run",
                "model_sha256": "a" * 64,
                "preprocessor_sha256": "b" * 64,
                "results": [fake_row],
            },
        )
        assert forged_id_resp.status_code == 400

        exp_resp = client.post(
            "/api/v1/csv/export",
            json={
                "output_path": str(out_csv),
                "analysis_id": None,
                "source_csv_path": str(sample_csv),
                "model_key": "xgboost",
                "model_type": "XGBoost",
                "run_id": "forged-run",
                "model_sha256": "a" * 64,
                "preprocessor_sha256": "b" * 64,
                "results": [fake_row],
            },
        )
        assert exp_resp.status_code == 200
        meta = json.loads(Path(exp_resp.json()["metadata_path"]).read_text(encoding="utf-8"))
        assert meta["provenance_verification"] == "unverified_client_supplied"


def test_threshold_leakage_manifest_invariants_when_present():
    """Verify generated XGBoost & Autoencoder manifests strictly enforce Test isolation invariants."""
    xgb_manifest_path = MODEL_FILES["xgboost"][1]
    if xgb_manifest_path.is_file():
        xgb_m = json.loads(xgb_manifest_path.read_text(encoding="utf-8"))
        assert xgb_m.get("provenance_complete") is True
        assert xgb_m.get("preprocessing_contract_id") == "v2-flow-preprocessing-v1"
        assert len(xgb_m.get("preprocessor_artifact_sha256", "")) == 64
        tp = xgb_m.get("threshold_provenance", {})
        assert tp.get("selected_on") == "validation"
        assert tp.get("test_touched") is False

    ae_manifest_path = MODEL_FILES["autoencoder"][1]
    if ae_manifest_path.is_file():
        ae_m = json.loads(ae_manifest_path.read_text(encoding="utf-8"))
        assert len(ae_m.get("model_sha256", "")) == 64
        assert ae_m.get("provenance", {}).get("calibration", {}).get("threshold_frozen") is True
        ae_cal = ae_m.get("threshold_calibration", {})
        assert ae_cal.get("threshold_frozen") is True
        assert ae_cal.get("test_touched") is False
        assert ae_cal.get("selected_on") == "validation"
        assert float(ae_cal.get("empirical_val_fpr", 1.0)) <= 0.05
        norm = ae_m.get("score_normalization", {})
        if norm:
            assert "test" not in str(norm.get("calibration_partition", "")).lower()


def test_dry_run_isolation_never_executes_system_commands_on_ood_or_attack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Issue #27 dry-run must never spawn subprocesses or recommend containment for ABSTAINED_OOD."""

    def _forbid_subprocess(*args, **kwargs):  # pragma: no cover - defensive trap
        raise AssertionError("OS subprocess execution is forbidden in Issue #27 dry-run mode.")

    monkeypatch.setattr(subprocess, "run", _forbid_subprocess)
    monkeypatch.setattr(subprocess, "Popen", _forbid_subprocess)

    with TestClient(create_app(tmp_path / "dryrun_iso.db")) as client:
        ood_flow = {
            "row_id": 77,
            "row_index": 0,
            "predicted_label": None,
            "predicted_class": "ABSTAINED_OOD",
            "attack_probability": None,
            "raw_anomaly_score": None,
            "normalized_anomaly_score": None,
            "decision_threshold": 0.5,
            "score_type": "attack_probability",
            "score_direction": "higher_is_more_anomalous",
            "risk_score": None,
            "risk_level": "ABSTAINED_OOD",
            "is_ood_flagged": True,
            "ood_reason": "MIN_TTL == 0",
        }
        high_risk_flow = {
            "row_id": 78,
            "row_index": 1,
            "predicted_label": 1,
            "predicted_class": "Attack",
            "attack_probability": 0.99,
            "raw_anomaly_score": 0.99,
            "normalized_anomaly_score": 0.99,
            "decision_threshold": 0.5,
            "score_type": "attack_probability",
            "score_direction": "higher_is_more_anomalous",
            "risk_score": 99.0,
            "risk_level": "CRITICAL",
            "is_ood_flagged": False,
            "ood_reason": None,
        }
        resp = client.post(
            "/api/v1/security/simulate-response",
            json={
                "results": [ood_flow, high_risk_flow],
                "model_key": "xgboost",
                "triggered_by": "integrity_audit",
                "dry_run": True,
            },
        )
        assert resp.status_code == 200, resp.text
        sim = resp.json()
        assert sim["executed"] is False
        assert sim["os_firewall_touched"] is False
        assert sim["real_key_rotated"] is False
        assert sim["provenance_verification"] == "client_supplied_unverified"
        by_row = {int(r["row_id"]): r for r in sim["recommendations"]}
        assert by_row[77]["action"] in {"MONITOR", "INVESTIGATE", "NO_ACTION"}
        assert by_row[77]["action"] != "ISOLATE_RECOMMENDED"
        assert by_row[77]["containment_allowed"] is False
        assert by_row[78]["action"] == "INVESTIGATE"
        assert by_row[78]["containment_allowed"] is False
        assert sim["key_rotation_simulation"]["decision"] == "HOLD_UNVERIFIED_PROVENANCE"
        assert sim["key_rotation_simulation"]["recommended"] is False


@pytest.mark.skipif(
    not (
        DEMO_FLOWS.is_file()
        and DEMO_LABELS.is_file()
        and PREP_ARTIFACT.is_file()
        and all(p.is_file() for p, _ in MODEL_FILES.values())
    ),
    reason="Full 4-model local verified artifacts or demo CSV not present in this checkout.",
)
def test_all_four_verified_models_real_demo_csv_parity_and_eval(tmp_path: Path):
    """Run all 4 verified models on real Validation demo_flows.csv and verify strict semantics."""
    demo_df = pd.read_csv(DEMO_FLOWS)
    expected_row_ids = demo_df["row_id"].tolist()

    with TestClient(create_app(tmp_path / "four_models.db")) as client:
        models_resp = client.get("/api/v1/models")
        assert models_resp.status_code == 200
        models = {m["model_key"]: m for m in models_resp.json()}
        assert len(models) == 4
        for key in MODEL_FILES:
            assert models[key]["ready"] is True
            assert models[key]["status"] == "READY"
            assert len(models[key]["artifact_sha256"] or "") == 64

        for key, (model_path, manifest_path) in MODEL_FILES.items():
            az_resp = client.post(
                "/api/v1/csv/analyze",
                json={
                    "file_path": str(DEMO_FLOWS),
                    "model_name": key,
                    "batch_size": 100,
                    "create_incidents": False,
                },
            )
            assert az_resp.status_code == 200, f"{key}: {az_resp.text}"
            az = az_resp.json()
            assert az["inference_mode"] == "verified_model"
            assert az["total_rows"] == 200
            assert az["evaluated_rows"] == 200
            assert az["abstained_rows"] == 0
            assert az["prediction_coverage"] == 1.0
            assert [r["row_id"] for r in az["results"]] == expected_row_ids

            non_ood = [r for r in az["results"] if not r["is_ood_flagged"]]
            ood_rows = [r for r in az["results"] if r["is_ood_flagged"]]
            assert len(non_ood) == 200
            assert len(ood_rows) == 0
            assert all(
                r["predicted_label"] is None
                and r["predicted_class"] == "ABSTAINED_OOD"
                and r["attack_probability"] is None
                and r["raw_anomaly_score"] is None
                and r["normalized_anomaly_score"] is None
                and r["risk_score"] is None
                for r in ood_rows
            )

            if key in ("random_forest", "xgboost"):
                assert all(
                    r["attack_probability"] is not None
                    and r["normalized_anomaly_score"] is not None
                    and abs(r["attack_probability"] - r["normalized_anomaly_score"]) <= 1e-9
                    for r in non_ood
                )
            else:
                assert all(r["attack_probability"] is None for r in az["results"])
                assert all(
                    r["raw_anomaly_score"] is not None
                    and r["normalized_anomaly_score"] is not None
                    and 0.0 <= r["normalized_anomaly_score"] <= 1.0
                    for r in non_ood
                )

            pipe = InferencePipeline.from_artifacts(
                model_artifact_path=model_path,
                preprocessor_artifact_path=PREP_ARTIFACT,
                model_manifest_path=manifest_path if manifest_path.is_file() else None,
                preprocessor_manifest_path=PREP_MANIFEST,
            )
            cli_df = pipe.predict(demo_df)
            indices = [r["row_index"] for r in non_ood]
            assert [r["predicted_label"] for r in non_ood] == cli_df.iloc[indices][
                "prediction"
            ].astype(int).tolist()
            if key in ("random_forest", "xgboost"):
                assert np.allclose(
                    [r["attack_probability"] for r in non_ood],
                    cli_df.iloc[indices]["probability_Attack"].to_numpy(dtype=float),
                    atol=1e-7,
                )
            else:
                assert np.allclose(
                    [r["raw_anomaly_score"] for r in non_ood],
                    cli_df.iloc[indices]["anomaly_score"].to_numpy(dtype=float),
                    atol=1e-7,
                )

            ev_resp = client.post(
                "/api/v1/csv/evaluate",
                json={"labels_path": str(DEMO_LABELS), "predictions": az["results"]},
            )
            assert ev_resp.status_code == 200, ev_resp.text
            ev = ev_resp.json()
            cm = ev["confusion_matrix"]
            assert cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"] == 200
            assert ev["abstained_rows"] == 0
            assert ev["prediction_coverage"] == 1.0

            sim_resp = client.post(
                "/api/v1/security/simulate-response",
                json={"analysis_id": az["analysis_id"], "dry_run": True},
            )
            assert sim_resp.status_code == 200, sim_resp.text
            sim_body = sim_resp.json()
            assert sim_body["executed"] is False
            assert sim_body["provenance_verification"] == "server_verified_analysis"
            ood_row_ids = {int(r["row_id"]) for r in ood_rows}
            for rec in sim_body["recommendations"]:
                if int(rec["row_id"]) in ood_row_ids:
                    assert rec["containment_allowed"] is False
                    assert rec["action"] != "ISOLATE_RECOMMENDED"
            if key == "random_forest":
                assert az["compatibility_gate"]["compatibility_status"] == "MODEL_VALIDATED"
                assert sim_body["action_counts"]["ISOLATE_RECOMMENDED"] > 0
                assert (
                    sim_body["key_rotation_simulation"]["decision"]
                    == "SIMULATED_ROTATION_RECOMMENDED"
                )
            else:
                assert az["compatibility_gate"]["compatibility_status"] == "RESEARCH_ONLY"
                assert sim_body["action_counts"]["ISOLATE_RECOMMENDED"] == 0
                assert sim_body["key_rotation_simulation"]["decision"] == "HOLD_RESEARCH_ONLY_MODEL"
                assert sim_body["key_rotation_simulation"]["recommended"] is False
