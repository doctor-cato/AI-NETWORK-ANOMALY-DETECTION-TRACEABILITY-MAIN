"""Unit and integration contract tests for Desktop CSV endpoints and M6 scoped features."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.desktop_csv import (
    build_deterministic_evidence_timeline,
    compute_deterministic_risk_score,
    compute_netflow_behavioral_summary,
    validate_safe_csv_path,
    validate_safe_export_path,
)
from network_anomaly.api.main import create_app
from network_anomaly.api.schemas import CompatibilityGateSummarySchema, CsvFlowPredictionItem
from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.inference.predict import InferencePipeline

DEMO_FLOWS = PROJECT_ROOT / "data" / "demo" / "demo_flows.csv"
DEMO_LABELS = PROJECT_ROOT / "data" / "demo" / "demo_labels.csv"
RF_MODEL = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
IF_MODEL = ARTIFACTS / "models" / "isolation_forest" / "isolation_forest.joblib"
PREP_ARTIFACT = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"


def _make_synthetic_flow_df(n_rows: int = 4) -> pd.DataFrame:
    data: dict[str, list[object]] = {
        "row_id": [100 + i for i in range(n_rows)],
        "FLOW_START_MILLISECONDS": [
            1_700_000_005_000,
            1_700_000_001_000,
            1_700_000_003_000,
            1_700_000_001_000,
        ][:n_rows],
        "FLOW_END_MILLISECONDS": [
            1_700_000_005_500,
            1_700_000_001_500,
            1_700_000_003_500,
            1_700_000_001_500,
        ][:n_rows],
        "IPV4_SRC_ADDR": ["10.0.0.2", "10.0.0.1", "10.0.0.2", "10.0.0.3"][:n_rows],
        "IPV4_DST_ADDR": ["192.168.1.10"] * n_rows,
        "L4_SRC_PORT": [50000 + i for i in range(n_rows)],
        "L4_DST_PORT": [443, 80, 443, 22][:n_rows],
    }
    for col in ML_FEATURE_COLUMNS:
        if col == "MIN_TTL":
            data[col] = [62.0, 0.0, 62.0, 254.0][:n_rows]
        elif col == "MAX_TTL":
            data[col] = [62.0, 0.0, 62.0, 254.0][:n_rows]
        elif col == "LONGEST_FLOW_PKT":
            data[col] = [512.0] * n_rows
        elif col == "SHORTEST_FLOW_PKT":
            data[col] = [64.0] * n_rows
        elif col == "MAX_IP_PKT_LEN":
            data[col] = [512.0] * n_rows
        elif col == "MIN_IP_PKT_LEN":
            data[col] = [64.0] * n_rows
        else:
            data[col] = [1.0 + i for i in range(n_rows)]
    return pd.DataFrame(data)


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(db_path=tmp_path / "desktop_csv_test.db")
    with TestClient(app, raise_server_exceptions=False) as tc:
        yield tc


def test_path_security_validation_rejects_bad_paths_and_overwrite(tmp_path: Path):
    txt_file = tmp_path / "bad.txt"
    txt_file.write_text("hello", encoding="utf-8")
    with pytest.raises(ValueError, match=".csv"):
        validate_safe_csv_path(str(txt_file))

    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        validate_safe_csv_path(str(empty_csv))

    valid_csv = tmp_path / "valid.csv"
    valid_csv.write_text("a,b\n1,2\n", encoding="utf-8")
    resolved = validate_safe_csv_path(str(valid_csv))
    assert resolved == valid_csv.resolve()

    with pytest.raises(ValueError, match="overwrite"):
        validate_safe_export_path(str(valid_csv), source_csv_path=str(valid_csv))


def test_deterministic_risk_score_contract_and_ood_abstention():
    # Supervised bounded probability
    score_rf, tier_rf = compute_deterministic_risk_score(
        is_ood_flagged=False,
        score_type="attack_probability",
        score_direction="higher_is_more_anomalous",
        attack_probability=0.91,
        raw_anomaly_score=None,
        decision_threshold=0.5,
    )
    assert score_rf == 91.0
    assert tier_rf == "CRITICAL"

    # Unsupervised IF lower_is_more_anomalous
    score_if_attack, tier_if_attack = compute_deterministic_risk_score(
        is_ood_flagged=False,
        score_type="anomaly_score_unsupervised",
        score_direction="lower_is_more_anomalous",
        attack_probability=None,
        raw_anomaly_score=-0.10,
        decision_threshold=-0.0335,
    )
    score_if_benign, _ = compute_deterministic_risk_score(
        is_ood_flagged=False,
        score_type="anomaly_score_unsupervised",
        score_direction="lower_is_more_anomalous",
        attack_probability=None,
        raw_anomaly_score=0.08,
        decision_threshold=-0.0335,
    )
    assert score_if_attack is not None and score_if_benign is not None
    assert score_if_attack > 50.0 > score_if_benign

    # OOD abstention MUST yield None and ABSTAINED_OOD
    abstained_score, abstained_tier = compute_deterministic_risk_score(
        is_ood_flagged=True,
        score_type="attack_probability",
        score_direction="higher_is_more_anomalous",
        attack_probability=0.99,
        raw_anomaly_score=None,
        decision_threshold=0.5,
    )
    assert abstained_score is None
    assert abstained_tier == "ABSTAINED_OOD"

    # Non-finite input must fail closed
    with pytest.raises(ValueError, match="Non-finite"):
        compute_deterministic_risk_score(
            is_ood_flagged=False,
            score_type="attack_probability",
            score_direction="higher_is_more_anomalous",
            attack_probability=float("nan"),
            raw_anomaly_score=None,
            decision_threshold=0.5,
        )


def test_behavioral_summary_and_deterministic_timeline_ordering():
    df = _make_synthetic_flow_df(4)
    summary = compute_netflow_behavioral_summary(df)
    assert summary.total_flows == 4
    assert summary.unique_src_ips == 3
    assert summary.top_src_ips[0].key == "10.0.0.2"
    assert summary.top_src_ips[0].count == 2
    assert "IPV4_SRC_ADDR" in summary.excluded_from_ml_features
    assert "do not attribute" in summary.non_attribution_notice

    items = [
        CsvFlowPredictionItem(
            row_id=row["row_id"],
            row_index=idx,
            predicted_label=1 if idx % 2 == 0 else 0,
            predicted_class="Attack" if idx % 2 == 0 else "Benign",
            score_type="attack_probability",
            score_direction="higher_is_more_anomalous",
            attack_probability=0.8 if idx % 2 == 0 else 0.1,
            risk_score=None if idx == 1 else (80.0 if idx % 2 == 0 else 10.0),
            risk_level="ABSTAINED_OOD" if idx == 1 else ("CRITICAL" if idx % 2 == 0 else "LOW"),
            is_ood_flagged=(idx == 1),
            flow_start_ms=int(row["FLOW_START_MILLISECONDS"]),
            src_ip=str(row["IPV4_SRC_ADDR"]),
            dst_ip=str(row["IPV4_DST_ADDR"]),
        )
        for idx, row in df.iterrows()
    ]
    tl_first = build_deterministic_evidence_timeline(items)
    tl_second = build_deterministic_evidence_timeline(list(reversed(items)))
    assert [(x.flow_start_ms, x.row_id) for x in tl_first] == [
        (1_700_000_001_000, 101),
        (1_700_000_001_000, 103),
        (1_700_000_003_000, 102),
        (1_700_000_005_000, 100),
    ]
    assert tl_first == tl_second


def test_csv_inspect_evaluate_and_export_endpoints(client: TestClient, tmp_path: Path):
    df = _make_synthetic_flow_df(4)
    # Add Label and Attack to verify strict leakage exclusion from ML contract
    df["Label"] = [1, 0, 1, 0]
    df["Attack"] = ["Exploits", "Benign", "Exploits", "Benign"]
    flows_csv = tmp_path / "flows.csv"
    df.to_csv(flows_csv, index=False)

    labels_csv = tmp_path / "labels.csv"
    df[["row_id", "Label", "Attack"]].to_csv(labels_csv, index=False)

    inspect_resp = client.post(
        "/api/v1/csv/inspect",
        json={"file_path": str(flows_csv), "preview_limit": 10},
    )
    assert inspect_resp.status_code == 200, inspect_resp.text
    ins = inspect_resp.json()
    assert ins["ml_features_valid"] is True
    assert ins["ml_feature_count"] == 47
    assert set(ins["target_columns_excluded"]) == {"Label", "Attack"}
    assert ins["ood_report"]["zero_ttl_count"] == 1
    assert len(ins["models_status"]) == 4

    # Synthetic verified pipeline for unit-level analyze/evaluate/export verification in CI
    class _FakePrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    fake_pipeline = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-unit-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_FakePrep(),
        predict=lambda frame: pd.DataFrame(
            {
                "prediction": [1, 0, 1, 0][: len(frame)],
                "probability_Attack": [0.92, 0.08, 0.85, 0.12][: len(frame)],
                "probability_Benign": [0.08, 0.92, 0.15, 0.88][: len(frame)],
                "run_id": ["rf-unit-test"] * len(frame),
            }
        ),
    )

    svc = client.app.state.service
    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipeline),
        patch(
            "network_anomaly.api.desktop_csv._evaluate_gate",
            return_value=(
                CompatibilityGateSummarySchema(
                    model_key="random_forest",
                    model_identifier="rf-unit-test",
                    eligible=True,
                    eligibility_status="ELIGIBLE",
                    compatibility_status="MODEL_VALIDATED",
                    reasons=[],
                    warnings=[],
                    missing_features=[],
                ),
                True,
            ),
        ),
    ):
        analyze_resp = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(flows_csv), "model_name": "random_forest", "batch_size": 2},
        )
    assert analyze_resp.status_code == 200, analyze_resp.text
    az = analyze_resp.json()
    assert az["total_rows"] == 4
    # row 1 had MIN_TTL=0 so OOD-flagged and risk abstained
    assert az["ood_flagged_count"] == 1
    assert az["abstained_risk_count"] == 1
    assert az["results"][1]["risk_score"] is None
    assert az["results"][1]["risk_level"] == "ABSTAINED_OOD"
    assert az["results"][0]["risk_score"] == 92.0
    assert len(az["timeline"]) == 4

    eval_resp = client.post(
        "/api/v1/csv/evaluate",
        json={"labels_path": str(labels_csv), "predictions": az["results"]},
    )
    assert eval_resp.status_code == 200, eval_resp.text
    ev = eval_resp.json()
    assert ev["matched_rows"] == 4
    assert ev["accuracy"] == 1.0
    assert ev["confusion_matrix"] == {"tn": 2, "fp": 0, "fn": 0, "tp": 2}

    export_csv = tmp_path / "exported_preds.csv"
    exp_resp = client.post(
        "/api/v1/csv/export",
        json={
            "output_path": str(export_csv),
            "source_csv_path": str(flows_csv),
            "model_key": "random_forest",
            "model_type": "RandomForest",
            "run_id": az["run_id"],
            "model_sha256": az["model_sha256"],
            "preprocessor_sha256": az["preprocessor_sha256"],
            "results": az["results"],
            "evaluation": ev,
        },
    )
    assert exp_resp.status_code == 200, exp_resp.text
    exp = exp_resp.json()
    assert Path(exp["csv_path"]).is_file()
    assert Path(exp["metadata_path"]).is_file()
    meta_json = json.loads(Path(exp["metadata_path"]).read_text(encoding="utf-8"))
    assert meta_json["rows_exported"] == 4
    assert meta_json["evaluation_summary"]["f1"] == 1.0


def test_db_path_reads_env_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    custom_db = tmp_path / "env_override.db"
    monkeypatch.setenv("NETWORK_ANOMALY_DB_PATH", str(custom_db))
    db = DatabaseManager()
    assert Path(db.db_path) == custom_db
    assert db.is_healthy()


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
def test_live_demo_csv_rf_and_if_cli_parity_and_blocked_models(client: TestClient, tmp_path: Path):
    models_resp = client.get("/api/v1/models")
    assert models_resp.status_code == 200
    models_map = {m["model_key"]: m for m in models_resp.json()}
    assert models_map["random_forest"]["status"] == "READY"
    assert models_map["isolation_forest"]["status"] == "READY"
    assert models_map["xgboost"]["status"] == "BLOCKED / NOT READY"
    assert models_map["autoencoder"]["status"] == "BLOCKED / NOT READY"

    # Unready model must fail closed with HTTP 503
    blocked_resp = client.post(
        "/api/v1/csv/analyze",
        json={"file_path": str(DEMO_FLOWS), "model_name": "xgboost"},
    )
    assert blocked_resp.status_code == 503

    demo_df = pd.read_csv(DEMO_FLOWS)

    # 1. Random Forest endpoint vs InferencePipeline CLI parity
    rf_resp = client.post(
        "/api/v1/csv/analyze",
        json={"file_path": str(DEMO_FLOWS), "model_name": "random_forest", "batch_size": 100},
    )
    assert rf_resp.status_code == 200, rf_resp.text
    rf_data = rf_resp.json()
    assert rf_data["total_rows"] == 200
    assert rf_data["ood_report"]["zero_ttl_count"] == 2

    rf_pipe = InferencePipeline.from_artifacts(
        model_artifact_path=RF_MODEL,
        preprocessor_artifact_path=PREP_ARTIFACT,
        model_manifest_path=PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json",
        preprocessor_manifest_path=PROJECT_ROOT
        / "reports"
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessing_manifest.json",
    )
    rf_cli_df = rf_pipe.predict(demo_df)
    assert [r["predicted_label"] for r in rf_data["results"]] == rf_cli_df["prediction"].astype(
        int
    ).tolist()
    assert np.allclose(
        [r["attack_probability"] for r in rf_data["results"]],
        rf_cli_df["probability_Attack"].to_numpy(dtype=float),
        atol=1e-9,
    )

    # 2. Isolation Forest endpoint vs InferencePipeline CLI parity + null attack_probability
    if_resp = client.post(
        "/api/v1/csv/analyze",
        json={"file_path": str(DEMO_FLOWS), "model_name": "isolation_forest", "batch_size": 100},
    )
    assert if_resp.status_code == 200, if_resp.text
    if_data = if_resp.json()
    assert if_data["total_rows"] == 200
    assert all(r["attack_probability"] is None for r in if_data["results"])
    assert all(r["raw_anomaly_score"] is not None for r in if_data["results"])

    if_pipe = InferencePipeline.from_artifacts(
        model_artifact_path=IF_MODEL,
        preprocessor_artifact_path=PREP_ARTIFACT,
        model_manifest_path=PROJECT_ROOT / "reports" / "models" / "isolation_forest_manifest.json",
        preprocessor_manifest_path=PROJECT_ROOT
        / "reports"
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessing_manifest.json",
    )
    if_cli_df = if_pipe.predict(demo_df)
    assert [r["predicted_label"] for r in if_data["results"]] == if_cli_df["prediction"].astype(
        int
    ).tolist()
    assert np.allclose(
        [r["raw_anomaly_score"] for r in if_data["results"]],
        if_cli_df["anomaly_score"].to_numpy(dtype=float),
        atol=1e-9,
    )

    # 3. Ground truth evaluation on demo_labels.csv
    eval_rf = client.post(
        "/api/v1/csv/evaluate",
        json={"labels_path": str(DEMO_LABELS), "predictions": rf_data["results"]},
    )
    assert eval_rf.status_code == 200
    assert eval_rf.json()["matched_rows"] == 200
    assert len(eval_rf.json()["attack_breakdown"]) >= 1

    # 4. Export verification
    out_csv = tmp_path / "demo_export.csv"
    exp_resp = client.post(
        "/api/v1/csv/export",
        json={
            "output_path": str(out_csv),
            "source_csv_path": str(DEMO_FLOWS),
            "model_key": "random_forest",
            "model_type": "RandomForest",
            "run_id": rf_data["run_id"],
            "model_sha256": rf_data["model_sha256"],
            "preprocessor_sha256": rf_data["preprocessor_sha256"],
            "results": rf_data["results"],
            "evaluation": eval_rf.json(),
        },
    )
    assert exp_resp.status_code == 200
    assert Path(exp_resp.json()["csv_path"]).is_file()
    assert Path(exp_resp.json()["metadata_path"]).is_file()


def test_desktop_csv_hardening_regressions(client: TestClient, tmp_path: Path):
    # 1. Inspect missing ML feature must return ml_features_valid=False instead of HTTP 400
    partial_df = _make_synthetic_flow_df(2).drop(columns=["PROTOCOL", "L7_PROTO"])
    partial_csv = tmp_path / "partial.csv"
    partial_df.to_csv(partial_csv, index=False)
    ins_partial = client.post("/api/v1/csv/inspect", json={"file_path": str(partial_csv)})
    assert ins_partial.status_code == 200, ins_partial.text
    body = ins_partial.json()
    assert body["ml_features_valid"] is False
    assert set(body["missing_ml_features"]) == {"PROTOCOL", "L7_PROTO"}

    # 2. Non-finite count includes NaN + Inf + missing string tokens
    nf_df = _make_synthetic_flow_df(2)
    nf_df[ML_FEATURE_COLUMNS[0]] = [np.inf, -np.inf]
    nf_df[ML_FEATURE_COLUMNS[1]] = ["null", "1.5"]
    nf_csv = tmp_path / "nonfinite.csv"
    nf_df.to_csv(nf_csv, index=False)
    ins_nf = client.post("/api/v1/csv/inspect", json={"file_path": str(nf_csv)})
    assert ins_nf.status_code == 200, ins_nf.text
    assert ins_nf.json()["non_finite_feature_cells"] == 3

    # 3. Timeline tie-break sorts numeric row_id cleanly (9 < 20 < 100)
    tl_items = [
        CsvFlowPredictionItem(
            row_id=rid,
            row_index=i,
            predicted_label=0,
            predicted_class="Benign",
            score_type="attack_probability",
            score_direction="higher_is_more_anomalous",
            attack_probability=0.1,
            risk_score=10.0,
            risk_level="LOW",
            is_ood_flagged=False,
            flow_start_ms=1_700_000_000_000,
        )
        for i, rid in enumerate([100, 9, 20])
    ]
    ordered = build_deterministic_evidence_timeline(tl_items)
    assert [x.row_id for x in ordered] == [9, 20, 100]

    # 4. Demo CSV non_finite count includes both NaN and Inf (30 NaN + 38 Inf = 68)
    if DEMO_FLOWS.is_file():
        demo_ins = client.post("/api/v1/csv/inspect", json={"file_path": str(DEMO_FLOWS)})
        assert demo_ins.status_code == 200
        assert demo_ins.json()["non_finite_feature_cells"] == 68
