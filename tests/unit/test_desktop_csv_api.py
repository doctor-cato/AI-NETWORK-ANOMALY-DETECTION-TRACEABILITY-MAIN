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
    CANONICAL_NF_UNSW_NB15_V3_SHA256,
    CANONICAL_SPLIT_MANIFEST_PATH,
    CANONICAL_SPLIT_MANIFEST_SHA256,
    CANONICAL_VALIDATION_TIME_START_MS,
    TRUSTED_CANONICAL_VALIDATION_SUBSETS,
    build_deterministic_evidence_timeline,
    compute_deterministic_risk_score,
    compute_netflow_behavioral_summary,
    resolve_csv_source_provenance,
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
XGB_MODEL = ARTIFACTS / "models" / "xgboost" / "xgboost_baseline.joblib"
IF_MODEL = ARTIFACTS / "models" / "isolation_forest" / "isolation_forest.joblib"
AE_MODEL = ARTIFACTS / "models" / "autoencoder" / "autoencoder_model.joblib"
PREP_ARTIFACT = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"


def _repeat_slice(values: list[object], n_rows: int) -> list[object]:
    return (values * ((n_rows // len(values)) + 1))[:n_rows]


def _make_synthetic_flow_df(n_rows: int = 4) -> pd.DataFrame:
    data: dict[str, list[object]] = {
        "row_id": [100 + i for i in range(n_rows)],
        "FLOW_START_MILLISECONDS": _repeat_slice(
            [
                1_700_000_005_000,
                1_700_000_001_000,
                1_700_000_003_000,
                1_700_000_001_000,
            ],
            n_rows,
        ),
        "FLOW_END_MILLISECONDS": _repeat_slice(
            [
                1_700_000_005_500,
                1_700_000_001_500,
                1_700_000_003_500,
                1_700_000_001_500,
            ],
            n_rows,
        ),
        "IPV4_SRC_ADDR": _repeat_slice(["10.0.0.2", "10.0.0.1", "10.0.0.2", "10.0.0.3"], n_rows),
        "IPV4_DST_ADDR": ["192.168.1.10"] * n_rows,
        "L4_SRC_PORT": [50000 + i for i in range(n_rows)],
        "L4_DST_PORT": _repeat_slice([443, 80, 443, 22], n_rows),
    }
    for col in ML_FEATURE_COLUMNS:
        if col == "MIN_TTL":
            data[col] = _repeat_slice([62.0, 0.0, 62.0, 254.0], n_rows)
        elif col == "MAX_TTL":
            data[col] = _repeat_slice([62.0, 0.0, 62.0, 254.0], n_rows)
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
    assert ins["ood_report"]["hard_violation_count"] == 0
    assert ins["ood_report"]["affected_rows_count"] == 1
    assert ins["ood_report"]["abstention_rate"] == 0.25
    assert ins["ood_report"]["prediction_coverage"] == 0.75
    assert len(ins["models_status"]) == 4

    # Synthetic verified pipeline for unit-level analyze/evaluate/export verification in CI
    class _FakePrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    def _feature_driven_predict(frame: pd.DataFrame) -> pd.DataFrame:
        # Row 0 (IN_BYTES=1.0) and row 2 (IN_BYTES=3.0) -> Attack; row 3 (IN_BYTES=4.0) -> Benign.
        # Row 1 (MIN_TTL=0.0) must NEVER reach this predict function.
        assert (frame["MIN_TTL"] != 0.0).all(), "OOD MIN_TTL==0 row leaked into predict()"
        preds = [1 if float(v) in {1.0, 3.0} else 0 for v in frame["IN_BYTES"].tolist()]
        p_att = [0.92 if p == 1 else 0.12 for p in preds]
        return pd.DataFrame(
            {
                "prediction": preds,
                "probability_Attack": p_att,
                "probability_Benign": [round(1.0 - p, 4) for p in p_att],
                "run_id": ["rf-unit-test"] * len(frame),
            }
        )

    fake_pipeline = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-unit-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_FakePrep(),
        predict=_feature_driven_predict,
    )

    svc = client.app.state.service
    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipeline),
        patch.object(svc, "analyze_flows", wraps=svc.analyze_flows) as spy_analyze,
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
    # Exactly 3 accepted rows (idx 0, 2, 3) sent across batch_size=2 -> [2 rows, 1 row]
    sent_events = [evt for call in spy_analyze.call_args_list for evt in call.args[0]]
    assert len(sent_events) == 3
    az = analyze_resp.json()
    assert az["total_rows"] == 4
    assert az["evaluated_rows"] == 3
    assert az["abstained_rows"] == 1
    assert az["prediction_coverage"] == 0.75
    # row 1 had MIN_TTL=0 so OOD-flagged and both inference & risk are abstained
    assert az["ood_flagged_count"] == 1
    assert az["abstained_risk_count"] == 1
    assert az["attack_count"] == 2
    assert az["benign_count"] == 1
    assert az["results"][1]["predicted_label"] is None
    assert az["results"][1]["predicted_class"] == "ABSTAINED_OOD"
    assert az["results"][1]["attack_probability"] is None
    assert az["results"][1]["raw_anomaly_score"] is None
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
    # OOD-abstained row (index 1) is excluded from confusion matrix and reported in abstained_rows
    assert ev["matched_rows"] == 3
    assert ev["evaluated_rows"] == 3
    assert ev["abstained_rows"] == 1
    assert ev["prediction_coverage"] == 0.75
    assert ev["unmatched_rows"] == 0
    assert ev["accuracy"] == 1.0
    assert ev["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 0, "tp": 2}

    export_csv = tmp_path / "exported_preds.csv"
    exp_resp = client.post(
        "/api/v1/csv/export",
        json={
            "output_path": str(export_csv),
            "analysis_id": az["analysis_id"],
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
    assert meta_json["evaluation_verification"] == "server_verified_evaluation"
    assert meta_json["provenance_verification"] == "server_verified_analysis"
    assert meta_json["analysis_id"] == az["analysis_id"]
    assert len(meta_json["source_csv_sha256"]) == 64


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
    if XGB_MODEL.is_file():
        assert models_map["xgboost"]["status"] == "READY"
    else:
        assert models_map["xgboost"]["status"] == "BLOCKED / NOT READY"
        blocked_resp = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(DEMO_FLOWS), "model_name": "xgboost"},
        )
        assert blocked_resp.status_code == 503
    if AE_MODEL.is_file():
        assert models_map["autoencoder"]["status"] == "READY"
    else:
        assert models_map["autoencoder"]["status"] == "BLOCKED / NOT READY"
        blocked_ae = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(DEMO_FLOWS), "model_name": "autoencoder"},
        )
        assert blocked_ae.status_code == 503

    demo_df = pd.read_csv(DEMO_FLOWS)

    # 1. Random Forest endpoint vs InferencePipeline CLI parity (non-OOD rows) + OOD abstention
    rf_resp = client.post(
        "/api/v1/csv/analyze",
        json={"file_path": str(DEMO_FLOWS), "model_name": "random_forest", "batch_size": 100},
    )
    assert rf_resp.status_code == 200, rf_resp.text
    rf_data = rf_resp.json()
    assert rf_data["total_rows"] == 200
    assert rf_data["ood_report"]["zero_ttl_count"] == 2
    assert rf_data["ood_report"]["hard_violation_count"] == 0
    assert rf_data["ood_report"]["affected_rows_count"] == 2
    assert rf_data["ood_report"]["prediction_coverage"] == 0.99
    assert rf_data["abstained_rows"] == 2
    assert rf_data["evaluated_rows"] == 198
    assert rf_data["prediction_coverage"] == 0.99
    assert rf_data["compatibility_gate"]["source_id"] == "source:nf-v3-canonical"
    assert rf_data["compatibility_gate"]["provenance_verified"] is True
    assert rf_data["compatibility_gate"]["compatibility_status"] == "MODEL_VALIDATED"
    assert rf_data["compatibility_gate"]["eligibility_status"] == "PREDICTION_AVAILABLE"
    assert (
        rf_data["benign_count"] + rf_data["attack_count"] + rf_data["ood_flagged_count"]
        == rf_data["total_rows"]
    )

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
    non_ood_rf = [r for r in rf_data["results"] if not r["is_ood_flagged"]]
    ood_rf = [r for r in rf_data["results"] if r["is_ood_flagged"]]
    assert len(non_ood_rf) == 198
    assert len(ood_rf) == 2
    assert all(
        r["predicted_label"] is None
        and r["predicted_class"] == "ABSTAINED_OOD"
        and r["attack_probability"] is None
        and r["raw_anomaly_score"] is None
        and r["risk_score"] is None
        and r["risk_level"] == "ABSTAINED_OOD"
        for r in ood_rf
    )
    non_ood_indices = [r["row_index"] for r in non_ood_rf]
    assert [r["predicted_label"] for r in non_ood_rf] == rf_cli_df.iloc[non_ood_indices][
        "prediction"
    ].astype(int).tolist()
    assert np.allclose(
        [r["attack_probability"] for r in non_ood_rf],
        rf_cli_df.iloc[non_ood_indices]["probability_Attack"].to_numpy(dtype=float),
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
    non_ood_if = [r for r in if_data["results"] if not r["is_ood_flagged"]]
    ood_if = [r for r in if_data["results"] if r["is_ood_flagged"]]
    assert len(non_ood_if) == 198
    assert len(ood_if) == 2
    assert all(r["attack_probability"] is None for r in if_data["results"])
    assert all(r["raw_anomaly_score"] is not None for r in non_ood_if)
    assert all(
        r["predicted_label"] is None
        and r["predicted_class"] == "ABSTAINED_OOD"
        and r["raw_anomaly_score"] is None
        and r["risk_score"] is None
        for r in ood_if
    )

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
    assert [r["predicted_label"] for r in non_ood_if] == if_cli_df.iloc[non_ood_indices][
        "prediction"
    ].astype(int).tolist()
    assert np.allclose(
        [r["raw_anomaly_score"] for r in non_ood_if],
        if_cli_df.iloc[non_ood_indices]["anomaly_score"].to_numpy(dtype=float),
        atol=1e-9,
    )

    # 3. Ground truth evaluation on demo_labels.csv (198 evaluated, 2 OOD abstained)
    eval_rf = client.post(
        "/api/v1/csv/evaluate",
        json={"labels_path": str(DEMO_LABELS), "predictions": rf_data["results"]},
    )
    assert eval_rf.status_code == 200
    assert eval_rf.json()["matched_rows"] == 198
    assert eval_rf.json()["abstained_rows"] == 2
    assert eval_rf.json()["unmatched_rows"] == 0
    assert len(eval_rf.json()["attack_breakdown"]) >= 1

    # 4. Export verification
    out_csv = tmp_path / "demo_export.csv"
    exp_resp = client.post(
        "/api/v1/csv/export",
        json={
            "output_path": str(out_csv),
            "analysis_id": rf_data["analysis_id"],
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
    demo_meta = json.loads(Path(exp_resp.json()["metadata_path"]).read_text(encoding="utf-8"))
    assert demo_meta["provenance_verification"] == "server_verified_analysis"
    assert demo_meta["evaluation_verification"] == "server_verified_evaluation"
    assert len(demo_meta["source_csv_sha256"]) == 64


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


def _build_demo_manifest_dict(
    *,
    csv_path: Path,
    csv_sha256: str,
    df: pd.DataFrame,
    partition: str = "validation",
    train_overlap: int = 0,
    test_overlap: int = 0,
    dataset_name: str = "NF-UNSW-NB15-v3",
    source_dataset_sha256: str = CANONICAL_NF_UNSW_NB15_V3_SHA256,
    split_manifest_sha256: str = CANONICAL_SPLIT_MANIFEST_SHA256,
) -> dict:
    import hashlib

    row_indices = [int(x) for x in df["row_id"].tolist()]
    idx_sha = hashlib.sha256(
        ("\n".join(str(i) for i in row_indices) + "\n").encode("utf-8")
    ).hexdigest()
    split_obj = json.loads(CANONICAL_SPLIT_MANIFEST_PATH.read_text(encoding="utf-8"))
    parts = split_obj["partitions"]
    return {
        "schema_version": "1.0",
        "dataset_name": dataset_name,
        "source_dataset_sha256": source_dataset_sha256,
        "split_manifest_sha256": split_manifest_sha256,
        "partition_indices_sha256": {
            "train": parts["train"]["index_sha256"],
            "validation": parts["validation"]["index_sha256"],
            "test": parts["test"]["index_sha256"],
        },
        "sampling": {
            "partition": partition,
            "sample_rows": len(df),
            "train_overlap_count": train_overlap,
            "test_overlap_count": test_overlap,
            "selected_indices_sha256": idx_sha,
            "source_row_indices": row_indices,
        },
        "outputs": {
            "demo_flows_csv": {
                "path": f"data/demo/{csv_path.name}",
                "sha256": csv_sha256,
                "row_count": len(df),
            }
        },
    }


def test_f01_provenance_anti_spoofing_matrix(client: TestClient, tmp_path: Path):
    """F-01 P1 regression: Untrusted CSV + sibling manifest MUST NOT forge MODEL_VALIDATED."""
    import hashlib
    import shutil

    from network_anomaly.inference.predict import _sha256_file
    from network_anomaly.ingestion.compatibility import DEFAULT_BENCHMARK_REGISTRY

    df = _make_synthetic_flow_df(4)
    df["MIN_TTL"] = [64.0, 64.0, 64.0, 64.0]
    df["MAX_TTL"] = [64.0, 64.0, 64.0, 64.0]
    df["FLOW_START_MILLISECONDS"] = [
        CANONICAL_VALIDATION_TIME_START_MS + 1000 + i for i in range(4)
    ]

    # 1. External CSV without manifest -> unverified
    no_man_csv = tmp_path / "external_no_manifest.csv"
    df.to_csv(no_man_csv, index=False)
    s1, v1, _ = resolve_csv_source_provenance(no_man_csv, _sha256_file(no_man_csv), len(df), df=df)
    assert (s1, v1) == ("source:nf-v3-unverified", False)

    # 2. External CSV with attacker-controlled self-declared demo_manifest.json (matching CSV SHA,
    #    canonical dataset SHA, canonical split manifest SHA, zero overlap, validation partition)
    #    MUST STILL FAIL CLOSED because the CSV digest is not in the controlled trust anchor!
    spoof_dir = tmp_path / "spoof_demo"
    spoof_dir.mkdir()
    spoof_csv = spoof_dir / "demo_flows.csv"
    df.to_csv(spoof_csv, index=False)
    spoof_sha = _sha256_file(spoof_csv)
    spoof_manifest = _build_demo_manifest_dict(csv_path=spoof_csv, csv_sha256=spoof_sha, df=df)
    (spoof_dir / "demo_manifest.json").write_text(json.dumps(spoof_manifest), encoding="utf-8")
    s2, v2, r2 = resolve_csv_source_provenance(spoof_csv, spoof_sha, len(df), df=df)
    assert (s2, v2) == ("source:nf-v3-unverified", False)
    assert "trust anchor" in r2.lower()

    # 3. Companion manifests (*.manifest.json / *_manifest.json) spoofing canonical or external
    #    benchmarks MUST ALSO BE IGNORED / UNVERIFIED.
    for fake_name, ds_name in (
        (f"{no_man_csv.name}.manifest.json", "NF-UNSW-NB15-v3"),
        (f"{no_man_csv.stem}.manifest.json", "NF-CSE-CIC-IDS2018-v3"),
        (f"{no_man_csv.stem}_manifest.json", "NF-ToN-IoT-v3"),
    ):
        comp_path = tmp_path / fake_name
        comp_path.write_text(
            json.dumps(
                {
                    "dataset_name": ds_name,
                    "source_dataset_sha256": CANONICAL_NF_UNSW_NB15_V3_SHA256,
                    "sample_sha256": _sha256_file(no_man_csv),
                    "sample_rows": len(df),
                    "train_overlap_count": 0,
                    "test_overlap_count": 0,
                }
            ),
            encoding="utf-8",
        )
        sc, vc, _ = resolve_csv_source_provenance(
            no_man_csv, _sha256_file(no_man_csv), len(df), df=df
        )
        assert (sc, vc) == ("source:nf-v3-unverified", False)
        comp_path.unlink()

    # Create a controlled test trust anchor for canonical tamper tests (runs in CI without raw CSV)
    canon_dir = tmp_path / "canonical_fixture"
    canon_dir.mkdir()
    canon_csv = canon_dir / "demo_flows.csv"
    df.to_csv(canon_csv, index=False)
    canon_sha = _sha256_file(canon_csv)
    canon_manifest = _build_demo_manifest_dict(csv_path=canon_csv, csv_sha256=canon_sha, df=df)
    split_obj = json.loads(CANONICAL_SPLIT_MANIFEST_PATH.read_text(encoding="utf-8"))
    controlled_anchor = {
        canon_sha: {
            "dataset_name": "NF-UNSW-NB15-v3",
            "source_id": "source:nf-v3-canonical",
            "partition": "validation",
            "row_count": len(df),
            "source_dataset_sha256": CANONICAL_NF_UNSW_NB15_V3_SHA256,
            "split_manifest_sha256": CANONICAL_SPLIT_MANIFEST_SHA256,
            "partition_indices_sha256": {
                k: split_obj["partitions"][k]["index_sha256"]
                for k in ("train", "validation", "test")
            },
            "selected_indices_sha256": hashlib.sha256(
                ("\n".join(str(int(x)) for x in df["row_id"].tolist()) + "\n").encode("utf-8")
            ).hexdigest(),
            "train_overlap_count": 0,
            "test_overlap_count": 0,
        }
    }

    # 4. Valid canonical fixture with valid companion demo_manifest -> verified!
    (canon_dir / "demo_manifest.json").write_text(json.dumps(canon_manifest), encoding="utf-8")
    sok, vok, _ = resolve_csv_source_provenance(
        canon_csv, canon_sha, len(df), df=df, trusted_subsets=controlled_anchor
    )
    assert (sok, vok) == ("source:nf-v3-canonical", True)

    # 5. Tamper manifest SHA-256 -> rejected
    bad_sha_man = json.loads(json.dumps(canon_manifest))
    bad_sha_man["outputs"]["demo_flows_csv"]["sha256"] = "0" * 64
    (canon_dir / "demo_manifest.json").write_text(json.dumps(bad_sha_man), encoding="utf-8")
    assert resolve_csv_source_provenance(
        canon_csv, canon_sha, len(df), df=df, trusted_subsets=controlled_anchor
    )[:2] == ("source:nf-v3-unverified", False)

    # 6. Change dataset_name in manifest -> rejected
    bad_ds_man = json.loads(json.dumps(canon_manifest))
    bad_ds_man["dataset_name"] = "EVIL-DATASET"
    (canon_dir / "demo_manifest.json").write_text(json.dumps(bad_ds_man), encoding="utf-8")
    assert resolve_csv_source_provenance(
        canon_csv, canon_sha, len(df), df=df, trusted_subsets=controlled_anchor
    )[:2] == ("source:nf-v3-unverified", False)

    # 7. Reject non-zero train/test overlap or Test/Train partition
    for field, val in (
        ("train_overlap_count", 1),
        ("test_overlap_count", 1),
        ("partition", "test"),
    ):
        bad_part_man = json.loads(json.dumps(canon_manifest))
        bad_part_man["sampling"][field] = val
        (canon_dir / "demo_manifest.json").write_text(json.dumps(bad_part_man), encoding="utf-8")
        assert resolve_csv_source_provenance(
            canon_csv, canon_sha, len(df), df=df, trusted_subsets=controlled_anchor
        )[:2] == ("source:nf-v3-unverified", False)

    # 8. Manifest pointing to a different filename -> rejected
    other_file_man = json.loads(json.dumps(canon_manifest))
    other_file_man["outputs"]["demo_flows_csv"]["path"] = "data/demo/other_subset.csv"
    (canon_dir / "demo_manifest.json").write_text(json.dumps(other_file_man), encoding="utf-8")
    assert resolve_csv_source_provenance(
        canon_csv, canon_sha, len(df), df=df, trusted_subsets=controlled_anchor
    )[:2] == ("source:nf-v3-unverified", False)

    # Restore valid manifest, then mutate CSV after manifest creation -> rejected
    (canon_dir / "demo_manifest.json").write_text(json.dumps(canon_manifest), encoding="utf-8")
    modified_csv = canon_dir / "demo_flows.csv"
    mod_df = df.copy()
    mod_df.loc[0, "IN_BYTES"] = mod_df.loc[0, "IN_BYTES"] + 999.0
    mod_df.to_csv(modified_csv, index=False)
    mod_sha = _sha256_file(modified_csv)
    assert resolve_csv_source_provenance(
        modified_csv, mod_sha, len(mod_df), df=mod_df, trusted_subsets=controlled_anchor
    )[:2] == ("source:nf-v3-unverified", False)

    # 9. Empty / missing trust anchor -> fail closed to UNVERIFIED
    df.to_csv(canon_csv, index=False)
    assert resolve_csv_source_provenance(canon_csv, canon_sha, len(df), df=df, trusted_subsets={})[
        :2
    ] == ("source:nf-v3-unverified", False)
    assert resolve_csv_source_provenance(
        canon_csv,
        canon_sha,
        len(df),
        df=df,
        trusted_subsets=controlled_anchor,
        split_manifest_path=tmp_path / "nonexistent_split_manifest.json",
    )[:2] == ("source:nf-v3-unverified", False)

    # 10. Real canonical demo dataset check (when present in checkout) + copy & mutate check
    if DEMO_FLOWS.is_file():
        real_df = pd.read_csv(DEMO_FLOWS)
        real_sha = _sha256_file(DEMO_FLOWS)
        assert real_sha in TRUSTED_CANONICAL_VALIDATION_SUBSETS
        rs, rv, _ = resolve_csv_source_provenance(DEMO_FLOWS, real_sha, len(real_df), df=real_df)
        assert (rs, rv) == ("source:nf-v3-canonical", True)

        # Mutate 1 cell of a copy of canonical demo_flows.csv AND even re-sign a fake manifest -> rejected!
        mut_copy_dir = tmp_path / "mutated_real_demo"
        mut_copy_dir.mkdir()
        shutil.copy2(DEMO_FLOWS, mut_copy_dir / "demo_flows.csv")
        shutil.copy2(
            PROJECT_ROOT / "data" / "demo" / "demo_manifest.json",
            mut_copy_dir / "demo_manifest.json",
        )
        mut_real_df = pd.read_csv(mut_copy_dir / "demo_flows.csv")
        mut_real_df.loc[0, "IN_BYTES"] = float(mut_real_df.loc[0, "IN_BYTES"]) + 1.0
        mut_real_df.to_csv(mut_copy_dir / "demo_flows.csv", index=False)
        mut_real_sha = _sha256_file(mut_copy_dir / "demo_flows.csv")
        mut_man = json.loads((mut_copy_dir / "demo_manifest.json").read_text(encoding="utf-8"))
        mut_man["outputs"]["demo_flows_csv"]["sha256"] = mut_real_sha
        (mut_copy_dir / "demo_manifest.json").write_text(json.dumps(mut_man), encoding="utf-8")
        assert resolve_csv_source_provenance(
            mut_copy_dir / "demo_flows.csv", mut_real_sha, len(mut_real_df), df=mut_real_df
        )[:2] == ("source:nf-v3-unverified", False)

    # 11. End-to-end API gate test: spoofed external CSV with 47 features + forged manifest
    #     receives VALIDATION_NOT_VERIFIED (NOT MODEL_VALIDATED) and blocks when allow_research_only=False.
    canonical_rec = DEFAULT_BENCHMARK_REGISTRY["source:nf-v3-canonical"]

    class _IdentityPrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    fake_canonical_pipe = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": canonical_rec.model_artifact_sha256,
            "run_id": canonical_rec.model_identifier,
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": canonical_rec.preprocessor_artifact_sha256},
        preprocessor=_IdentityPrep(),
        predict=lambda frame: pd.DataFrame(
            {
                "prediction": [0] * len(frame),
                "probability_Attack": [0.1] * len(frame),
                "probability_Benign": [0.9] * len(frame),
                "run_id": [canonical_rec.model_identifier] * len(frame),
            }
        ),
    )

    svc = client.app.state.service
    with patch.object(svc, "_load_inference_pipeline", return_value=fake_canonical_pipe):
        # Spoofed CSV with forged demo_manifest -> RESEARCH/UNVERIFIED only
        spoof_resp = client.post(
            "/api/v1/csv/analyze",
            json={
                "file_path": str(spoof_csv),
                "model_name": "random_forest",
                "allow_research_only": True,
            },
        )
        assert spoof_resp.status_code == 200, spoof_resp.text
        gate_spoof = spoof_resp.json()["compatibility_gate"]
        assert gate_spoof["source_id"] == "source:nf-v3-unverified"
        assert gate_spoof["provenance_verified"] is False
        assert gate_spoof["compatibility_status"] == "SEMANTICALLY_COMPATIBLE"
        assert gate_spoof["eligibility_status"] == "VALIDATION_NOT_VERIFIED"
        assert gate_spoof["compatibility_status"] != "MODEL_VALIDATED"

        # Blocked when allow_research_only=False
        blocked_spoof = client.post(
            "/api/v1/csv/analyze",
            json={
                "file_path": str(spoof_csv),
                "model_name": "random_forest",
                "allow_research_only": False,
            },
        )
        assert blocked_spoof.status_code == 503

        # With controlled trust anchor active, real canonical demo achieves MODEL_VALIDATED
        with patch.dict(TRUSTED_CANONICAL_VALIDATION_SUBSETS, controlled_anchor):
            ver_resp = client.post(
                "/api/v1/csv/analyze",
                json={
                    "file_path": str(canon_csv),
                    "model_name": "random_forest",
                    "allow_research_only": False,
                },
            )
        assert ver_resp.status_code == 200, ver_resp.text
        gate_ver = ver_resp.json()["compatibility_gate"]
        assert gate_ver["source_id"] == "source:nf-v3-canonical"
        assert gate_ver["provenance_verified"] is True
        assert gate_ver["compatibility_status"] == "MODEL_VALIDATED"
        assert gate_ver["eligibility_status"] == "PREDICTION_AVAILABLE"
        # Verify F-06 security_notice clarifies #27 is DEFERRED
        assert "Adaptive rotation & security response (#27)" in ver_resp.json()["security_notice"]
        assert "DEFERRED" in ver_resp.json()["security_notice"]


def test_f02_ood_pre_inference_abstention_matrix(client: TestClient, tmp_path: Path):
    """F-02 P1 regression: OOD rows must abstain BEFORE analyze_flows/predict/incident creation."""
    svc = client.app.state.service

    class _ImputingPrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            out = X.copy()
            for col in out.columns:
                out[col] = (
                    pd.to_numeric(out[col], errors="coerce")
                    .replace([np.inf, -np.inf], np.nan)
                    .fillna(0.0)
                )
            return out

    # Feature-driven predict spy verifying NO OOD rows ever enter model.predict()
    predict_calls: list[list[float]] = []

    def _spy_predict(frame: pd.DataFrame) -> pd.DataFrame:
        # Must NEVER receive MIN_TTL=0 or hard-invariant violation rows
        assert (frame["MIN_TTL"] != 0.0).all(), "MIN_TTL==0 row leaked to model.predict()"
        assert (
            frame["MIN_TTL"] <= frame["MAX_TTL"]
        ).all(), "MIN_TTL>MAX_TTL leaked to model.predict()"
        assert (frame["FLOW_DURATION_MILLISECONDS"] >= 0).all(), "Negative duration leaked!"
        assert (
            frame["SHORTEST_FLOW_PKT"] <= frame["LONGEST_FLOW_PKT"]
        ).all(), "Inverted pkt len leaked!"
        predict_calls.append(frame["IN_BYTES"].tolist())
        # Deterministic prediction by IN_BYTES parity/threshold
        preds = [1 if float(x) >= 100.0 else 0 for x in frame["IN_BYTES"].tolist()]
        probs = [0.91 if p == 1 else 0.09 for p in preds]
        return pd.DataFrame(
            {
                "prediction": preds,
                "probability_Attack": probs,
                "probability_Benign": [round(1.0 - p, 4) for p in probs],
                "run_id": ["rf-f02-test"] * len(frame),
            }
        )

    fake_pipe = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-f02-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_ImputingPrep(),
        predict=_spy_predict,
    )

    gate_ok = (
        CompatibilityGateSummarySchema(
            model_key="random_forest",
            model_identifier="rf-f02-test",
            eligible=True,
            eligibility_status="ELIGIBLE",
            compatibility_status="MODEL_VALIDATED",
            reasons=[],
            warnings=[],
            missing_features=[],
        ),
        True,
    )

    # 1. 0 OOD rows -> model receives all 4 rows
    df_clean = _make_synthetic_flow_df(4)
    df_clean["MIN_TTL"] = [64.0, 64.0, 64.0, 64.0]
    df_clean["MAX_TTL"] = [64.0, 64.0, 64.0, 64.0]
    df_clean["IN_BYTES"] = [10.0, 200.0, 20.0, 300.0]
    p_clean = tmp_path / "clean_0_ood.csv"
    df_clean.to_csv(p_clean, index=False)

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
        patch.object(svc, "analyze_flows", wraps=svc.analyze_flows) as spy_analyze,
    ):
        r_clean = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(p_clean), "model_name": "random_forest", "batch_size": 2},
        )
    assert r_clean.status_code == 200
    d_clean = r_clean.json()
    sent_clean = [e for c in spy_analyze.call_args_list for e in c.args[0]]
    assert len(sent_clean) == 4
    assert d_clean["evaluated_rows"] == 4
    assert d_clean["abstained_rows"] == 0
    assert d_clean["prediction_coverage"] == 1.0
    assert [x["predicted_label"] for x in d_clean["results"]] == [0, 1, 0, 1]

    # 2. Single OOD row (MIN_TTL=0) placed at start, middle, and end
    for ood_pos in (0, 2, 3):
        predict_calls.clear()
        df_one = df_clean.copy()
        df_one.loc[ood_pos, "MIN_TTL"] = 0.0
        df_one.loc[ood_pos, "MAX_TTL"] = 0.0
        p_one = tmp_path / f"one_ood_pos_{ood_pos}.csv"
        df_one.to_csv(p_one, index=False)
        with (
            patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
            patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
            patch.object(svc, "analyze_flows", wraps=svc.analyze_flows) as spy_analyze,
        ):
            r_one = client.post(
                "/api/v1/csv/analyze",
                json={"file_path": str(p_one), "model_name": "random_forest", "batch_size": 2},
            )
        assert r_one.status_code == 200
        d_one = r_one.json()
        sent_one = [e for c in spy_analyze.call_args_list for e in c.args[0]]
        assert len(sent_one) == 3
        assert sum(len(c) for c in predict_calls) == 3
        assert d_one["evaluated_rows"] == 3
        assert d_one["abstained_rows"] == 1
        assert d_one["ood_flagged_count"] == 1
        assert d_one["results"][ood_pos]["predicted_label"] is None
        assert d_one["results"][ood_pos]["predicted_class"] == "ABSTAINED_OOD"
        assert "MIN_TTL == 0" in d_one["results"][ood_pos]["ood_reason"]
        assert [x["row_index"] for x in d_one["results"]] == [0, 1, 2, 3]
        assert [x["row_id"] for x in d_one["results"]] == [100, 101, 102, 103]

    # 3. Multiple interleaved OOD rows (MIN_TTL=0 + Hard invariant violations) + batch boundary
    #    + valid row containing NaN/Inf in SRC_TO_DST_SECOND_BYTES + create_incidents=True
    predict_calls.clear()
    n_mixed = 8
    df_mixed = _make_synthetic_flow_df(n_mixed)
    df_mixed["row_id"] = [500 + i for i in range(n_mixed)]
    df_mixed["FLOW_START_MILLISECONDS"] = [1_700_000_000_000 + i * 1000 for i in range(n_mixed)]
    df_mixed["FLOW_END_MILLISECONDS"] = [1_700_000_000_500 + i * 1000 for i in range(n_mixed)]
    df_mixed["MIN_TTL"] = [64.0] * n_mixed
    df_mixed["MAX_TTL"] = [64.0] * n_mixed
    df_mixed["IN_BYTES"] = [10.0, 200.0, 300.0, 20.0, 400.0, 500.0, 30.0, 600.0]
    df_mixed["Label"] = [0, 1, 1, 0, 1, 1, 0, 1]
    df_mixed["Attack"] = [
        "Benign",
        "Exploits",
        "DoS",
        "Benign",
        "Exploits",
        "Fuzzers",
        "Benign",
        "Generic",
    ]
    # OOD indices: 0 (start, MIN_TTL=0), 2 (batch_size=2 boundary after idx 1 accepted? Wait: accepted indices are [1, 3, 5, 7], so idx 2 & 4 & 6 cover mixed boundaries),
    # Make OOD at indices 0 (MIN_TTL=0), 2 (MIN_TTL > MAX_TTL hard violation),
    # 5 (negative FLOW_DURATION_MILLISECONDS hard violation), 7 (MIN_TTL=0 at end).
    # Accepted indices = [1, 3, 4, 6] -> 4 accepted rows across batch_size=2 => [1, 3] and [4, 6].
    # Put NaN/Inf ratio feature on valid row 4 (follows preprocessing policy).
    df_mixed.loc[0, ["MIN_TTL", "MAX_TTL"]] = [0.0, 0.0]
    df_mixed.loc[2, ["MIN_TTL", "MAX_TTL"]] = [128.0, 64.0]
    df_mixed.loc[5, "FLOW_DURATION_MILLISECONDS"] = -25.0
    df_mixed.loc[7, ["MIN_TTL", "MAX_TTL"]] = [0.0, 0.0]
    df_mixed.loc[4, "SRC_TO_DST_SECOND_BYTES"] = np.inf

    p_mixed = tmp_path / "mixed_ood.csv"
    df_mixed.to_csv(p_mixed, index=False)
    p_mixed_labels = tmp_path / "mixed_labels.csv"
    df_mixed[["row_id", "Label", "Attack"]].to_csv(p_mixed_labels, index=False)

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
        patch.object(svc, "analyze_flows", wraps=svc.analyze_flows) as spy_analyze,
    ):
        r_mixed = client.post(
            "/api/v1/csv/analyze",
            json={
                "file_path": str(p_mixed),
                "model_name": "random_forest",
                "batch_size": 2,
                "create_incidents": True,
            },
        )
    assert r_mixed.status_code == 200, r_mixed.text
    d_mixed = r_mixed.json()
    sent_events_mixed = [e for c in spy_analyze.call_args_list for e in c.args[0]]
    # Strictly only indices [1, 3, 4, 6] reached analyze_flows & model.predict!
    assert len(sent_events_mixed) == 4
    assert [e["event_id"].rsplit("_", 1)[-1] for e in sent_events_mixed] == ["1", "3", "4", "6"]
    assert sum(len(c) for c in predict_calls) == 4

    assert d_mixed["total_rows"] == 8
    assert d_mixed["evaluated_rows"] == 4
    assert d_mixed["abstained_rows"] == 4
    assert d_mixed["prediction_coverage"] == 0.5
    # Accepted predictions: idx 1 (200->1), idx 3 (20->0), idx 4 (400->1), idx 6 (30->0) => 2 Attack, 2 Benign
    assert d_mixed["attack_count"] == 2
    assert d_mixed["benign_count"] == 2
    assert [r["row_index"] for r in d_mixed["results"]] == list(range(8))
    assert [r["row_id"] for r in d_mixed["results"]] == [500 + i for i in range(8)]
    for ood_i in (0, 2, 5, 7):
        item = d_mixed["results"][ood_i]
        assert item["predicted_label"] is None
        assert item["predicted_class"] == "ABSTAINED_OOD"
        assert item["attack_probability"] is None
        assert item["raw_anomaly_score"] is None
        assert item["risk_score"] is None
        assert item["risk_level"] == "ABSTAINED_OOD"
    assert "MIN_TTL == 0" in d_mixed["results"][0]["ood_reason"]
    assert "Hard protocol invariant violation" in d_mixed["results"][2]["ood_reason"]
    assert "Hard protocol invariant violation" in d_mixed["results"][5]["ood_reason"]
    assert "MIN_TTL == 0" in d_mixed["results"][7]["ood_reason"]

    # Verify SQLite incidents created ONLY for valid Attack rows (idx 1 & 4), NEVER for OOD rows!
    conn = svc.db.get_connection()
    try:
        inc_rows = conn.execute("SELECT event_id FROM incidents").fetchall()
    finally:
        conn.close()
    incident_event_suffixes = sorted(r[0].rsplit("_", 1)[-1] for r in inc_rows)
    assert incident_event_suffixes == ["1", "4"]

    # Verify Ground Truth evaluation excludes OOD abstained rows from Confusion Matrix
    ev_resp = client.post(
        "/api/v1/csv/evaluate",
        json={"labels_path": str(p_mixed_labels), "predictions": d_mixed["results"]},
    )
    assert ev_resp.status_code == 200
    ev = ev_resp.json()
    cm = ev["confusion_matrix"]
    assert cm["tn"] + cm["fp"] + cm["fn"] + cm["tp"] == 4
    assert cm == {"tn": 2, "fp": 0, "fn": 0, "tp": 2}
    assert ev["evaluated_rows"] == 4
    assert ev["matched_rows"] == 4
    assert ev["abstained_rows"] == 4
    assert ev["prediction_coverage"] == 0.5

    # 4. 100% OOD CSV -> 0 calls to analyze_flows / model.predict and HTTP 503
    predict_calls.clear()
    df_all_ood = _make_synthetic_flow_df(3)
    df_all_ood.loc[0, ["MIN_TTL", "MAX_TTL"]] = [0.0, 0.0]
    df_all_ood.loc[1, "FLOW_DURATION_MILLISECONDS"] = -1.0
    df_all_ood.loc[2, ["MIN_TTL", "MAX_TTL"]] = [200.0, 64.0]
    p_all_ood = tmp_path / "all_ood_mixed.csv"
    df_all_ood.to_csv(p_all_ood, index=False)

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch.object(svc, "analyze_flows", wraps=svc.analyze_flows) as spy_analyze_all_ood,
    ):
        r_all = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(p_all_ood), "model_name": "random_forest"},
        )
    assert r_all.status_code == 503
    assert spy_analyze_all_ood.call_count == 0
    assert len(predict_calls) == 0

    # 5. Missing ML feature column in analyze fails cleanly BEFORE inference
    df_missing = df_clean.drop(columns=["PROTOCOL"])
    p_missing = tmp_path / "missing_col.csv"
    df_missing.to_csv(p_missing, index=False)
    with patch.object(svc, "analyze_flows", wraps=svc.analyze_flows) as spy_missing:
        r_missing = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(p_missing), "model_name": "random_forest"},
        )
    assert r_missing.status_code == 400
    assert spy_missing.call_count == 0


@pytest.mark.skipif(
    not (
        DEMO_FLOWS.is_file()
        and RF_MODEL.is_file()
        and IF_MODEL.is_file()
        and PREP_ARTIFACT.is_file()
    ),
    reason="Offline verified model artifacts or demo CSV not present in this checkout.",
)
def test_f02_real_models_only_receive_198_eligible_demo_rows(client: TestClient):
    """Verify with spy + REAL RF & IF models that 2 OOD rows never enter service.analyze_flows."""
    svc = client.app.state.service
    for model_key in ("random_forest", "isolation_forest"):
        with patch.object(svc, "analyze_flows", wraps=svc.analyze_flows) as spy_analyze:
            resp = client.post(
                "/api/v1/csv/analyze",
                json={"file_path": str(DEMO_FLOWS), "model_name": model_key, "batch_size": 100},
            )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        sent_events = [e for c in spy_analyze.call_args_list for e in c.args[0]]
        assert len(sent_events) == 198, f"{model_key} received {len(sent_events)} != 198 rows"
        assert data["evaluated_rows"] == 198
        assert data["abstained_rows"] == 2
        assert data["prediction_coverage"] == 0.99
        assert data["benign_count"] + data["attack_count"] == 198


def test_all_ood_rows_fail_closed_in_analyze_and_evaluate(client: TestClient, tmp_path: Path):
    """P1 regression: When 100% of rows are OOD-abstained, both analyze and evaluate fail closed."""
    df = _make_synthetic_flow_df(2)
    df["MIN_TTL"] = [0.0, 0.0]
    df["MAX_TTL"] = [0.0, 0.0]
    df["Label"] = [1, 0]
    all_ood_csv = tmp_path / "all_ood.csv"
    df.to_csv(all_ood_csv, index=False)
    labels_csv = tmp_path / "all_ood_labels.csv"
    df[["row_id", "Label"]].to_csv(labels_csv, index=False)

    class _IdentityPrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    fake_pipe = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-ood-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_IdentityPrep(),
        predict=lambda frame: pd.DataFrame(
            {
                "prediction": [1] * len(frame),
                "probability_Attack": [0.9] * len(frame),
                "probability_Benign": [0.1] * len(frame),
                "run_id": ["rf-ood-test"] * len(frame),
            }
        ),
    )

    svc = client.app.state.service
    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch(
            "network_anomaly.api.desktop_csv._evaluate_gate",
            return_value=(
                CompatibilityGateSummarySchema(
                    model_key="random_forest",
                    model_identifier="rf-ood-test",
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
        resp = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(all_ood_csv), "model_name": "random_forest"},
        )
        assert resp.status_code == 503
        assert "abstained" in resp.text.lower()

    eval_resp = client.post(
        "/api/v1/csv/evaluate",
        json={
            "labels_path": str(labels_csv),
            "predictions": [
                {
                    "row_id": int(df["row_id"].iloc[i]),
                    "row_index": i,
                    "predicted_label": None,
                    "predicted_class": "ABSTAINED_OOD",
                    "score_type": "attack_probability",
                    "score_direction": "higher_is_more_anomalous",
                    "risk_score": None,
                    "risk_level": "ABSTAINED_OOD",
                    "is_ood_flagged": True,
                }
                for i in range(len(df))
            ],
        },
    )
    assert eval_resp.status_code == 400
    assert "abstained" in eval_resp.text.lower()


def test_evaluate_handles_float_upcast_row_id_and_all_nan_attack_column(
    client: TestClient, tmp_path: Path
):
    """P2 regression: Ground truth with float columns or all-NaN Attack must align integer row_ids."""
    labels_csv = tmp_path / "labels_all_nan_attack_and_float.csv"
    labels_csv.write_text(
        "row_id,Label,Attack,weight\n2393,0,,1.5\n2394,1,,0.75\n2395,0,,2.25\n",
        encoding="utf-8",
    )
    preds = [
        {
            "row_id": 2393,
            "row_index": 0,
            "predicted_label": 0,
            "predicted_class": "Benign",
            "attack_probability": 0.05,
            "raw_anomaly_score": 0.05,
            "decision_threshold": 0.5,
            "score_type": "attack_probability",
            "score_direction": "higher_is_more_anomalous",
            "risk_score": 5.0,
            "risk_level": "LOW",
            "is_ood_flagged": False,
        },
        {
            "row_id": 2394,
            "row_index": 1,
            "predicted_label": 1,
            "predicted_class": "Attack",
            "attack_probability": 0.95,
            "raw_anomaly_score": 0.95,
            "decision_threshold": 0.5,
            "score_type": "attack_probability",
            "score_direction": "higher_is_more_anomalous",
            "risk_score": 95.0,
            "risk_level": "CRITICAL",
            "is_ood_flagged": False,
        },
        {
            "row_id": 2395,
            "row_index": 2,
            "predicted_label": None,
            "predicted_class": "ABSTAINED_OOD",
            "attack_probability": None,
            "raw_anomaly_score": None,
            "decision_threshold": 0.5,
            "score_type": "attack_probability",
            "score_direction": "higher_is_more_anomalous",
            "risk_score": None,
            "risk_level": "ABSTAINED_OOD",
            "is_ood_flagged": True,
        },
    ]
    resp = client.post(
        "/api/v1/csv/evaluate",
        json={"labels_path": str(labels_csv), "predictions": preds},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["matched_rows"] == 2
    assert body["evaluated_rows"] == 2
    assert body["abstained_rows"] == 1
    assert body["prediction_coverage"] == pytest.approx(2 / 3, abs=1e-4)
    assert body["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 0, "tp": 1}


def test_evaluate_separates_label_match_rate_from_post_ood_coverage(
    client: TestClient, tmp_path: Path
):
    """Regression: partial ground-truth label match (1/3) must expose label_match_rate & unmatched_rows separately."""

    def _pred(row_id: int, row_index: int, label: int | None, is_ood: bool = False) -> dict:
        if is_ood or label is None:
            return {
                "row_id": row_id,
                "row_index": row_index,
                "predicted_label": None,
                "predicted_class": "ABSTAINED_OOD",
                "attack_probability": None,
                "raw_anomaly_score": None,
                "decision_threshold": 0.5,
                "score_type": "attack_probability",
                "score_direction": "higher_is_more_anomalous",
                "risk_score": None,
                "risk_level": "ABSTAINED_OOD",
                "is_ood_flagged": True,
            }
        return {
            "row_id": row_id,
            "row_index": row_index,
            "predicted_label": label,
            "predicted_class": "Attack" if label == 1 else "Benign",
            "attack_probability": 0.9 if label == 1 else 0.1,
            "raw_anomaly_score": 0.9 if label == 1 else 0.1,
            "decision_threshold": 0.5,
            "score_type": "attack_probability",
            "score_direction": "higher_is_more_anomalous",
            "risk_score": 90.0 if label == 1 else 10.0,
            "risk_level": "CRITICAL" if label == 1 else "LOW",
            "is_ood_flagged": False,
        }

    # Case 1: 3 predictions, labels CSV matches only 1/3 rows (no OOD abstention)
    labels_one_of_three = tmp_path / "labels_1_of_3.csv"
    labels_one_of_three.write_text("row_id,Label,Attack\n101,1,Exploits\n", encoding="utf-8")
    preds_three = [_pred(101, 0, 1), _pred(102, 1, 0), _pred(103, 2, 0)]

    r1 = client.post(
        "/api/v1/csv/evaluate",
        json={"labels_path": str(labels_one_of_three), "predictions": preds_three},
    )
    assert r1.status_code == 200, r1.text
    b1 = r1.json()
    assert b1["total_prediction_rows"] == 3
    assert b1["matched_label_rows"] == 1
    assert b1["unmatched_rows"] == 2
    assert b1["label_match_rate"] == pytest.approx(1 / 3, abs=1e-4)
    assert b1["evaluated_rows"] == 1
    assert b1["matched_rows"] == 1
    assert b1["abstained_rows"] == 0
    assert b1["prediction_coverage"] == 1.0
    assert "Partial label match: 1/3" in b1["scientific_notice"]
    assert "2 unmatched rows excluded" in b1["scientific_notice"]

    # Case 2: Combined partial label match (2/4) AND OOD abstention (1/2 matched rows abstained)
    labels_partial_with_ood = tmp_path / "labels_partial_with_ood.csv"
    labels_partial_with_ood.write_text(
        "row_id,Label,Attack\n101,1,Exploits\n102,0,Benign\n",
        encoding="utf-8",
    )
    preds_four = [
        _pred(101, 0, 1, is_ood=False),
        _pred(102, 1, None, is_ood=True),
        _pred(103, 2, 0, is_ood=False),
        _pred(104, 3, None, is_ood=True),
    ]
    r2 = client.post(
        "/api/v1/csv/evaluate",
        json={"labels_path": str(labels_partial_with_ood), "predictions": preds_four},
    )
    assert r2.status_code == 200, r2.text
    b2 = r2.json()
    assert b2["total_prediction_rows"] == 4
    assert b2["matched_label_rows"] == 2
    assert b2["unmatched_rows"] == 2
    assert b2["label_match_rate"] == 0.5
    assert b2["evaluated_rows"] == 1
    assert b2["abstained_rows"] == 1
    assert b2["prediction_coverage"] == 0.5
    assert b2["confusion_matrix"] == {"tn": 0, "fp": 0, "fn": 0, "tp": 1}


def test_ood_report_separates_zero_ttl_from_hard_physical_violations(
    client: TestClient, tmp_path: Path
):
    """F1 regression: MIN_TTL == 0 must not inflate hard_violation_count while preserving abstention coverage."""
    svc = client.app.state.service

    class _PassthroughPrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    def _predict_valid(frame: pd.DataFrame) -> pd.DataFrame:
        assert (frame["MIN_TTL"] != 0.0).all()
        assert (frame["FLOW_DURATION_MILLISECONDS"] >= 0.0).all()
        return pd.DataFrame(
            {
                "prediction": [0] * len(frame),
                "probability_Attack": [0.1] * len(frame),
                "probability_Benign": [0.9] * len(frame),
                "run_id": ["rf-f1-test"] * len(frame),
            }
        )

    fake_pipe = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-f1-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_PassthroughPrep(),
        predict=_predict_valid,
    )
    gate_ok = (
        CompatibilityGateSummarySchema(
            model_key="random_forest",
            model_identifier="rf-f1-test",
            eligible=True,
            eligibility_status="ELIGIBLE",
            compatibility_status="MODEL_VALIDATED",
            reasons=[],
            warnings=[],
            missing_features=[],
        ),
        True,
    )

    # Case 1: MIN_TTL=0 only (row 1 of 4) -> hard_violation_count == 0, affected == 1, coverage == 0.75
    df_zero_only = _make_synthetic_flow_df(4)
    p_zero = tmp_path / "f1_zero_only.csv"
    df_zero_only.to_csv(p_zero, index=False)

    ins_zero = client.post(
        "/api/v1/csv/inspect", json={"file_path": str(p_zero), "preview_limit": 10}
    )
    assert ins_zero.status_code == 200, ins_zero.text
    ood_ins_zero = ins_zero.json()["ood_report"]
    assert ood_ins_zero["zero_ttl_count"] == 1
    assert ood_ins_zero["zero_ttl_indices"] == [1]
    assert ood_ins_zero["hard_violation_count"] == 0
    assert ood_ins_zero["hard_violation_indices"] == []
    assert ood_ins_zero["out_of_range_details"] == {}
    assert ood_ins_zero["affected_rows_count"] == 1
    assert ood_ins_zero["abstention_rate"] == 0.25
    assert ood_ins_zero["prediction_coverage"] == 0.75

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
    ):
        ana_zero = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(p_zero), "model_name": "random_forest"},
        )
    assert ana_zero.status_code == 200, ana_zero.text
    ana_zero_body = ana_zero.json()
    assert ana_zero_body["abstained_rows"] == 1
    assert ana_zero_body["evaluated_rows"] == 3
    assert ana_zero_body["prediction_coverage"] == 0.75
    assert ana_zero_body["ood_report"] == ood_ins_zero

    # Case 2: Overlapping + disjoint physical violation and MIN_TTL=0 (5 rows):
    # row 1: MIN_TTL=0 only; row 2: negative duration only; row 3: BOTH MIN_TTL=0 and negative duration.
    df_mixed = _make_synthetic_flow_df(5)
    df_mixed.loc[2, "FLOW_DURATION_MILLISECONDS"] = -5.0
    df_mixed.loc[3, "MIN_TTL"] = 0.0
    df_mixed.loc[3, "MAX_TTL"] = 0.0
    df_mixed.loc[3, "FLOW_DURATION_MILLISECONDS"] = -1.0
    p_mixed = tmp_path / "f1_mixed.csv"
    df_mixed.to_csv(p_mixed, index=False)

    ins_mixed = client.post(
        "/api/v1/csv/inspect", json={"file_path": str(p_mixed), "preview_limit": 10}
    )
    assert ins_mixed.status_code == 200, ins_mixed.text
    ood_ins_mixed = ins_mixed.json()["ood_report"]
    assert ood_ins_mixed["zero_ttl_count"] == 2
    assert ood_ins_mixed["zero_ttl_indices"] == [1, 3]
    assert ood_ins_mixed["hard_violation_count"] == 2
    assert ood_ins_mixed["hard_violation_indices"] == [2, 3]
    assert ood_ins_mixed["out_of_range_details"] == {"FLOW_DURATION_MILLISECONDS_negative": 2}
    # Union {1, 2, 3} -> 3 unique affected rows out of 5 (not double-counted as 4)
    assert ood_ins_mixed["affected_rows_count"] == 3
    assert ood_ins_mixed["abstention_rate"] == 0.6
    assert ood_ins_mixed["prediction_coverage"] == 0.4

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
    ):
        ana_mixed = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(p_mixed), "model_name": "random_forest"},
        )
    assert ana_mixed.status_code == 200, ana_mixed.text
    ana_mixed_body = ana_mixed.json()
    assert ana_mixed_body["abstained_rows"] == 3
    assert ana_mixed_body["evaluated_rows"] == 2
    assert ana_mixed_body["prediction_coverage"] == 0.4
    assert ana_mixed_body["ood_report"] == ood_ins_mixed


def test_f3_export_provenance_verification_and_tamper_rejection(client: TestClient, tmp_path: Path):
    """F3 regression: export must record source_csv_sha256 and reject tampered analysis provenance."""
    svc = client.app.state.service

    class _PassthroughPrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    def _predict_clean(frame: pd.DataFrame) -> pd.DataFrame:
        return pd.DataFrame(
            {
                "prediction": [0] * len(frame),
                "probability_Attack": [0.15] * len(frame),
                "probability_Benign": [0.85] * len(frame),
                "run_id": ["rf-f3-test"] * len(frame),
            }
        )

    fake_pipe = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-f3-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_PassthroughPrep(),
        predict=_predict_clean,
    )
    gate_ok = (
        CompatibilityGateSummarySchema(
            model_key="random_forest",
            model_identifier="rf-f3-test",
            eligible=True,
            eligibility_status="ELIGIBLE",
            compatibility_status="MODEL_VALIDATED",
            reasons=[],
            warnings=[],
            missing_features=[],
        ),
        True,
    )

    df = _make_synthetic_flow_df(4)
    flows_csv = tmp_path / "f3_flows.csv"
    df.to_csv(flows_csv, index=False)

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
    ):
        az = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(flows_csv), "model_name": "random_forest"},
        ).json()

    base_payload = {
        "output_path": str(tmp_path / "f3_export.csv"),
        "analysis_id": az["analysis_id"],
        "source_csv_path": str(flows_csv),
        "model_key": "random_forest",
        "model_type": "RandomForest",
        "run_id": az["run_id"],
        "model_sha256": az["model_sha256"],
        "preprocessor_sha256": az["preprocessor_sha256"],
        "results": az["results"],
        "evaluation": None,
    }

    # 1. Unknown analysis_id -> 400 fail-closed
    bad_id = {**base_payload, "analysis_id": "csvrun_forged123456"}
    assert client.post("/api/v1/csv/export", json=bad_id).status_code == 400

    # 2. Tampered model_sha256 with real analysis_id -> 400 fail-closed
    bad_sha = {**base_payload, "model_sha256": "0" * 64}
    assert client.post("/api/v1/csv/export", json=bad_sha).status_code == 400

    # 3. Tampered prediction results with real analysis_id -> 400 fail-closed
    tampered_results = [dict(az["results"][0], predicted_class="Benign", predicted_label=0)] + az[
        "results"
    ][1:]
    if az["results"][0]["predicted_label"] == 0:
        tampered_results[0]["predicted_class"] = "Attack"
        tampered_results[0]["predicted_label"] = 1
    bad_results = {**base_payload, "results": tampered_results}
    assert client.post("/api/v1/csv/export", json=bad_results).status_code == 400

    # 4. Omitting analysis_id with spoofed metadata labels export unverified_client_supplied
    no_id_payload = {
        **base_payload,
        "output_path": str(tmp_path / "f3_unverified.csv"),
        "analysis_id": None,
        "model_sha256": "0" * 64,
    }
    unv_resp = client.post("/api/v1/csv/export", json=no_id_payload)
    assert unv_resp.status_code == 200, unv_resp.text
    unv_meta = json.loads(Path(unv_resp.json()["metadata_path"]).read_text(encoding="utf-8"))
    assert unv_meta["provenance_verification"] == "unverified_client_supplied"
    assert unv_meta["evaluation_verification"] == "none"
    assert unv_meta["source_csv_sha256"] == az["file_sha256"]


def test_f07_export_verifies_source_csv_immutability(client: TestClient, tmp_path: Path):
    """F-07 P1 regression: server_verified_analysis must verify recorded source CSV digest on disk."""
    svc = client.app.state.service

    class _PassthroughPrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    def _predict_clean(frame: pd.DataFrame) -> pd.DataFrame:
        return pd.DataFrame(
            {
                "prediction": [0] * len(frame),
                "probability_Attack": [0.1] * len(frame),
                "probability_Benign": [0.9] * len(frame),
                "run_id": ["rf-f07-test"] * len(frame),
            }
        )

    fake_pipe = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-f07-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_PassthroughPrep(),
        predict=_predict_clean,
    )
    gate_ok = (
        CompatibilityGateSummarySchema(
            model_key="random_forest",
            model_identifier="rf-f07-test",
            eligible=True,
            eligibility_status="ELIGIBLE",
            compatibility_status="MODEL_VALIDATED",
            reasons=[],
            warnings=[],
            missing_features=[],
        ),
        True,
    )

    flows_csv = tmp_path / "f07_source.csv"
    _make_synthetic_flow_df(4).to_csv(flows_csv, index=False)

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
    ):
        az = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(flows_csv), "model_name": "random_forest"},
        ).json()

    base_payload = {
        "analysis_id": az["analysis_id"],
        "source_csv_path": str(flows_csv),
        "model_key": "random_forest",
        "model_type": "RandomForest",
        "run_id": az["run_id"],
        "model_sha256": az["model_sha256"],
        "preprocessor_sha256": az["preprocessor_sha256"],
        "results": az["results"],
        "evaluation": None,
    }

    # 1. Valid unchanged CSV passes with server_verified_analysis
    ok_resp = client.post(
        "/api/v1/csv/export",
        json={**base_payload, "output_path": str(tmp_path / "f07_ok.csv")},
    )
    assert ok_resp.status_code == 200, ok_resp.text
    ok_meta = json.loads(Path(ok_resp.json()["metadata_path"]).read_text(encoding="utf-8"))
    assert ok_meta["provenance_verification"] == "server_verified_analysis"
    assert ok_meta["source_csv_sha256"] == az["file_sha256"]

    # 2. source_csv_path=None with intact CSV still verifies recorded CSV on disk
    none_ok = client.post(
        "/api/v1/csv/export",
        json={
            **base_payload,
            "source_csv_path": None,
            "output_path": str(tmp_path / "f07_none_ok.csv"),
        },
    )
    assert none_ok.status_code == 200, none_ok.text
    none_meta = json.loads(Path(none_ok.json()["metadata_path"]).read_text(encoding="utf-8"))
    assert none_meta["provenance_verification"] == "server_verified_analysis"
    assert none_meta["source_csv_path"] == str(flows_csv.resolve())
    assert none_meta["source_csv_sha256"] == az["file_sha256"]

    # 3. Empty string source_csv_path fails closed
    empty_src = client.post(
        "/api/v1/csv/export",
        json={
            **base_payload,
            "source_csv_path": "",
            "output_path": str(tmp_path / "f07_empty_src.csv"),
        },
    )
    assert empty_src.status_code == 400

    # 4. Modifying source CSV after inference fails closed (both with path and with None)
    flows_csv.write_text(flows_csv.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    mod_with_path = client.post(
        "/api/v1/csv/export",
        json={**base_payload, "output_path": str(tmp_path / "f07_mod1.csv")},
    )
    assert mod_with_path.status_code == 400
    mod_with_none = client.post(
        "/api/v1/csv/export",
        json={
            **base_payload,
            "source_csv_path": None,
            "output_path": str(tmp_path / "f07_mod2.csv"),
        },
    )
    assert mod_with_none.status_code == 400

    # 5. Deleting source CSV after inference fails closed (both with path and with None)
    flows_csv.unlink()
    del_with_path = client.post(
        "/api/v1/csv/export",
        json={**base_payload, "output_path": str(tmp_path / "f07_del1.csv")},
    )
    assert del_with_path.status_code == 400
    del_with_none = client.post(
        "/api/v1/csv/export",
        json={
            **base_payload,
            "source_csv_path": None,
            "output_path": str(tmp_path / "f07_del2.csv"),
        },
    )
    assert del_with_none.status_code == 400


def test_f08_export_verifies_evaluation_summary_or_marks_unverified(
    client: TestClient, tmp_path: Path
):
    """F-08 P2 regression: evaluation summary on export must match server evaluation or be marked unverified."""
    svc = client.app.state.service

    class _PassthroughPrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    def _predict_in_bytes(frame: pd.DataFrame) -> pd.DataFrame:
        preds = [1 if float(v) >= 2.5 else 0 for v in frame["IN_BYTES"].tolist()]
        probs = [0.9 if p == 1 else 0.1 for p in preds]
        return pd.DataFrame(
            {
                "prediction": preds,
                "probability_Attack": probs,
                "probability_Benign": [round(1.0 - p, 4) for p in probs],
                "run_id": ["rf-f08-test"] * len(frame),
            }
        )

    fake_pipe = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-f08-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_PassthroughPrep(),
        predict=_predict_in_bytes,
    )
    gate_ok = (
        CompatibilityGateSummarySchema(
            model_key="random_forest",
            model_identifier="rf-f08-test",
            eligible=True,
            eligibility_status="ELIGIBLE",
            compatibility_status="MODEL_VALIDATED",
            reasons=[],
            warnings=[],
            missing_features=[],
        ),
        True,
    )

    df = _make_synthetic_flow_df(4)
    df["Label"] = [0, 0, 1, 1]
    df["Attack"] = ["Benign", "Benign", "Exploits", "Fuzzers"]
    flows_csv = tmp_path / "f08_flows.csv"
    labels_csv = tmp_path / "f08_labels.csv"
    df.drop(columns=["Label", "Attack"]).to_csv(flows_csv, index=False)
    df[["row_id", "Label", "Attack"]].to_csv(labels_csv, index=False)

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
    ):
        az = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(flows_csv), "model_name": "random_forest"},
        ).json()

    ev_resp = client.post(
        "/api/v1/csv/evaluate",
        json={"labels_path": str(labels_csv), "predictions": az["results"]},
    )
    assert ev_resp.status_code == 200, ev_resp.text
    ev = ev_resp.json()

    base_payload = {
        "analysis_id": az["analysis_id"],
        "source_csv_path": str(flows_csv),
        "model_key": "random_forest",
        "model_type": "RandomForest",
        "run_id": az["run_id"],
        "model_sha256": az["model_sha256"],
        "preprocessor_sha256": az["preprocessor_sha256"],
        "results": az["results"],
        "evaluation": ev,
    }

    # 1. Tampered metric (e.g. forged f1 / accuracy) -> fail-closed 400
    forged_metrics = {**ev, "f1": 0.123456}
    assert (
        client.post(
            "/api/v1/csv/export",
            json={
                **base_payload,
                "output_path": str(tmp_path / "f08_bad_metric.csv"),
                "evaluation": forged_metrics,
            },
        ).status_code
        == 400
    )

    # 2. Tampered labels_sha256 -> fail-closed 400
    forged_labels_sha = {**ev, "labels_sha256": "f" * 64}
    assert (
        client.post(
            "/api/v1/csv/export",
            json={
                **base_payload,
                "output_path": str(tmp_path / "f08_bad_sha.csv"),
                "evaluation": forged_labels_sha,
            },
        ).status_code
        == 400
    )

    # 3. Export without analysis_id containing evaluation -> explicitly marked client_supplied_unverified
    unverified_eval_resp = client.post(
        "/api/v1/csv/export",
        json={
            **base_payload,
            "analysis_id": None,
            "output_path": str(tmp_path / "f08_unverified.csv"),
            "evaluation": forged_metrics,
        },
    )
    assert unverified_eval_resp.status_code == 200, unverified_eval_resp.text
    unverified_meta = json.loads(
        Path(unverified_eval_resp.json()["metadata_path"]).read_text(encoding="utf-8")
    )
    assert unverified_meta["provenance_verification"] == "unverified_client_supplied"
    assert unverified_meta["evaluation_verification"] == "client_supplied_unverified"

    # 4. Valid server-verified export records server_verified_evaluation
    valid_resp = client.post(
        "/api/v1/csv/export",
        json={**base_payload, "output_path": str(tmp_path / "f08_valid.csv")},
    )
    assert valid_resp.status_code == 200, valid_resp.text
    valid_meta = json.loads(Path(valid_resp.json()["metadata_path"]).read_text(encoding="utf-8"))
    assert valid_meta["provenance_verification"] == "server_verified_analysis"
    assert valid_meta["evaluation_verification"] == "server_verified_evaluation"

    # 5. Modifying labels CSV after evaluation fails closed against recorded labels_sha256
    labels_csv.write_text("row_id,Label,Attack\n100,1,Exploits\n", encoding="utf-8")
    assert (
        client.post(
            "/api/v1/csv/export",
            json={**base_payload, "output_path": str(tmp_path / "f08_tampered_labels_disk.csv")},
        ).status_code
        == 400
    )


def test_f4_path_hardening_blocks_unc_and_enforces_allowed_roots(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F4 regression: UNC paths and outside-allowlist CSV/export paths must fail closed with 400."""
    # UNC paths rejected for inspect and export
    assert (
        client.post(
            "/api/v1/csv/inspect", json={"file_path": "\\\\fileserver\\share\\a.csv"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/csv/export",
            json={
                "output_path": "//fileserver/share/out.csv",
                "model_key": "random_forest",
                "model_type": "RandomForest",
                "results": [
                    {
                        "row_id": 1,
                        "row_index": 0,
                        "predicted_label": 0,
                        "predicted_class": "Benign",
                        "decision_threshold": 0.5,
                        "score_type": "attack_probability",
                        "score_direction": "higher_is_more_anomalous",
                        "risk_score": 10.0,
                        "risk_level": "LOW",
                        "is_ood_flagged": False,
                    }
                ],
            },
        ).status_code
        == 400
    )

    allowed_dir = tmp_path / "allowed"
    blocked_dir = tmp_path / "outside"
    allowed_dir.mkdir()
    blocked_dir.mkdir()

    ok_csv = allowed_dir / "ok.csv"
    out_csv = blocked_dir / "outside.csv"
    _make_synthetic_flow_df(2).to_csv(ok_csv, index=False)
    _make_synthetic_flow_df(2).to_csv(out_csv, index=False)

    monkeypatch.setenv("NETWORK_ANOMALY_ALLOWED_CSV_ROOTS", str(allowed_dir))
    assert client.post("/api/v1/csv/inspect", json={"file_path": str(ok_csv)}).status_code == 200
    assert client.post("/api/v1/csv/inspect", json={"file_path": str(out_csv)}).status_code == 400


def test_f5_run_api_emits_security_warning_for_allow_non_local(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """F5 regression: --allow-non-local must emit an explicit unauthenticated binding warning."""
    import sys

    import uvicorn

    from scripts import run_api

    called = {}
    monkeypatch.setattr(
        uvicorn, "run", lambda app, host, port, reload: called.update({"host": host, "port": port})
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_api.py", "--host", "0.0.0.0", "--port", "8999", "--allow-non-local"],
    )
    run_api.main()
    captured = capsys.readouterr()
    assert "[SECURITY WARNING]" in captured.err
    assert "WITHOUT built-in authentication" in captured.err
    assert called["host"] == "0.0.0.0"


def test_f6_float_row_id_with_nan_normalizes_without_dot_zero_suffix(
    client: TestClient, tmp_path: Path
):
    """F6 regression: CSV row_id promoted to float64 by NaN must emit integer IDs instead of '<id>.0'."""
    svc = client.app.state.service

    class _PassthroughPrep:
        def transform(self, X: pd.DataFrame, partition_name: str = "inference") -> pd.DataFrame:
            return X.copy()

    def _predict_clean(frame: pd.DataFrame) -> pd.DataFrame:
        return pd.DataFrame(
            {
                "prediction": [0] * len(frame),
                "probability_Attack": [0.2] * len(frame),
                "probability_Benign": [0.8] * len(frame),
                "run_id": ["rf-f6-test"] * len(frame),
            }
        )

    fake_pipe = SimpleNamespace(
        model_metadata={
            "model_type": "RandomForest",
            "model_artifact_sha256": "a" * 64,
            "run_id": "rf-f6-test",
            "threshold": 0.5,
        },
        preprocessor_metadata={"artifact_sha256": "b" * 64},
        preprocessor=_PassthroughPrep(),
        predict=_predict_clean,
    )
    gate_ok = (
        CompatibilityGateSummarySchema(
            model_key="random_forest",
            model_identifier="rf-f6-test",
            eligible=True,
            eligibility_status="ELIGIBLE",
            compatibility_status="MODEL_VALIDATED",
            reasons=[],
            warnings=[],
            missing_features=[],
        ),
        True,
    )

    df = _make_synthetic_flow_df(4)
    df["MIN_TTL"] = [62.0, 62.0, 62.0, 62.0]
    df["MAX_TTL"] = [62.0, 62.0, 62.0, 62.0]
    df["row_id"] = [101, 102, np.nan, 104]
    csv_path = tmp_path / "float_row_id.csv"
    df.to_csv(csv_path, index=False)

    with (
        patch.object(svc, "_load_inference_pipeline", return_value=fake_pipe),
        patch("network_anomaly.api.desktop_csv._evaluate_gate", return_value=gate_ok),
    ):
        resp = client.post(
            "/api/v1/csv/analyze",
            json={"file_path": str(csv_path), "model_name": "random_forest"},
        )
    assert resp.status_code == 200, resp.text
    row_ids = [item["row_id"] for item in resp.json()["results"]]
    assert row_ids == [101, 102, "row_2", 104]


def test_session_token_middleware_enforces_header_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from network_anomaly.api.main import create_app

    token = "test-session-token-0123456789abcdef"
    monkeypatch.setenv("NETWORK_ANOMALY_API_TOKEN", token)
    secured_app = create_app(db_path=":memory:")
    secured_client = TestClient(secured_app)

    # /health stays available for lightweight liveness check
    health_resp = secured_client.get("/health")
    assert health_resp.status_code == 200

    # /api/v1/* rejects missing or wrong token fail-closed with 401
    unauth_resp = secured_client.get("/api/v1/models")
    assert unauth_resp.status_code == 401
    wrong_resp = secured_client.get(
        "/api/v1/models",
        headers={"X-Sentinel-Session-Token": "wrong-token"},
    )
    assert wrong_resp.status_code == 401

    # Valid session token succeeds
    ok_resp = secured_client.get(
        "/api/v1/models",
        headers={"X-Sentinel-Session-Token": token},
    )
    assert ok_resp.status_code == 200
    assert len(ok_resp.json()) == 4


def test_sensitive_system_path_blocks_program_files_x86_and_programdata():
    from pathlib import PurePosixPath, PureWindowsPath

    from network_anomaly.api.desktop_csv import _is_sensitive_system_path

    assert _is_sensitive_system_path(Path(r"C:\Program Files (x86)\Evil\test.csv")) is True
    assert _is_sensitive_system_path(Path(r"C:\ProgramData\Evil\test.csv")) is True
    assert (
        _is_sensitive_system_path(PureWindowsPath(r"C:\Program Files (x86)\Evil\test.csv")) is True
    )
    assert _is_sensitive_system_path(PurePosixPath(r"C:\Program Files (x86)\Evil\test.csv")) is True
    assert _is_sensitive_system_path(PurePosixPath("/etc/passwd")) is True
    assert (
        _is_sensitive_system_path(Path(r"C:\Users\Alice\AppData\Local\NetFlowSentinelM6\demo.csv"))
        is False
    )


def test_collect_models_status_does_not_mask_missing_manifest_threshold(
    client: TestClient, tmp_path: Path
):
    from unittest.mock import patch

    from network_anomaly.api.desktop_csv import collect_models_status

    svc = client.app.state.service

    class _FakePipe:
        def __init__(self, meta):
            self.model_metadata = meta

    def _fake_load(key: str):
        if key == "random_forest":
            return _FakePipe(
                {
                    "model_type": "RandomForest",
                    "model_artifact_sha256": "a" * 64,
                    "threshold": None,
                    "raw_manifest": {"run_id": "rf-no-thresh"},
                }
            )
        if key == "xgboost":
            return _FakePipe(
                {
                    "model_type": "XGBoost",
                    "model_artifact_sha256": "b" * 64,
                    "threshold": None,
                    "raw_manifest": {
                        "run_id": "xgb-test-thresh",
                        "test_summary": {"decision_threshold": 0.5},
                    },
                }
            )
        raise FileNotFoundError(f"Missing {key}")

    with (
        patch.object(
            svc,
            "_resolve_artifact_paths",
            side_effect=lambda k: (tmp_path / f"{k}.joblib", None, None, None),
        ),
        patch.object(svc, "_load_inference_pipeline", side_effect=_fake_load),
    ):
        items = {item.model_key: item for item in collect_models_status(svc)}

    assert items["random_forest"].ready is True
    assert items["random_forest"].decision_threshold is None
    assert items["xgboost"].ready is True
    assert items["xgboost"].decision_threshold == 0.5
