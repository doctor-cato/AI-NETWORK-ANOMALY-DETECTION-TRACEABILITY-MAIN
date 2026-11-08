"""Integration tests for multi-source ingestion, gate decision, and inference pipeline (Issue #46)."""

import json
from pathlib import Path

import pandas as pd
import pytest

from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import ALL_COLUMNS, ML_FEATURE_COLUMNS
from network_anomaly.inference.predict import (
    load_verified_model,
    load_verified_preprocessor,
)
from network_anomaly.ingestion import (
    BaseSourceAdapter,
    FormatInvalidError,
    FormatSniffer,
    InferenceEligibility,
    InferenceEligibilityGate,
    StreamingChunkParser,
    ValidationStatus,
    check_deployment_readiness,
    create_api_response,
    route_to_trace_engine,
)


@pytest.fixture
def synthetic_files_dir(tmp_path: Path):
    """Generate sample files for multiple formats (NetFlow v3, Zeek, NetFlow v5, malformed)."""
    # 1. NetFlow v3 CSV
    v3_csv = tmp_path / "incoming_v3.csv"
    data = {col: [10.0] * 5 for col in ALL_COLUMNS}
    data["IPV4_SRC_ADDR"] = ["192.168.1.10"] * 5
    data["L4_SRC_PORT"] = [12345] * 5
    data["IPV4_DST_ADDR"] = ["10.0.0.1"] * 5
    data["L4_DST_PORT"] = [80] * 5
    data["PROTOCOL"] = [6] * 5
    data["MIN_TTL"] = [31] * 5
    data["MAX_TTL"] = [64] * 5
    pd.DataFrame(data).to_csv(v3_csv, index=False)

    # 2. Zeek conn.log TSV
    zeek_tsv = tmp_path / "conn.log"
    zeek_lines = [
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n",
        "1518611287.705\tCabc1\t192.168.1.100\t54321\t8.8.8.8\t53\tudp\tdns\t0.05\t100\t200\tSF\n",
        "1518611288.100\tCabc2\t192.168.1.101\t54322\t1.1.1.1\t53\tudp\tdns\t0.02\t80\t160\tSF\n",
    ]
    with open(zeek_tsv, "w", encoding="utf-8") as f:
        f.writelines(zeek_lines)

    # 3. Cisco NetFlow v5 CSV
    v5_csv = tmp_path / "netflow_v5.csv"
    v5_data = {
        "srcaddr": ["10.0.0.1", "10.0.0.2"],
        "dstaddr": ["172.16.0.1", "172.16.0.2"],
        "srcport": [443, 80],
        "dstport": [51000, 52000],
        "prot": [6, 6],
        "dOctets": [1500, 3000],
        "dPkts": [10, 20],
        "first": [100.0, 200.0],
        "last": [105.0, 210.0],
    }
    pd.DataFrame(v5_data).to_csv(v5_csv, index=False)

    # 4. Malformed CSV
    malformed_csv = tmp_path / "corrupted.csv"
    with open(malformed_csv, "w", encoding="utf-8") as f:
        f.write("")

    return {
        "v3_csv": v3_csv,
        "zeek_tsv": zeek_tsv,
        "v5_csv": v5_csv,
        "malformed_csv": malformed_csv,
    }


def test_deployment_readiness():
    """Verify backend deployment contract and readiness reporting."""
    report = check_deployment_readiness()
    assert isinstance(report.environment_info, dict)
    assert "python_version" in report.environment_info
    model_file = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
    prep_file = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    if model_file.exists() and prep_file.exists():
        assert report.is_ready is True
        assert report.model_status == "READY"
        assert report.preprocessor_status == "READY"
        assert len(report.blockers) == 0
    else:
        assert report.is_ready is False
        assert len(report.blockers) > 0


def test_multi_source_netflow_v3_end_to_end_inference(synthetic_files_dir: dict, tmp_path: Path):
    """End-to-end flow: Ingest NetFlow v3 -> Gate -> ML Prediction -> Unified Response."""
    v3_csv = synthetic_files_dir["v3_csv"]
    parser = StreamingChunkParser(chunk_size=10)
    gate = InferenceEligibilityGate()

    # Load canonical artifacts
    m_path = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
    m_man = PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
    p_path = ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    p_man = PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"

    if not m_path.is_file() or not p_path.is_file():
        pytest.skip("Canonical model/preprocessor binary artifacts excluded via .gitignore policy.")

    prep, _ = load_verified_preprocessor(p_path, manifest_path=p_man)
    model, _ = load_verified_model(m_path, manifest_path=m_man)

    all_preds = []
    for chunk_events in parser.parse_file_chunks(v3_csv):
        decision = gate.evaluate(chunk_events)
        assert decision.can_proceed_to_ml is True
        assert decision.eligibility_status == InferenceEligibility.PREDICTION_AVAILABLE
        assert decision.validation_status == ValidationStatus.MODEL_VALIDATED

        # Extract features and transform
        X_df, idxs = BaseSourceAdapter.extract_ml_matrix(chunk_events)
        X_trans = prep.transform(X_df)
        preds = model.predict(X_trans)

        chunk_preds = [{"row_id": i, "prediction": int(p)} for i, p in zip(idxs, preds)]
        all_preds.extend(chunk_preds)

        response = create_api_response(chunk_events, decision, predictions=chunk_preds)
        assert response.can_proceed_to_ml is True
        assert response.predictions_count == len(chunk_events)

    assert len(all_preds) == 5


def test_multi_source_zeek_abstention_and_trace_routing(synthetic_files_dir: dict):
    """End-to-end flow: Ingest Zeek TSV -> Gate -> Abstain ML -> Route to Trace Engine."""
    zeek_tsv = synthetic_files_dir["zeek_tsv"]
    parser = StreamingChunkParser(chunk_size=10)
    gate = InferenceEligibilityGate()

    trace_records = []
    for chunk_events in parser.parse_file_chunks(zeek_tsv):
        decision = gate.evaluate(chunk_events)
        assert decision.can_proceed_to_ml is False
        assert decision.eligibility_status == InferenceEligibility.FEATURE_INCOMPATIBLE
        assert decision.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
        assert decision.route_to_trace_engine is True

        for event in chunk_events:
            trace_contract = route_to_trace_engine(event)
            trace_records.append(trace_contract)

        response = create_api_response(chunk_events, decision)
        assert response.can_proceed_to_ml is False
        assert response.predictions_count == 0
        assert len(response.abstention_reasons) > 0

    assert len(trace_records) == 2
    assert trace_records[0].raw_record_id == "Cabc1"
    assert trace_records[0].ipv4_src_addr == "192.168.1.100"


def test_multi_source_netflow_v5_abstention(synthetic_files_dir: dict):
    """End-to-end flow: Ingest NetFlow v5 -> Gate -> Abstain ML."""
    v5_csv = synthetic_files_dir["v5_csv"]
    parser = StreamingChunkParser(chunk_size=10)
    gate = InferenceEligibilityGate()

    for chunk_events in parser.parse_file_chunks(v5_csv):
        decision = gate.evaluate(chunk_events)
        assert decision.can_proceed_to_ml is False
        assert decision.eligibility_status == InferenceEligibility.FEATURE_INCOMPATIBLE
        assert any("NetFlow v5" in r or "anti-imputation" in r.lower() for r in decision.abstention_reasons)


def test_format_sniffer_empty_file_fails(synthetic_files_dir: dict):
    """Empty file raises FormatInvalidError."""
    malformed_csv = synthetic_files_dir["malformed_csv"]
    sniffer = FormatSniffer()
    with pytest.raises(FormatInvalidError, match="empty"):
        sniffer.inspect_file(malformed_csv)
