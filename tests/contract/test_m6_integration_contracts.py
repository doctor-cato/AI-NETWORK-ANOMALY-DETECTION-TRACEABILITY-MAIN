"""Contract tests for M6 FastAPI, Streamlit, Risk, and Trace integration interfaces (Issue #46)."""

import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import (
    NetFlowV3Adapter,
    SuricataEveAdapter,
    ZeekConnAdapter,
)
from network_anomaly.ingestion.contracts import (
    APIIngestResponse,
    DashboardViewModel,
    RiskEngineContract,
    TraceEngineContract,
    create_api_response,
    create_dashboard_view_model,
    route_to_risk_engine,
    route_to_trace_engine,
)
from network_anomaly.ingestion.gate import InferenceEligibilityGate
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus


def test_api_ingest_response_contract_approved():
    gate = InferenceEligibilityGate()
    v3_adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    raw = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    raw["MIN_TTL"] = 31.0
    raw["MAX_TTL"] = 64.0
    event = v3_adapter.adapt_record(raw)

    decision = gate.evaluate([event])
    response = create_api_response([event], decision, predictions=[{"row_id": 0, "prediction": 1, "confidence": 0.95}])

    d = response.to_dict()
    assert d["can_proceed_to_ml"] is True
    assert d["validation_status"] == "MODEL_VALIDATED"
    assert d["eligibility_status"] == "PREDICTION_AVAILABLE"
    assert d["total_records"] == 1
    assert d["predictions_count"] == 1
    assert d["predictions"][0]["prediction"] == 1


def test_api_ingest_response_contract_abstained():
    gate = InferenceEligibilityGate()
    zeek_adapter = ZeekConnAdapter()
    event = zeek_adapter.adapt_record({"id.orig_h": "1.1.1.1", "id.orig_p": 80, "id.resp_h": "2.2.2.2", "id.resp_p": 80})

    decision = gate.evaluate([event])
    response = create_api_response([event], decision)

    d = response.to_dict()
    assert d["can_proceed_to_ml"] is False
    assert d["validation_status"] == "SCHEMA_COMPATIBLE"
    assert d["eligibility_status"] == "FEATURE_INCOMPATIBLE"
    assert len(d["abstention_reasons"]) > 0
    assert d["trace_route_eligible"] is True
    assert d["risk_route_eligible"] is True


def test_dashboard_view_model_contract():
    gate = InferenceEligibilityGate()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    raw = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    raw["MIN_TTL"] = 31.0
    raw["MAX_TTL"] = 64.0
    event = adapter.adapt_record(raw)

    decision = gate.evaluate([event])
    vm = create_dashboard_view_model(decision, "NF-UNSW-NB15-v3 Canonical")

    assert vm.tier_badge == "MODEL_VALIDATED"
    assert vm.badge_color == "green"
    assert vm.predictions_available is True
    assert "Model Validated" in vm.summary_message


def test_route_to_trace_engine_contract():
    zeek_adapter = ZeekConnAdapter()
    event = zeek_adapter.adapt_record({
        "uid": "C999",
        "ts": 1600000000.0,
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 5000,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": "1.5",
        "orig_bytes": "500",
    })

    trace_payload = route_to_trace_engine(event)

    assert isinstance(trace_payload, TraceEngineContract)
    assert trace_payload.source_id == "source:zeek-conn"
    assert trace_payload.raw_record_id == "C999"
    assert trace_payload.ipv4_src_addr == "192.168.1.10"
    assert trace_payload.l4_src_port == 5000
    assert trace_payload.ipv4_dst_addr == "10.0.0.1"
    assert trace_payload.l4_dst_port == 443
    assert trace_payload.protocol == 6
    assert trace_payload.has_ml_prediction is False


def test_route_to_risk_engine_contract_with_suricata_alert():
    suricata_adapter = SuricataEveAdapter()
    event = suricata_adapter.adapt_record({
        "timestamp": "2026-11-08T12:00:00Z",
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "src_port": 1234,
        "dest_ip": "5.6.7.8",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {"signature": "ET SCAN", "severity": 1},
    })
    gate = InferenceEligibilityGate()
    decision = gate.evaluate([event])

    risk_payload = route_to_risk_engine(event, decision)

    assert isinstance(risk_payload, RiskEngineContract)
    assert risk_payload.source_id == "source:suricata-eve"
    assert risk_payload.has_ml_prediction is False
    assert len(risk_payload.signature_alerts) == 1
    assert risk_payload.signature_alerts[0]["signature"] == "ET SCAN"
