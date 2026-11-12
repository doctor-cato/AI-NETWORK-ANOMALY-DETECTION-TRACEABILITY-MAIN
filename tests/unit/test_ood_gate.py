"""Unit tests for OODValidator and InferenceEligibilityGate (Issue #46)."""

import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import NetFlowV3Adapter, ZeekConnAdapter
from network_anomaly.ingestion.gate import InferenceEligibilityGate
from network_anomaly.ingestion.ood import OODValidator
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus


def test_ood_validator_clean_data():
    validator = OODValidator(check_shortcut_drift=True)
    df = pd.DataFrame({
        "FLOW_DURATION_MILLISECONDS": [100.0, 50.0],
        "MIN_TTL": [31, 62],  # Valid lab shortcuts
        "MAX_TTL": [64, 128],
        "LONGEST_FLOW_PKT": [1500, 1000],
        "SHORTEST_FLOW_PKT": [64, 40],
        "PROTOCOL": [6, 17],
    })
    report = validator.audit_dataframe(df)
    assert not report.has_ood_warning
    assert report.affected_rows_count == 0
    assert report.hard_violation_count == 0
    assert report.shortcut_shift_count == 0


def test_ood_validator_detects_negative_duration():
    validator = OODValidator()
    df = pd.DataFrame({
        "FLOW_DURATION_MILLISECONDS": [-10.0, 50.0],
    })
    report = validator.audit_dataframe(df)
    assert report.has_ood_warning
    assert report.hard_violation_count == 1
    assert "FLOW_DURATION_MILLISECONDS_negative" in report.out_of_range_details


def test_ood_validator_detects_inverted_ttl():
    validator = OODValidator()
    df = pd.DataFrame({
        "MIN_TTL": [100],
        "MAX_TTL": [50],  # MIN > MAX
    })
    report = validator.audit_dataframe(df)
    assert report.has_ood_warning
    assert report.hard_violation_count == 1
    assert "MIN_TTL_greater_than_MAX_TTL" in report.out_of_range_details


def test_ood_validator_detects_shortcut_drift_and_zero_ttl():
    validator = OODValidator(check_shortcut_drift=True)
    df = pd.DataFrame({
        "MIN_TTL": [0, 0, 128],  # None are in {31, 62, 254, 255}
        "MAX_TTL": [64, 64, 128],
    })
    report = validator.audit_dataframe(df)
    assert report.has_ood_warning
    assert report.shortcut_shift_count == 3
    assert report.zero_ttl_count == 2
    assert report.shortcut_drift_ratio == 1.0
    assert any("Shortcut shift" in f for f in report.ood_flags)
    assert any("MIN_TTL=0" in f for f in report.ood_flags)


def test_eligibility_gate_approves_valid_canonical_netflow_v3():
    gate = InferenceEligibilityGate()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    rec = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec["MIN_TTL"] = 31
    rec["MAX_TTL"] = 64
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.PREDICTION_AVAILABLE
    assert decision.validation_status == ValidationStatus.MODEL_VALIDATED
    assert decision.route_to_trace_engine
    assert decision.route_to_risk_engine


def test_eligibility_gate_blocks_benchmark_failed_source():
    """External source with failed benchmark (Recall=0.0) is blocked by the Gate."""
    gate = InferenceEligibilityGate()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-external")
    rec = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec["MIN_TTL"] = 31
    rec["MAX_TTL"] = 64
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert not decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.BENCHMARK_UNSATISFACTORY
    assert decision.validation_status == ValidationStatus.BENCHMARK_FAILED
    assert any("failed" in r.lower() for r in decision.abstention_reasons)
    assert decision.route_to_trace_engine is True
    assert decision.route_to_risk_engine is True


def test_eligibility_gate_rejects_zeek_for_ml_but_routes_to_trace_and_risk():
    gate = InferenceEligibilityGate()
    adapter = ZeekConnAdapter()
    event = adapter.adapt_record({"id.orig_h": "1.1.1.1", "id.orig_p": 80, "id.resp_h": "2.2.2.2", "id.resp_p": 80})

    decision = gate.evaluate([event])
    assert not decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.FEATURE_INCOMPATIBLE
    assert decision.route_to_trace_engine is True
    assert decision.route_to_risk_engine is True
    assert any("anti-imputation" in r.lower() for r in decision.abstention_reasons)


def test_eligibility_gate_strict_ood_mode_abstains_on_boundary_violations():
    gate = InferenceEligibilityGate(strict_ood_abstain=True)
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    rec = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec["MIN_TTL"] = 31
    rec["MAX_TTL"] = 64
    rec["FLOW_DURATION_MILLISECONDS"] = -999.0  # Illegal negative duration
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert not decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.ABSTAINED
    assert any("Hard constraint violation" in r for r in decision.abstention_reasons)


def test_eligibility_gate_abstains_on_critical_shortcut_drift():
    """Gate triggers fail-closed abstention when shortcut drift ratio exceeds threshold."""
    gate = InferenceEligibilityGate(strict_ood_abstain=True, max_allowed_shortcut_drift_ratio=0.50)
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    rec = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec["MIN_TTL"] = 0  # Shortcut drift (not in 31, 62, 254, 255)
    rec["MAX_TTL"] = 64
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert not decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.ABSTAINED
    assert any("Strict OOD shortcut abstention" in r for r in decision.abstention_reasons)
