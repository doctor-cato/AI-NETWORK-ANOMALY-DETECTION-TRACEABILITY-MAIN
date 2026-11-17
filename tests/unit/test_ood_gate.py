"""Unit tests for OODValidator and InferenceEligibilityGate (v2)."""

import pandas as pd

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import CanonicalFlowV2Adapter, ZeekConnAdapter
from network_anomaly.ingestion.compatibility import BenchmarkEvidence, FeatureCompatibilityEvaluator
from network_anomaly.ingestion.gate import InferenceEligibilityGate
from network_anomaly.ingestion.ood import OODValidator
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus


def test_ood_validator_clean_data():
    validator = OODValidator(check_protocol_drift=True)
    df = pd.DataFrame(
        {
            "duration_ms": [100.0, 50.0],
            "bytes_in": [1500.0, 500.0],
            "bytes_out": [4000.0, 1200.0],
            "pkts_in": [10, 4],
            "pkts_out": [12, 6],
            "bytes_in_ratio": [0.27, 0.29],
            "pkts_in_ratio": [0.45, 0.40],
            "protocol_num": [6, 17],
        }
    )
    report = validator.audit_dataframe(df)
    assert not report.has_ood_warning
    assert report.affected_rows_count == 0
    assert report.hard_violation_count == 0


def test_ood_validator_detects_negative_duration():
    validator = OODValidator()
    df = pd.DataFrame({"duration_ms": [-10.0, 50.0]})
    report = validator.audit_dataframe(df)
    assert report.has_ood_warning
    assert report.hard_violation_count == 1
    assert "duration_ms_negative_or_invalid" in report.out_of_range_details


def test_ood_validator_detects_ratio_out_of_bounds():
    validator = OODValidator()
    df = pd.DataFrame({"bytes_in_ratio": [1.5]})
    report = validator.audit_dataframe(df)
    assert report.has_ood_warning
    assert report.hard_violation_count == 1
    assert "bytes_in_ratio_out_of_bounds" in report.out_of_range_details


def test_ood_validator_detects_unseen_protocol_drift():
    validator = OODValidator(check_protocol_drift=True)
    df = pd.DataFrame({"protocol_num": [6, 99]})
    report = validator.audit_dataframe(df)
    assert report.has_ood_warning
    assert report.unseen_categories == {"protocol_num": [99]}
    assert any("Unseen IP protocol IDs detected" in f for f in report.ood_flags)


def test_eligibility_gate_approves_valid_canonical_v2_flow():
    gate = InferenceEligibilityGate()
    adapter = CanonicalFlowV2Adapter(source_id="source:ait-nds-v2")
    rec = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.PREDICTION_AVAILABLE
    assert decision.validation_status == ValidationStatus.MODEL_VALIDATED
    assert decision.route_to_trace_engine
    assert decision.route_to_risk_engine


def test_eligibility_gate_blocks_benchmark_failed_source():
    """External source with failed benchmark (Recall=0.0) is blocked by the Gate."""
    failed_ev = BenchmarkEvidence(
        source_id="source:ctu-sme-11",
        model_identifier="rf-v2",
        is_passed=False,
        recall=0.0,
        verification_status="FAILED",
        reason="Empirical zero recall on cross-domain transfer.",
    )
    gate = InferenceEligibilityGate(
        evaluator=FeatureCompatibilityEvaluator(
            benchmark_registry={"source:ctu-sme-11": failed_ev}
        )
    )
    adapter = CanonicalFlowV2Adapter(source_id="source:ctu-sme-11")
    rec = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert not decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.BENCHMARK_UNSATISFACTORY
    assert decision.validation_status == ValidationStatus.BENCHMARK_FAILED
    assert any(
        "benchmark" in r.lower() or "failed" in r.lower() or "not met" in r.lower()
        for r in decision.abstention_reasons
    )
    assert decision.route_to_trace_engine is True
    assert decision.route_to_risk_engine is True


def test_eligibility_gate_rejects_zeek_for_ml_but_routes_to_trace_and_risk():
    gate = InferenceEligibilityGate()
    adapter = ZeekConnAdapter()
    event = adapter.adapt_record(
        {"id.orig_h": "1.1.1.1", "id.orig_p": 80, "id.resp_h": "2.2.2.2", "id.resp_p": 80}
    )

    decision = gate.evaluate([event])
    assert not decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.FEATURE_INCOMPATIBLE
    assert decision.route_to_trace_engine is True
    assert decision.route_to_risk_engine is True
    assert any("anti-imputation" in r.lower() for r in decision.abstention_reasons)


def test_eligibility_gate_strict_ood_mode_abstains_on_boundary_violations():
    gate = InferenceEligibilityGate(strict_ood_abstain=True)
    adapter = CanonicalFlowV2Adapter(source_id="source:ait-nds-v2")
    rec = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6
    rec["duration_ms"] = -999.0  # Illegal negative duration
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert not decision.can_proceed_to_ml
    assert decision.eligibility_status == InferenceEligibility.ABSTAINED
    assert any("Hard constraint violation" in r for r in decision.abstention_reasons)
