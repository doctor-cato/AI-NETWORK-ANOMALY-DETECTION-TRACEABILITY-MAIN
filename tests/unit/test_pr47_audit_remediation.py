"""Comprehensive unit tests verifying all PR #47 audit remediation fixes (P0-01, P0-02, P1-01, P1-02, P1-03)."""

import math
import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import BaseSourceAdapter, NetFlowV3Adapter
from network_anomaly.ingestion.compatibility import (
    BenchmarkEvidence,
    DEFAULT_BENCHMARK_REGISTRY,
    FeatureCompatibilityEvaluator,
)
from network_anomaly.ingestion.gate import InferenceEligibilityGate
from network_anomaly.ingestion.ood import OODValidator
from network_anomaly.ingestion.schemas import (
    CanonicalNetworkEvent,
    InferenceEligibility,
    ValidationStatus,
)


def _make_clean_record(source_id: str = "source:nf-v3-canonical") -> dict:
    rec = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec["MIN_TTL"] = 31
    rec["MAX_TTL"] = 64
    rec["L4_SRC_PORT"] = 12345
    rec["L4_DST_PORT"] = 80
    rec["PROTOCOL"] = 6
    rec["IPV4_SRC_ADDR"] = "192.168.1.10"
    rec["IPV4_DST_ADDR"] = "10.0.0.1"
    rec["FLOW_DURATION_MILLISECONDS"] = 125.0
    rec["IN_BYTES"] = 500
    rec["IN_PKTS"] = 5
    return rec


# ---------------------------------------------------------------------------
# P0-01: Benchmark Evidence Binding & Verification Tests
# ---------------------------------------------------------------------------

def test_benchmark_evidence_binding_verification():
    """Verify BenchmarkEvidence binding against artifact SHA-256 hashes and contract."""
    evidence = DEFAULT_BENCHMARK_REGISTRY["source:nf-v3-canonical"]

    # 1. Matching hashes pass
    valid, msg = evidence.verify_binding(
        model_identifier="rf-baseline-1794068628",
        model_artifact_sha256="801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea",
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
    )
    assert valid is True
    assert "verified" in msg.lower()

    # 2. Mismatched model artifact SHA-256 fails
    valid, msg = evidence.verify_binding(
        model_artifact_sha256="deadbeef" * 8,
    )
    assert valid is False
    assert "Model artifact SHA-256 mismatch" in msg

    # 3. Mismatched preprocessor artifact SHA-256 fails
    valid, msg = evidence.verify_binding(
        preprocessor_artifact_sha256="deadbeef" * 8,
    )
    assert valid is False
    assert "Preprocessor artifact SHA-256 mismatch" in msg

    # 4. Mismatched feature contract fails
    valid, msg = evidence.verify_binding(
        feature_contract_version="nf-unsw-nb15-v3-baseline-41",
    )
    assert valid is False
    assert "Feature contract version mismatch" in msg

    # 5. Stale / Expired evidence fails
    stale_evidence = BenchmarkEvidence(
        source_id="source:stale",
        verification_status="STALE",
        is_passed=True,
    )
    valid, msg = stale_evidence.verify_binding()
    assert valid is False
    assert "STALE" in msg


def test_evaluator_rejects_mismatched_model_hash():
    """Evaluator fails closed when runtime model SHA-256 does not match benchmark evidence."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    event = adapter.adapt_record(_make_clean_record())

    # Passing mismatched hash
    report = evaluator.evaluate_events(
        [event],
        model_artifact_sha256="0000000000000000000000000000000000000000000000000000000000000000",
    )
    assert report.validation_status == ValidationStatus.BENCHMARK_FAILED
    assert report.inference_eligibility == InferenceEligibility.BENCHMARK_UNSATISFACTORY
    assert report.is_eligible_for_inference is False
    assert any("mismatch" in r.lower() for r in report.rejection_reasons)


def test_unverified_benchmark_fails_closed_in_gate():
    """Unbenchmarked source reaches SEMANTICALLY_COMPATIBLE but is blocked fail-closed from certified inference."""
    from network_anomaly.data.nf_unsw_nb15_v3 import ALL_COLUMNS
    from network_anomaly.ingestion.registry import SourceDefinition, SourceRegistry

    registry = SourceRegistry()
    registry.register(
        SourceDefinition(
            source_id="source:new-unseen-telemetry",
            name="New Unseen NetFlow v3",
            physical_format="csv",
            schema_version="1.0.0",
            ml_supported=True,
            trace_supported=True,
            description="Complete NetFlow v3 from an unseen network without benchmark evidence.",
            expected_columns=list(ALL_COLUMNS),
            adapter_name="NetFlowV3Adapter",
        )
    )

    gate = InferenceEligibilityGate(registry=registry)
    adapter = NetFlowV3Adapter(source_id="source:new-unseen-telemetry")
    event = adapter.adapt_record(_make_clean_record())

    # Default: allow_unverified=False -> Gate blocks inference
    decision = gate.evaluate([event])
    assert decision.can_proceed_to_ml is False
    assert decision.validation_status == ValidationStatus.SEMANTICALLY_COMPATIBLE
    assert decision.eligibility_status == InferenceEligibility.VALIDATION_NOT_VERIFIED    assert any("uncertified" in r.lower() or "unverified" in r.lower() for r in decision.abstention_reasons)

    # Explicit opt-in for experimental exploration allows uncertified inference
    decision_optin = gate.evaluate([event], allow_unverified=True)
    assert decision_optin.can_proceed_to_ml is True
    assert decision_optin.validation_status == ValidationStatus.SEMANTICALLY_COMPATIBLE


# ---------------------------------------------------------------------------
# P0-02: Network Metadata Validation & Out-of-Range Port Tests
# ---------------------------------------------------------------------------

def test_gate_actually_validates_metadata_ports_out_of_range():
    """Verify that OODValidator and Gate inspect metadata and reject ports outside [0, 65535]."""
    gate = InferenceEligibilityGate()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")

    # Case A: L4_SRC_PORT > 65535
    rec_high = _make_clean_record()
    rec_high["L4_SRC_PORT"] = 70000
    ev_high = adapter.adapt_record(rec_high)

    decision_high = gate.evaluate([ev_high])
    assert decision_high.can_proceed_to_ml is False
    assert decision_high.eligibility_status == InferenceEligibility.ABSTAINED
    assert any("Port out of range" in r for r in decision_high.abstention_reasons)

    # Case B: L4_DST_PORT < 0
    rec_neg = _make_clean_record()
    rec_neg["L4_DST_PORT"] = -1
    ev_neg = adapter.adapt_record(rec_neg)

    decision_neg = gate.evaluate([ev_neg])
    assert decision_neg.can_proceed_to_ml is False
    assert decision_neg.eligibility_status == InferenceEligibility.ABSTAINED
    assert any("Port out of range" in r for r in decision_neg.abstention_reasons)


def test_gate_validates_protocol_out_of_range():
    """Verify that invalid IP protocol numbers outside [0, 255] trigger ABSTAINED."""
    gate = InferenceEligibilityGate()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")

    rec = _make_clean_record()
    rec["PROTOCOL"] = 999  # Invalid IP protocol
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert decision.can_proceed_to_ml is False
    assert decision.eligibility_status == InferenceEligibility.ABSTAINED
    assert any("Protocol number out of range" in r for r in decision.abstention_reasons)


# ---------------------------------------------------------------------------
# P1-01: Anti-Imputation and DataFrame Inf Handling
# ---------------------------------------------------------------------------

def test_evaluate_dataframe_anti_imputation_handles_inf_and_nan():
    """Verify evaluate_dataframe strictly catches positive/negative infinity and NaN."""
    evaluator = FeatureCompatibilityEvaluator()

    # 1. Positive Infinity
    df_pos_inf = pd.DataFrame([{col: 1.0 for col in ML_FEATURE_COLUMNS}])
    df_pos_inf["MIN_TTL"] = np.inf
    report_pos = evaluator.evaluate_dataframe(df_pos_inf, source_id="source:nf-v3-canonical")
    assert report_pos.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report_pos.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert not report_pos.is_eligible_for_inference
    assert "MIN_TTL" in report_pos.missing_features

    # 2. Negative Infinity
    df_neg_inf = pd.DataFrame([{col: 1.0 for col in ML_FEATURE_COLUMNS}])
    df_neg_inf["FLOW_DURATION_MILLISECONDS"] = -np.inf
    report_neg = evaluator.evaluate_dataframe(df_neg_inf, source_id="source:nf-v3-canonical")
    assert report_neg.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report_neg.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert "FLOW_DURATION_MILLISECONDS" in report_neg.missing_features

    # 3. Non-numeric corrupt token
    df_corrupt = pd.DataFrame([{col: 1.0 for col in ML_FEATURE_COLUMNS}])
    df_corrupt["TCP_FLAGS"] = "MALFORMED_TOKEN"
    report_token = evaluator.evaluate_dataframe(df_corrupt, source_id="source:nf-v3-canonical")
    assert report_token.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report_token.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert "TCP_FLAGS" in report_token.missing_features


# ---------------------------------------------------------------------------
# P1-02: Row-Level / Batch-Level Eligibility & Row Identity Preservation
# ---------------------------------------------------------------------------

def test_mixed_batch_row_level_preservation_and_no_benign_leak():
    """Verify mixed valid/invalid batch keeps row identities and never marks rejected rows as Benign."""
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")

    # Row 0: Valid
    ev0 = adapter.adapt_record(_make_clean_record(), record_idx=100)

    # Row 1: Incomplete (NaN)
    rec1 = _make_clean_record()
    rec1["MIN_TTL"] = float("nan")
    ev1 = adapter.adapt_record(rec1, record_idx=101)

    # Row 2: Incomplete (Missing column)
    rec2 = _make_clean_record()
    del rec2["MAX_IP_PKT_LEN"]
    ev2 = adapter.adapt_record(rec2, record_idx=102)

    # Row 3: Valid
    rec3 = _make_clean_record()
    rec3["MIN_TTL"] = 62
    ev3 = adapter.adapt_record(rec3, record_idx=103)

    events = [ev0, ev1, ev2, ev3]

    X_mat, eligible_indices = BaseSourceAdapter.extract_ml_matrix(events)

    # Only rows 0 and 3 extracted
    assert eligible_indices == [0, 3]
    assert len(X_mat) == 2
    assert X_mat.iloc[0]["MIN_TTL"] == 31.0
    assert X_mat.iloc[1]["MIN_TTL"] == 62.0

    # Simulated model prediction
    fake_preds = [1, 1]  # Attack
    mapped_predictions = [
        {"row_id": orig_idx, "prediction": pred}
        for orig_idx, pred in zip(eligible_indices, fake_preds)
    ]

    # Only rows 0 and 3 have predictions
    assert [p["row_id"] for p in mapped_predictions] == [0, 3]
    # Rows 1 and 2 are never assigned predictions or assumed Benign
    assert all(p["row_id"] not in (1, 2) for p in mapped_predictions)


# ---------------------------------------------------------------------------
# P1-03: OOD Threshold Edge Cases & Audit
# ---------------------------------------------------------------------------

def test_ood_threshold_edge_cases():
    """Verify OOD threshold validation for edge cases (0.0, 1.0, out of range)."""
    # Valid boundaries
    gate_0 = InferenceEligibilityGate(max_allowed_shortcut_drift_ratio=0.0)
    assert gate_0.max_allowed_shortcut_drift_ratio == 0.0

    gate_1 = InferenceEligibilityGate(max_allowed_shortcut_drift_ratio=1.0)
    assert gate_1.max_allowed_shortcut_drift_ratio == 1.0

    # Invalid boundaries raise ValueError
    with pytest.raises(ValueError, match="must be in"):
        InferenceEligibilityGate(max_allowed_shortcut_drift_ratio=-0.05)

    with pytest.raises(ValueError, match="must be in"):
        InferenceEligibilityGate(max_allowed_shortcut_drift_ratio=1.05)


def test_ood_report_abstention_rate_and_coverage():
    """Verify OODReport calculates abstention_rate and prediction_coverage accurately."""
    validator = OODValidator(check_shortcut_drift=True)
    df = pd.DataFrame({
        "FLOW_DURATION_MILLISECONDS": [-1.0, 50.0, 100.0, 20.0],  # 1 hard violation out of 4
        "MIN_TTL": [31, 62, 31, 31],
        "MAX_TTL": [64, 64, 64, 64],
    })
    report = validator.audit_dataframe(df)
    assert report.total_rows == 4
    assert report.hard_violation_count == 1
    assert report.abstention_rate == 0.25
    assert report.prediction_coverage == 0.75


# ---------------------------------------------------------------------------
# Multi-Model OOD Gate & Research-Only Isolation Tests
# ---------------------------------------------------------------------------

def test_multi_model_benchmark_registry_and_binding():
    """Verify registry has distinct records for RF, XGBoost, IF, and Autoencoder."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    clean_event = adapter.adapt_record(_make_clean_record())

    # 1. Random Forest verification passes
    rf_report = evaluator.evaluate_events(
        [clean_event],
        model_identifier="rf-baseline-1794068628",
        model_artifact_sha256="801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea",
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
    )
    assert rf_report.validation_status == ValidationStatus.MODEL_VALIDATED
    assert rf_report.is_eligible_for_inference is True
    assert rf_report.risk_route_eligible is True

    # 2. XGBoost verification passes
    xgb_report = evaluator.evaluate_events(
        [clean_event],
        model_identifier="xgb-baseline-canonical-v1",
        model_artifact_sha256="c70ec52fb3229ccca680f70356e0a8c44e0b16ff7988c5e6fb91da3383eabd6e",
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
    )
    assert xgb_report.validation_status == ValidationStatus.MODEL_VALIDATED
    assert xgb_report.is_eligible_for_inference is True
    assert xgb_report.risk_route_eligible is True

    # 3. Isolation Forest is research-only by default -> UNVALIDATED without allow_research_only
    if_report = evaluator.evaluate_events(
        [clean_event],
        model_identifier="if-baseline-canonical-v1",
        model_artifact_sha256="0" * 64,
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_research_only=False,
    )
    assert if_report.validation_status == ValidationStatus.UNVALIDATED
    assert if_report.inference_eligibility == InferenceEligibility.VALIDATION_NOT_VERIFIED

    # 4. Isolation Forest with allow_research_only=True -> RESEARCH_ONLY and risk_route_eligible is False
    if_research_report = evaluator.evaluate_events(
        [clean_event],
        model_identifier="if-baseline-canonical-v1",
        model_artifact_sha256="0" * 64,
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_research_only=True,
    )
    assert if_research_report.validation_status == ValidationStatus.RESEARCH_ONLY
    assert if_research_report.inference_eligibility == InferenceEligibility.RESEARCH_ONLY
    assert if_research_report.is_eligible_for_inference is True
    assert if_research_report.risk_route_eligible is False

    # 5. Autoencoder with allow_research_only=True -> RESEARCH_ONLY and risk_route_eligible is False
    ae_research_report = evaluator.evaluate_events(
        [clean_event],
        model_identifier="ae-baseline-canonical-v1",
        model_artifact_sha256="0" * 64,
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_research_only=True,
    )
    assert ae_research_report.validation_status == ValidationStatus.RESEARCH_ONLY
    assert ae_research_report.risk_route_eligible is False


def test_gate_research_only_routing_isolation():
    """Verify Gate allows research inference but strictly disables Risk Engine routing."""
    gate = InferenceEligibilityGate()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    clean_event = adapter.adapt_record(_make_clean_record())

    # Fail-closed without allow_research_only
    decision_closed = gate.evaluate(
        [clean_event],
        model_identifier="if-baseline-canonical-v1",
        model_artifact_sha256="0" * 64,
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_research_only=False,
    )
    assert decision_closed.can_proceed_to_ml is False
    assert decision_closed.validation_status == ValidationStatus.UNVALIDATED
    assert decision_closed.route_to_risk_engine is False

    # Allowed with allow_research_only=True, but route_to_risk_engine is False
    decision_research = gate.evaluate(
        [clean_event],
        model_identifier="if-baseline-canonical-v1",
        model_artifact_sha256="0" * 64,
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_research_only=True,
    )
    assert decision_research.can_proceed_to_ml is True
    assert decision_research.validation_status == ValidationStatus.RESEARCH_ONLY
    assert decision_research.route_to_trace_engine is True
    assert decision_research.route_to_risk_engine is False


def test_gate_prevents_cross_model_benchmark_inheritance():
    """Requesting an unbenchmarked model on a source with RF evidence does NOT inherit RF validation."""
    gate = InferenceEligibilityGate()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    clean_event = adapter.adapt_record(_make_clean_record())

    decision = gate.evaluate(
        [clean_event],
        model_identifier="some-unknown-neural-net",
        model_artifact_sha256="1" * 64,
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
    )
    assert decision.can_proceed_to_ml is False
    assert decision.validation_status == ValidationStatus.SEMANTICALLY_COMPATIBLE
    assert decision.eligibility_status == InferenceEligibility.VALIDATION_NOT_VERIFIED
