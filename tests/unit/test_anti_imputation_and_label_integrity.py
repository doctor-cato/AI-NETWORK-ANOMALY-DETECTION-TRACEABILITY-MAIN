"""Unit tests for Anti-Imputation, Finite Values, and Label Integrity."""

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import CanonicalFlowV2Adapter
from network_anomaly.ingestion.adapters.base import BaseSourceAdapter
from network_anomaly.ingestion.compatibility import BenchmarkEvidence, FeatureCompatibilityEvaluator
from network_anomaly.ingestion.gate import InferenceEligibilityGate
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus


def test_nan_feature_rejected_row_level():
    adapter = CanonicalFlowV2Adapter(source_id="source:canonical-flow-v2")
    raw = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    raw["protocol_num"] = 6.0
    raw["bytes_in_ratio"] = 0.5
    raw["pkts_in_ratio"] = 0.5
    raw["bytes_in"] = float("nan")

    event = adapter.adapt_record(raw)
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert "bytes_in" in event.invalid_features
    assert event.invalid_features["bytes_in"] == "non_finite"


def test_inf_feature_rejected_row_level():
    adapter = CanonicalFlowV2Adapter(source_id="source:canonical-flow-v2")
    raw = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    raw["protocol_num"] = 6.0
    raw["duration_ms"] = float("inf")

    event = adapter.adapt_record(raw)
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert "duration_ms" in event.invalid_features
    assert event.invalid_features["duration_ms"] == "non_finite"


def test_invalid_string_token_rejected_row_level():
    adapter = CanonicalFlowV2Adapter(source_id="source:canonical-flow-v2")
    raw = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    raw["protocol_num"] = 6.0
    raw["bytes_out"] = "MALFORMED_HEX_CORRUPT"

    event = adapter.adapt_record(raw)
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert "bytes_out" in event.invalid_features


def test_mixed_valid_and_invalid_rows_matrix_extraction():
    """Verify that extract_ml_matrix isolates only 100% finite valid records, never imputing median/zero."""
    adapter = CanonicalFlowV2Adapter(source_id="source:canonical-flow-v2")

    # Row 0: Clean valid
    rec0 = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec0["protocol_num"] = 6.0
    rec0["bytes_in"] = 100.0

    # Row 1: NaN token in bytes_out
    rec1 = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec1["protocol_num"] = 6.0
    rec1["bytes_out"] = float("nan")

    # Row 2: Corrupted string in bytes_in
    rec2 = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec2["protocol_num"] = 6.0
    rec2["bytes_in"] = "corrupted_text"

    # Row 3: Clean valid
    rec3 = {col: 20.0 for col in ML_FEATURE_COLUMNS}
    rec3["protocol_num"] = 17.0
    rec3["bytes_in"] = 200.0

    events = [
        adapter.adapt_record(rec0, record_idx=0),
        adapter.adapt_record(rec1, record_idx=1),
        adapter.adapt_record(rec2, record_idx=2),
        adapter.adapt_record(rec3, record_idx=3),
    ]

    X_mat, eligible_indices = BaseSourceAdapter.extract_ml_matrix(events)

    # Must extract exactly rows 0 and 3; rows 1 and 2 must be strictly rejected
    assert len(eligible_indices) == 2
    assert eligible_indices == [0, 3]
    assert len(X_mat) == 2
    assert X_mat.isna().sum().sum() == 0
    assert X_mat.iloc[0]["bytes_in"] == 100.0
    assert X_mat.iloc[1]["bytes_in"] == 200.0


def test_missing_mandatory_feature_fails_compatibility():
    adapter = CanonicalFlowV2Adapter(source_id="source:canonical-flow-v2")
    raw = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    del raw["duration_ms"]
    del raw["is_udp"]

    event = adapter.adapt_record(raw)
    assert event.ml_features is None
    assert "duration_ms" in event.missing_features

    evaluator = FeatureCompatibilityEvaluator()
    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert not report.is_eligible_for_inference
    assert "duration_ms" in report.missing_features


def test_failed_external_benchmark_cannot_proceed_to_ml_in_gate():
    """Verify Gate fail-closed block when empirical recall is zero."""
    failed_ev = BenchmarkEvidence(
        source_id="source:ctu-sme-11",
        model_identifier="rf-v2",
        is_passed=False,
        recall=0.0,
        verification_status="FAILED",
        reason="Empirical recall is zero on cross-domain transfer.",
    )
    gate = InferenceEligibilityGate(
        evaluator=FeatureCompatibilityEvaluator(benchmark_registry={"source:ctu-sme-11": failed_ev})
    )
    adapter = CanonicalFlowV2Adapter(source_id="source:ctu-sme-11")
    rec = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6.0
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert decision.can_proceed_to_ml is False
    assert decision.validation_status == ValidationStatus.BENCHMARK_FAILED
    assert decision.eligibility_status == InferenceEligibility.BENCHMARK_UNSATISFACTORY
    assert any(
        "benchmark" in r.lower() or "failed" in r.lower() or "not met" in r.lower()
        for r in decision.abstention_reasons
    )
