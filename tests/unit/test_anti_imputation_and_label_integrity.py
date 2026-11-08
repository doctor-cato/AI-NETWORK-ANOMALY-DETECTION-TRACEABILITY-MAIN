"""Unit tests for Anti-Imputation, Finite Values, and Label Integrity (Issue #46 Audit)."""

import math
import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import NetFlowV3Adapter
from network_anomaly.ingestion.adapters.base import BaseSourceAdapter
from network_anomaly.ingestion.compatibility import FeatureCompatibilityEvaluator
from network_anomaly.ingestion.gate import InferenceEligibilityGate
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus


def test_nan_feature_rejected_row_level():
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    raw = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    raw["MIN_TTL"] = float("nan")

    event = adapter.adapt_record(raw)
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert "MIN_TTL" in event.invalid_features
    assert event.invalid_features["MIN_TTL"] == "non_finite_nan_or_inf"


def test_inf_feature_rejected_row_level():
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    raw = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    raw["FLOW_DURATION_MILLISECONDS"] = float("inf")

    event = adapter.adapt_record(raw)
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert "FLOW_DURATION_MILLISECONDS" in event.invalid_features
    assert event.invalid_features["FLOW_DURATION_MILLISECONDS"] == "non_finite_nan_or_inf"


def test_invalid_string_token_rejected_row_level():
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    raw = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    raw["TCP_FLAGS"] = "MALFORMED_HEX_CORRUPT"

    event = adapter.adapt_record(raw)
    assert event.ml_features is None
    assert event.eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert "TCP_FLAGS" in event.invalid_features


def test_mixed_valid_and_invalid_rows_matrix_extraction():
    """Verify that extract_ml_matrix isolates only 100% finite valid records, never imputing median/zero."""
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")

    # Row 0: Clean valid
    rec0 = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec0["MIN_TTL"] = 31.0
    rec0["MAX_TTL"] = 64.0

    # Row 1: NaN token in MIN_TTL
    rec1 = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec1["MIN_TTL"] = float("nan")

    # Row 2: Corrupted string in IN_BYTES
    rec2 = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec2["IN_BYTES"] = "corrupted_text"

    # Row 3: Clean valid
    rec3 = {col: 20.0 for col in ML_FEATURE_COLUMNS}
    rec3["MIN_TTL"] = 62.0
    rec3["MAX_TTL"] = 128.0

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
    assert X_mat.iloc[0]["MIN_TTL"] == 31.0
    assert X_mat.iloc[1]["MIN_TTL"] == 62.0


def test_missing_mandatory_feature_fails_compatibility():
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    raw = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    del raw["MIN_IP_PKT_LEN"]  # 46 out of 47 features

    event = adapter.adapt_record(raw)
    assert event.ml_features is None
    assert "MIN_IP_PKT_LEN" in event.missing_features

    evaluator = FeatureCompatibilityEvaluator()
    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert not report.is_eligible_for_inference
    assert "MIN_IP_PKT_LEN" in report.missing_features


def test_failed_external_benchmark_cannot_proceed_to_ml_in_gate():
    """Verify Gate fail-closed block when empirical recall is zero."""
    gate = InferenceEligibilityGate()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-external")
    rec = {col: 10.0 for col in ML_FEATURE_COLUMNS}
    rec["MIN_TTL"] = 31.0
    rec["MAX_TTL"] = 64.0
    event = adapter.adapt_record(rec)

    decision = gate.evaluate([event])
    assert decision.can_proceed_to_ml is False
    assert decision.validation_status == ValidationStatus.BENCHMARK_FAILED
    assert decision.eligibility_status == InferenceEligibility.BENCHMARK_UNSATISFACTORY
    assert any("failed" in r.lower() for r in decision.abstention_reasons)
