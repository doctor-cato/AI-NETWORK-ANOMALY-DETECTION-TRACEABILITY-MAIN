"""Unit tests for FeatureCompatibilityEvaluator, Anti-Imputation, and Benchmark Binding (Issue #46)."""

import math
import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import NetFlowV3Adapter, ZeekConnAdapter
from network_anomaly.ingestion.compatibility import BenchmarkEvidence, FeatureCompatibilityEvaluator
from network_anomaly.ingestion.schemas import (
    FeatureMappingStatus,
    InferenceEligibility,
    ValidationStatus,
)


def test_evaluator_empty_events_returns_schema_invalid():
    evaluator = FeatureCompatibilityEvaluator()
    report = evaluator.evaluate_events([])
    assert report.validation_status == ValidationStatus.PARSEABLE
    assert report.inference_eligibility == InferenceEligibility.SCHEMA_INVALID
    assert not report.is_eligible_for_inference


def test_evaluator_canonical_internal_benchmark_reaches_model_validated():
    """Canonical internal baseline (NF-UNSW-NB15-v3) with verified evidence reaches MODEL_VALIDATED."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")
    rec = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.MODEL_VALIDATED
    assert report.inference_eligibility == InferenceEligibility.PREDICTION_AVAILABLE
    assert report.is_eligible_for_inference is True
    assert len(report.missing_features) == 0
    assert report.feature_statuses["PROTOCOL"] == FeatureMappingStatus.EXACT


def test_evaluator_failed_external_benchmark_blocks_inference_eligibility():
    """External benchmark that failed empirical recall (Recall=0.0) MUST NOT be granted MODEL_VALIDATED."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-external")
    rec = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    # Must be marked BENCHMARK_FAILED, NOT MODEL_VALIDATED
    assert report.validation_status == ValidationStatus.BENCHMARK_FAILED
    assert report.inference_eligibility == InferenceEligibility.BENCHMARK_UNSATISFACTORY
    assert report.is_eligible_for_inference is False
    assert any("failed" in r.lower() or "zero recall" in r.lower() for r in report.rejection_reasons)
    assert report.benchmark_evidence is not None
    assert report.benchmark_evidence.is_passed is False
    assert report.benchmark_evidence.recall == 0.0


def test_evaluator_unbenchmarked_source_is_semantically_compatible_unverified():
    """Complete source without benchmark evidence reaches SEMANTICALLY_COMPATIBLE with VALIDATION_NOT_VERIFIED."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = NetFlowV3Adapter(source_id="source:new-unseen-netflow")
    rec = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.SEMANTICALLY_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.VALIDATION_NOT_VERIFIED
    assert report.is_eligible_for_inference is True


def test_evaluator_anti_imputation_rejects_nan_and_inf_values():
    """Anti-imputation: Any record containing NaN, Inf, or None is rejected row-level."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")

    # Record with NaN in one feature
    rec = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    rec["MIN_TTL"] = float("nan")
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert report.is_eligible_for_inference is False
    assert report.eligible_events_count == 0
    assert "MIN_TTL" in report.missing_features


def test_evaluator_audits_every_row_not_just_first():
    """Row-level completeness: If row 1 is valid but row 2 has missing feature, row 2 is flagged."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-canonical")

    rec1 = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    rec2 = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    del rec2["MAX_TTL"]  # Row 2 is missing MAX_TTL

    ev1 = adapter.adapt_record(rec1)
    ev2 = adapter.adapt_record(rec2)

    report = evaluator.evaluate_events([ev1, ev2])
    assert report.total_events == 2
    assert report.eligible_events_count == 1
    assert "MAX_TTL" in report.missing_features


def test_evaluator_zeek_events_fails_closed_feature_incompatible():
    evaluator = FeatureCompatibilityEvaluator()
    adapter = ZeekConnAdapter()
    event = adapter.adapt_record({"id.orig_h": "10.0.0.1", "id.orig_p": 80, "id.resp_h": "10.0.0.2", "id.resp_p": 80})

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPATIBLE
    assert not report.is_eligible_for_inference
    assert len(report.missing_features) == 47
    assert report.trace_route_eligible is True
    assert report.risk_route_eligible is True
    assert any("anti-imputation" in r.lower() for r in report.rejection_reasons)


def test_evaluator_dataframe_with_nan_fails_anti_imputation():
    evaluator = FeatureCompatibilityEvaluator()
    data = {col: [1.0, 2.0] for col in ML_FEATURE_COLUMNS}
    data["MIN_TTL"][1] = np.nan
    df_with_nan = pd.DataFrame(data)

    report = evaluator.evaluate_dataframe(df_with_nan, source_id="source:nf-v3-canonical")
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert not report.is_eligible_for_inference
    assert "MIN_TTL" in report.missing_features
