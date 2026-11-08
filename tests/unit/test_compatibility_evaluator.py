"""Unit tests for FeatureCompatibilityEvaluator (Issue #46)."""

import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import NetFlowV3Adapter, ZeekConnAdapter
from network_anomaly.ingestion.compatibility import FeatureCompatibilityEvaluator
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


def test_evaluator_netflow_v3_benchmarked_reaches_model_validated():
    evaluator = FeatureCompatibilityEvaluator()
    adapter = NetFlowV3Adapter(source_id="source:nf-v3-external")
    rec = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.MODEL_VALIDATED
    assert report.inference_eligibility == InferenceEligibility.PREDICTION_AVAILABLE
    assert report.is_eligible_for_inference
    assert len(report.missing_features) == 0
    assert report.feature_statuses["PROTOCOL"] == FeatureMappingStatus.EXACT


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


def test_evaluator_dataframe_missing_features():
    evaluator = FeatureCompatibilityEvaluator()
    df_partial = pd.DataFrame({"PROTOCOL": [6], "IN_BYTES": [1000]})

    report = evaluator.evaluate_dataframe(df_partial, source_id="source:custom_csv")
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPATIBLE
    assert not report.is_eligible_for_inference
    assert len(report.missing_features) == 45


def test_evaluator_dataframe_full_features():
    evaluator = FeatureCompatibilityEvaluator()
    data = {col: [1.0] for col in ML_FEATURE_COLUMNS}
    df_full = pd.DataFrame(data)

    report = evaluator.evaluate_dataframe(df_full, source_id="source:nf-v3-canonical")
    assert report.validation_status == ValidationStatus.MODEL_VALIDATED
    assert report.inference_eligibility == InferenceEligibility.PREDICTION_AVAILABLE
    assert report.is_eligible_for_inference
