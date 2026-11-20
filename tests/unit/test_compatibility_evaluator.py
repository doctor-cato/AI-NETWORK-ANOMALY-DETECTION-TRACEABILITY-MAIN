"""Unit tests for FeatureCompatibilityEvaluator, Anti-Imputation, and Benchmark Binding."""

import json

import numpy as np
import pandas as pd

from network_anomaly.data.v2_schema import FEATURE_CONTRACT_ID, ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import CanonicalFlowV2Adapter, ZeekConnAdapter
from network_anomaly.ingestion.compatibility import (
    BenchmarkEvidence,
    FeatureCompatibilityEvaluator,
    load_v2_benchmark_registry,
)
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
    """Canonical internal baseline (AIT-NDS-v2) with verified evidence reaches MODEL_VALIDATED."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = CanonicalFlowV2Adapter(source_id="source:ait-nds-v2")
    rec = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6.0
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.MODEL_VALIDATED
    assert report.inference_eligibility == InferenceEligibility.PREDICTION_AVAILABLE
    assert report.is_eligible_for_inference is True
    assert len(report.missing_features) == 0
    assert report.feature_statuses["protocol_num"] == FeatureMappingStatus.EXACT


def test_evaluator_failed_external_benchmark_blocks_inference_eligibility():
    """External benchmark that failed empirical recall (Recall=0.0) MUST NOT be granted MODEL_VALIDATED."""
    failed_ev = BenchmarkEvidence(
        source_id="source:failed-external",
        model_identifier="rf-v2",
        is_passed=False,
        recall=0.0,
        verification_status="FAILED",
        reason="Empirical zero recall on failed cross-source transfer.",
    )
    evaluator = FeatureCompatibilityEvaluator(
        benchmark_registry={"source:failed-external": failed_ev}
    )
    adapter = CanonicalFlowV2Adapter(source_id="source:failed-external")
    rec = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6.0
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.BENCHMARK_FAILED
    assert report.inference_eligibility == InferenceEligibility.BENCHMARK_UNSATISFACTORY
    assert report.is_eligible_for_inference is False
    assert any(
        "failed" in r.lower() or "zero recall" in r.lower() for r in report.rejection_reasons
    )
    assert report.benchmark_evidence is not None
    assert report.benchmark_evidence.is_passed is False
    assert report.benchmark_evidence.recall == 0.0


def test_evaluator_unbenchmarked_source_is_semantically_compatible_unverified():
    """Complete source without benchmark evidence reaches SEMANTICALLY_COMPATIBLE with VALIDATION_NOT_VERIFIED."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = CanonicalFlowV2Adapter(source_id="source:new-unseen-netflow")
    rec = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6.0
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.SEMANTICALLY_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.VALIDATION_NOT_VERIFIED
    # Unverified benchmark sources are NOT certified for inference fail-closed
    assert report.is_eligible_for_inference is False


def test_evaluator_anti_imputation_rejects_nan_and_inf_values():
    """Anti-imputation: Any record containing NaN, Inf, or None is rejected row-level."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = CanonicalFlowV2Adapter(source_id="source:ait-nds-v2")

    # Record with NaN in one feature
    rec = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec["bytes_in"] = float("nan")
    event = adapter.adapt_record(rec)

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert report.is_eligible_for_inference is False
    assert report.eligible_events_count == 0
    assert "bytes_in" in report.missing_features


def test_evaluator_audits_every_row_not_just_first():
    """Row-level completeness: If row 1 is valid but row 2 has missing feature, row 2 is flagged."""
    evaluator = FeatureCompatibilityEvaluator()
    adapter = CanonicalFlowV2Adapter(source_id="source:ait-nds-v2")

    rec1 = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    rec2 = {col: 0.5 for col in ML_FEATURE_COLUMNS}
    del rec2["bytes_out"]
    del rec2["is_tcp"]  # Ensure not auto-recomputed from base

    ev1 = adapter.adapt_record(rec1)
    ev2 = adapter.adapt_record(rec2)

    report = evaluator.evaluate_events([ev1, ev2])
    assert report.total_events == 2
    assert report.eligible_events_count == 1
    assert "bytes_out" in report.missing_features


def test_evaluator_zeek_events_fails_closed_feature_incompatible():
    evaluator = FeatureCompatibilityEvaluator()
    adapter = ZeekConnAdapter()
    event = adapter.adapt_record(
        {"id.orig_h": "10.0.0.1", "id.orig_p": 80, "id.resp_h": "10.0.0.2", "id.resp_p": 80}
    )

    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPATIBLE
    assert not report.is_eligible_for_inference
    assert len(report.missing_features) == 18
    assert report.trace_route_eligible is True
    assert report.risk_route_eligible is True
    assert any("anti-imputation" in r.lower() for r in report.rejection_reasons)


def test_evaluator_dataframe_with_nan_fails_anti_imputation():
    evaluator = FeatureCompatibilityEvaluator()
    data = {col: [1.0, 2.0] for col in ML_FEATURE_COLUMNS}
    data["bytes_in"][1] = np.nan
    df_with_nan = pd.DataFrame(data)

    report = evaluator.evaluate_dataframe(df_with_nan, source_id="source:ait-nds-v2")
    assert report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE
    assert report.inference_eligibility == InferenceEligibility.FEATURE_INCOMPLETE
    assert not report.is_eligible_for_inference
    assert "bytes_in" in report.missing_features


def _write_synthetic_manifest(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_v2_benchmark_registry_removes_hash_only_fallback_and_enforces_provenance(tmp_path):
    """F-04 regression: hashes alone must NOT grant benchmark_passed; missing hashes/metrics stay UNVALIDATED."""
    # Case 1: random_forest missing artifact_sha256 -> UNVALIDATED
    _write_synthetic_manifest(
        tmp_path / "random_forest_manifest.json",
        {
            "feature_contract_version": FEATURE_CONTRACT_ID,
            "run_id": "rf-no-hash",
            "preprocessor_artifact_sha256": "p" * 64,
            "split_manifest_sha256": "s" * 64,
            "evaluation": {"ait_test": {"recall": 0.99, "false_positive_rate": 0.001}},
        },
    )
    # Case 2: xgboost missing preprocessor_artifact_sha256 -> UNVALIDATED (even as research default)
    _write_synthetic_manifest(
        tmp_path / "xgboost_manifest.json",
        {
            "feature_contract_version": FEATURE_CONTRACT_ID,
            "run_id": "xgb-no-prep",
            "model_artifact_sha256": "m" * 64,
            "split_manifest_sha256": "s" * 64,
            "evaluation": {"ait_test": {"recall": 0.85, "false_positive_rate": 0.001}},
        },
    )
    # Case 3: isolation_forest has hashes & split sha, but NO ait_test and NO benchmark_passed -> UNVALIDATED
    _write_synthetic_manifest(
        tmp_path / "isolation_forest_manifest.json",
        {
            "feature_contract_version": FEATURE_CONTRACT_ID,
            "run_id": "if-hash-only",
            "model_artifact_sha256": "m" * 64,
            "preprocessor_artifact_sha256": "p" * 64,
            "split_manifest_sha256": "s" * 64,
        },
    )

    reg = load_v2_benchmark_registry(manifest_root=tmp_path)
    rf_ev = reg["source:ait-nds-v2::random_forest"]
    assert rf_ev.artifact_verified is False
    assert rf_ev.is_passed is False
    assert rf_ev.verification_status == "UNVALIDATED"
    assert rf_ev.deployment_tier == "RESEARCH_ONLY"

    xgb_ev = reg["source:ait-nds-v2::xgboost"]
    assert xgb_ev.artifact_verified is False
    assert xgb_ev.is_passed is False
    assert xgb_ev.verification_status == "UNVALIDATED"

    if_ev = reg["source:ait-nds-v2::isolation_forest"]
    assert if_ev.artifact_verified is True
    assert if_ev.in_domain_evaluated is False
    assert if_ev.is_passed is False
    assert if_ev.verification_status == "UNVALIDATED"

    # Binding rejects UNVALIDATED evidence even if marked is_research_only=True
    evaluator = FeatureCompatibilityEvaluator(benchmark_registry={"source:ait-nds-v2": if_ev})
    rec = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6.0
    event = CanonicalFlowV2Adapter(source_id="source:ait-nds-v2").adapt_record(rec)
    rep = evaluator.evaluate_events([event])
    assert rep.validation_status == ValidationStatus.BENCHMARK_FAILED
    assert rep.is_eligible_for_inference is False


def test_real_v2_benchmark_registry_separates_in_domain_and_cross_source_tiers():
    """Real v2 manifests keep xgboost RESEARCH_ONLY and keep all 4 models off PRODUCTION_ELIGIBLE."""
    reg = load_v2_benchmark_registry()
    rf_ev = reg["source:ait-nds-v2::random_forest"]
    assert rf_ev.artifact_verified is True
    assert rf_ev.in_domain_evaluated is True
    assert rf_ev.cross_source_validated is False
    assert rf_ev.verification_status == "VERIFIED"
    assert rf_ev.deployment_tier == "RESEARCH_ONLY"

    xgb_ev = reg["source:ait-nds-v2::xgboost"]
    assert xgb_ev.artifact_verified is True
    assert xgb_ev.in_domain_evaluated is True
    assert xgb_ev.cross_source_validated is False
    assert xgb_ev.is_research_only is True
    assert xgb_ev.verification_status == "RESEARCH_ONLY"
    assert xgb_ev.deployment_tier == "RESEARCH_ONLY"
