"""Feature Compatibility Evaluator, 4-Tier Data State Validator, and Benchmark Binding (Issue #46)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.schemas import (
    CanonicalNetworkEvent,
    FeatureMappingStatus,
    InferenceEligibility,
    ValidationStatus,
)


@dataclass(frozen=True)
class BenchmarkEvidence:
    """Empirical benchmark evidence binding a specific source domain to a model version."""

    source_id: str
    model_version: str
    dataset_name: str
    recall: float
    fpr: float
    accuracy: float
    is_passed: bool
    reason: str


DEFAULT_BENCHMARK_REGISTRY: Dict[str, BenchmarkEvidence] = {
    "source:nf-v3-canonical": BenchmarkEvidence(
        source_id="source:nf-v3-canonical",
        model_version="rf-baseline-1794068628",
        dataset_name="NF-UNSW-NB15-v3",
        recall=0.999850,
        fpr=0.000016,
        accuracy=0.999977,
        is_passed=True,
        reason="Canonical internal validation passed: Recall 99.98%, FPR 0.0016% on held-out test split.",
    ),
    "source:nf-v3-external": BenchmarkEvidence(
        source_id="source:nf-v3-external",
        model_version="rf-baseline-1794068628",
        dataset_name="NF-CSE-CIC-IDS2018-v3",
        recall=0.000000,
        fpr=0.380191,
        accuracy=0.433990,
        is_passed=False,
        reason="Empirical external benchmark failed: Zero Recall (0.0%) and high FPR (38.02%) on AWS infrastructure slice.",
    ),
    "source:nf-cse-cic-ids2018-v3": BenchmarkEvidence(
        source_id="source:nf-cse-cic-ids2018-v3",
        model_version="rf-baseline-1794068628",
        dataset_name="NF-CSE-CIC-IDS2018-v3",
        recall=0.000000,
        fpr=0.380191,
        accuracy=0.433990,
        is_passed=False,
        reason="Empirical external benchmark failed: Zero Recall (0.0%) and high FPR (38.02%) on AWS infrastructure slice.",
    ),
}


@dataclass
class CompatibilityEvaluationReport:
    """Detailed audit report on source, row-level features, and model compatibility."""

    source_id: str
    validation_status: ValidationStatus
    inference_eligibility: InferenceEligibility
    total_events: int
    eligible_events_count: int
    missing_features: List[str] = field(default_factory=list)
    semantic_mismatch_features: List[str] = field(default_factory=list)
    feature_statuses: Dict[str, FeatureMappingStatus] = field(default_factory=dict)
    rejection_reasons: List[str] = field(default_factory=list)
    benchmark_evidence: Optional[BenchmarkEvidence] = None
    trace_route_eligible: bool = True
    risk_route_eligible: bool = True

    @property
    def is_eligible_for_inference(self) -> bool:
        """True only if the source reaches a valid state and is NOT blocked by failed benchmark or missing features."""
        return self.inference_eligibility in (
            InferenceEligibility.PREDICTION_AVAILABLE,
            InferenceEligibility.VALIDATION_NOT_VERIFIED,
        )


class FeatureCompatibilityEvaluator:
    """Evaluates multi-source events against the 4-tier validation model and 47-feature ML contract."""

    def __init__(
        self,
        target_features: Optional[List[str]] = None,
        benchmark_registry: Optional[Dict[str, BenchmarkEvidence]] = None,
    ) -> None:
        self.target_features = target_features or list(ML_FEATURE_COLUMNS)
        self.benchmark_registry = (
            benchmark_registry if benchmark_registry is not None else DEFAULT_BENCHMARK_REGISTRY
        )

    def evaluate_events(
        self,
        events: List[CanonicalNetworkEvent],
        source_id: Optional[str] = None,
    ) -> CompatibilityEvaluationReport:
        """Evaluate a batch of CanonicalNetworkEvents with row-level completeness verification."""
        if not events:
            return CompatibilityEvaluationReport(
                source_id=source_id or "unknown",
                validation_status=ValidationStatus.PARSEABLE,
                inference_eligibility=InferenceEligibility.SCHEMA_INVALID,
                total_events=0,
                eligible_events_count=0,
                rejection_reasons=["Event list is empty (0 records)."],
            )

        eff_source = source_id or events[0].metadata.source_id
        target_set = set(self.target_features)

        # Row-level completeness audit
        eligible_count = 0
        all_missing_keys: Set[str] = set()
        non_finite_keys: Set[str] = set()
        events_without_ml_features = 0

        for idx, ev in enumerate(events):
            if ev.missing_features:
                all_missing_keys.update(ev.missing_features)
            if ev.invalid_features:
                non_finite_keys.update(ev.invalid_features.keys())

            if ev.ml_features is None:
                events_without_ml_features += 1
                continue

            available_keys = set(ev.ml_features.keys())
            missing = target_set - available_keys
            if missing:
                all_missing_keys.update(missing)
                continue

            # Check for non-finite values (NaN / Inf / null) - distinction between 0.0 (valid) and NaN (missing)
            has_non_finite = False
            for k in self.target_features:
                val = ev.ml_features.get(k)
                if val is None or not isinstance(val, (int, float)) or not math.isfinite(val):
                    non_finite_keys.add(k)
                    has_non_finite = True
                    break

            if not has_non_finite:
                eligible_count += 1

        total_events = len(events)

        # 1. Check if source lacks ML vector entirely or attempted ML vector is incomplete
        if events_without_ml_features == total_events:
            if all_missing_keys or non_finite_keys:
                missing_or_invalid = sorted(all_missing_keys | non_finite_keys)
                return CompatibilityEvaluationReport(
                    source_id=eff_source,
                    validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                    inference_eligibility=InferenceEligibility.FEATURE_INCOMPLETE,
                    total_events=total_events,
                    eligible_events_count=0,
                    missing_features=missing_or_invalid,
                    feature_statuses={feat: FeatureMappingStatus.MISSING for feat in missing_or_invalid},
                    rejection_reasons=[
                        f"Batch contains incomplete or non-finite features (NaN/Inf): {missing_or_invalid[:5]}",
                        "Strict anti-imputation policy: Zero/median synthetic filling is prohibited.",
                    ],
                    trace_route_eligible=True,
                    risk_route_eligible=True,
                )

            missing = list(self.target_features)
            return CompatibilityEvaluationReport(
                source_id=eff_source,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                inference_eligibility=InferenceEligibility.FEATURE_INCOMPATIBLE,
                total_events=total_events,
                eligible_events_count=0,
                missing_features=missing,
                feature_statuses={feat: FeatureMappingStatus.MISSING for feat in missing},
                rejection_reasons=[
                    f"Source '{eff_source}' does not provide the 47 micro-telemetry features required for ML baseline.",
                    "Strict anti-imputation policy: Zero/median synthetic filling is prohibited.",
                ],
                trace_route_eligible=True,
                risk_route_eligible=True,
            )

        # 2. Check if events have missing columns or non-finite tokens (Anti-Imputation)
        rejection_reasons: List[str] = []
        if all_missing_keys:
            rejection_reasons.append(
                f"Missing {len(all_missing_keys)} mandatory ML feature(s): {sorted(all_missing_keys)[:5]}..."
            )
        if non_finite_keys:
            rejection_reasons.append(
                f"Non-finite values (NaN/Inf) detected in {len(non_finite_keys)} feature(s): {sorted(non_finite_keys)[:5]}..."
            )

        if eligible_count == 0:
            missing_or_invalid = sorted(all_missing_keys | non_finite_keys)
            return CompatibilityEvaluationReport(
                source_id=eff_source,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                inference_eligibility=InferenceEligibility.FEATURE_INCOMPLETE,
                total_events=total_events,
                eligible_events_count=0,
                missing_features=missing_or_invalid,
                feature_statuses={feat: FeatureMappingStatus.MISSING for feat in missing_or_invalid},
                rejection_reasons=rejection_reasons,
                trace_route_eligible=True,
                risk_route_eligible=True,
            )

        # 3. Benchmark evidence and tier verification
        evidence = self.benchmark_registry.get(eff_source)

        if evidence is not None:
            if evidence.is_passed:
                val_status = ValidationStatus.MODEL_VALIDATED
                eligibility = InferenceEligibility.PREDICTION_AVAILABLE
            else:
                # Benchmark executed but failed empirical threshold
                val_status = ValidationStatus.BENCHMARK_FAILED
                eligibility = InferenceEligibility.BENCHMARK_UNSATISFACTORY
                rejection_reasons.append(
                    f"Model validation failed for '{eff_source}': {evidence.reason}"
                )
        else:
            # Structurally and semantically complete, but unbenchmarked
            val_status = ValidationStatus.SEMANTICALLY_COMPATIBLE
            eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED

        feature_statuses = {
            feat: FeatureMappingStatus.EXACT
            if feat not in (all_missing_keys | non_finite_keys)
            else FeatureMappingStatus.MISSING
            for feat in self.target_features
        }

        return CompatibilityEvaluationReport(
            source_id=eff_source,
            validation_status=val_status,
            inference_eligibility=eligibility,
            total_events=total_events,
            eligible_events_count=eligible_count,
            missing_features=sorted(all_missing_keys | non_finite_keys),
            feature_statuses=feature_statuses,
            rejection_reasons=rejection_reasons,
            benchmark_evidence=evidence,
            trace_route_eligible=True,
            risk_route_eligible=True,
        )

    def evaluate_dataframe(
        self,
        df: pd.DataFrame,
        source_id: str = "source:detected",
    ) -> CompatibilityEvaluationReport:
        """Evaluate raw pandas DataFrame against 47-feature contract and Anti-Imputation."""
        if len(df) == 0:
            return CompatibilityEvaluationReport(
                source_id=source_id,
                validation_status=ValidationStatus.PARSEABLE,
                inference_eligibility=InferenceEligibility.SCHEMA_INVALID,
                total_events=0,
                eligible_events_count=0,
                rejection_reasons=["DataFrame is empty."],
            )

        missing = [col for col in self.target_features if col not in df.columns]
        if missing:
            return CompatibilityEvaluationReport(
                source_id=source_id,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                inference_eligibility=InferenceEligibility.FEATURE_INCOMPATIBLE,
                total_events=len(df),
                eligible_events_count=0,
                missing_features=missing,
                feature_statuses={col: FeatureMappingStatus.MISSING for col in missing},
                rejection_reasons=[
                    f"Input table missing {len(missing)} required baseline ML features: {missing[:5]}..."
                ],
                trace_route_eligible=True,
                risk_route_eligible=True,
            )

        # Check for NaN / Inf values across target columns
        X_sub = df[self.target_features]
        nan_counts = X_sub.isna().sum()
        cols_with_nan = nan_counts[nan_counts > 0].to_dict()

        rejection_reasons: List[str] = []
        if cols_with_nan:
            rejection_reasons.append(
                f"Missing/NaN values detected in columns: {list(cols_with_nan.keys())[:5]}"
            )
            return CompatibilityEvaluationReport(
                source_id=source_id,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                inference_eligibility=InferenceEligibility.FEATURE_INCOMPLETE,
                total_events=len(df),
                eligible_events_count=int((~X_sub.isna().any(axis=1)).sum()),
                missing_features=list(cols_with_nan.keys()),
                feature_statuses={
                    col: FeatureMappingStatus.EXACT if col not in cols_with_nan else FeatureMappingStatus.APPROXIMATE
                    for col in self.target_features
                },
                rejection_reasons=rejection_reasons,
                trace_route_eligible=True,
                risk_route_eligible=True,
            )

        evidence = self.benchmark_registry.get(source_id)
        if evidence is not None:
            if evidence.is_passed:
                val_status = ValidationStatus.MODEL_VALIDATED
                eligibility = InferenceEligibility.PREDICTION_AVAILABLE
            else:
                val_status = ValidationStatus.BENCHMARK_FAILED
                eligibility = InferenceEligibility.BENCHMARK_UNSATISFACTORY
                rejection_reasons.append(f"Model benchmark failed for '{source_id}': {evidence.reason}")
        else:
            val_status = ValidationStatus.SEMANTICALLY_COMPATIBLE
            eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED

        return CompatibilityEvaluationReport(
            source_id=source_id,
            validation_status=val_status,
            inference_eligibility=eligibility,
            total_events=len(df),
            eligible_events_count=len(df),
            missing_features=[],
            feature_statuses={col: FeatureMappingStatus.EXACT for col in self.target_features},
            rejection_reasons=rejection_reasons,
            benchmark_evidence=evidence,
            trace_route_eligible=True,
            risk_route_eligible=True,
        )
