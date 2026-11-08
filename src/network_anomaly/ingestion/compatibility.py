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
    """Empirical benchmark evidence binding a specific source domain to a model version and artifacts."""

    source_id: str
    model_identifier: str = "rf-baseline-1794068628"
    model_artifact_sha256: str = "801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea"
    preprocessor_artifact_sha256: str = "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"
    feature_contract_version: str = "nf-unsw-nb15-v3-baseline-47"
    feature_contract_hash: Optional[str] = None
    dataset_name: str = "NF-UNSW-NB15-v3"
    dataset_version: str = "v3"
    dataset_sha256: Optional[str] = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    evaluation_protocol: str = "nf-unsw-nb15-v3-chronological-group-purged-v1"
    split_identity: str = "held-out-test-split"
    recall: float = 0.0
    fpr: float = 0.0
    accuracy: float = 0.0
    metrics: Dict[str, float] = field(default_factory=dict)
    acceptance_criteria: Dict[str, float] = field(default_factory=dict)
    validation_timestamp_utc: str = "2026-11-07T23:23:48Z"
    verification_status: str = "VERIFIED"
    is_passed: bool = False
    reason: str = ""
    model_version: str = ""

    def __post_init__(self) -> None:
        if not self.model_version and self.model_identifier:
            object.__setattr__(self, "model_version", self.model_identifier)
        if not self.metrics:
            object.__setattr__(
                self,
                "metrics",
                {"recall": self.recall, "fpr": self.fpr, "accuracy": self.accuracy},
            )
        if not self.acceptance_criteria:
            object.__setattr__(
                self,
                "acceptance_criteria",
                {"min_recall": 0.85, "max_fpr": 0.05},
            )

    def verify_binding(
        self,
        model_identifier: Optional[str] = None,
        model_artifact_sha256: Optional[str] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        feature_contract_version: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Verify that runtime model, preprocessor, and contract match benchmarked evidence."""
        if model_identifier and model_identifier != self.model_identifier:
            return False, f"Model identifier mismatch: expected '{self.model_identifier}', got '{model_identifier}'"
        if model_artifact_sha256 and model_artifact_sha256 != self.model_artifact_sha256:
            return False, f"Model artifact SHA-256 mismatch: expected '{self.model_artifact_sha256[:12]}...', got '{model_artifact_sha256[:12]}...'"
        if preprocessor_artifact_sha256 and preprocessor_artifact_sha256 != self.preprocessor_artifact_sha256:
            return False, f"Preprocessor artifact SHA-256 mismatch: expected '{self.preprocessor_artifact_sha256[:12]}...', got '{preprocessor_artifact_sha256[:12]}...'"
        if feature_contract_version and feature_contract_version != self.feature_contract_version:
            return False, f"Feature contract version mismatch: expected '{self.feature_contract_version}', got '{feature_contract_version}'"
        if self.verification_status in ("STALE", "EXPIRED", "REVOKED"):
            return False, f"Benchmark evidence status is {self.verification_status}."
        if not self.is_passed:
            return False, f"Benchmark empirical criteria not met: {self.reason}"
        return True, "Benchmark evidence binding verified."


DEFAULT_BENCHMARK_REGISTRY: Dict[str, BenchmarkEvidence] = {
    "source:nf-v3-canonical": BenchmarkEvidence(
        source_id="source:nf-v3-canonical",
        model_identifier="rf-baseline-1794068628",
        model_artifact_sha256="801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea",
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        dataset_name="NF-UNSW-NB15-v3",
        dataset_version="v3",
        dataset_sha256="4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        evaluation_protocol="nf-unsw-nb15-v3-chronological-group-purged-v1",
        split_identity="held-out-test-split",
        recall=0.999850,
        fpr=0.000016,
        accuracy=0.999977,
        metrics={"recall": 0.999850, "fpr": 0.000016, "accuracy": 0.999977},
        acceptance_criteria={"min_recall": 0.85, "max_fpr": 0.05},
        validation_timestamp_utc="2026-11-07T23:23:48Z",
        verification_status="VERIFIED",
        is_passed=True,
        reason="Canonical internal validation passed: Recall 99.98%, FPR 0.0016% on held-out test split.",
    ),
    "source:nf-v3-external": BenchmarkEvidence(
        source_id="source:nf-v3-external",
        model_identifier="rf-baseline-1794068628",
        model_artifact_sha256="801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea",
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        dataset_name="NF-CSE-CIC-IDS2018-v3",
        dataset_version="v3",
        dataset_sha256="4ac221b16bd642b1bdf703f4fc7efb22",
        evaluation_protocol="external-generalization-slice-100k",
        split_identity="sample100k",
        recall=0.000000,
        fpr=0.380191,
        accuracy=0.433990,
        metrics={"recall": 0.000000, "fpr": 0.380191, "accuracy": 0.433990},
        acceptance_criteria={"min_recall": 0.85, "max_fpr": 0.05},
        validation_timestamp_utc="2026-11-08T15:48:03Z",
        verification_status="BENCHMARK_FAILED",
        is_passed=False,
        reason="Empirical external benchmark failed: Zero Recall (0.0%) and high FPR (38.02%) on AWS infrastructure slice.",
    ),
    "source:nf-cse-cic-ids2018-v3": BenchmarkEvidence(
        source_id="source:nf-cse-cic-ids2018-v3",
        model_identifier="rf-baseline-1794068628",
        model_artifact_sha256="801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea",
        preprocessor_artifact_sha256="12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19",
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        dataset_name="NF-CSE-CIC-IDS2018-v3",
        dataset_version="v3",
        dataset_sha256="4ac221b16bd642b1bdf703f4fc7efb22",
        evaluation_protocol="external-generalization-slice-100k",
        split_identity="sample100k",
        recall=0.000000,
        fpr=0.380191,
        accuracy=0.433990,
        metrics={"recall": 0.000000, "fpr": 0.380191, "accuracy": 0.433990},
        acceptance_criteria={"min_recall": 0.85, "max_fpr": 0.05},
        validation_timestamp_utc="2026-11-08T15:48:03Z",
        verification_status="BENCHMARK_FAILED",
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
        """True only if the source reaches a valid state and is certified for inference."""
        return self.inference_eligibility == InferenceEligibility.PREDICTION_AVAILABLE


class FeatureCompatibilityEvaluator:
    """Evaluates multi-source events against the 4-tier validation model and 47-feature ML contract."""

    def __init__(
        self,
        target_features: Optional[List[str]] = None,
        benchmark_registry: Optional[Dict[str, BenchmarkEvidence]] = None,
        expected_model_identifier: Optional[str] = None,
        expected_model_sha256: Optional[str] = None,
        expected_preprocessor_sha256: Optional[str] = None,
        expected_feature_contract: Optional[str] = None,
    ) -> None:
        self.target_features = target_features or list(ML_FEATURE_COLUMNS)
        self.benchmark_registry = (
            benchmark_registry if benchmark_registry is not None else DEFAULT_BENCHMARK_REGISTRY
        )
        self.expected_model_identifier = expected_model_identifier
        self.expected_model_sha256 = expected_model_sha256
        self.expected_preprocessor_sha256 = expected_preprocessor_sha256
        self.expected_feature_contract = expected_feature_contract

    def evaluate_events(
        self,
        events: List[CanonicalNetworkEvent],
        source_id: Optional[str] = None,
        model_identifier: Optional[str] = None,
        model_artifact_sha256: Optional[str] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        feature_contract_version: Optional[str] = None,
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
            eff_model = model_identifier or self.expected_model_identifier
            eff_model_sha = model_artifact_sha256 or self.expected_model_sha256
            eff_prep_sha = preprocessor_artifact_sha256 or self.expected_preprocessor_sha256
            eff_contract = feature_contract_version or self.expected_feature_contract

            is_valid_binding, binding_err = evidence.verify_binding(
                model_identifier=eff_model,
                model_artifact_sha256=eff_model_sha,
                preprocessor_artifact_sha256=eff_prep_sha,
                feature_contract_version=eff_contract,
            )

            if not is_valid_binding:
                val_status = ValidationStatus.BENCHMARK_FAILED
                eligibility = InferenceEligibility.BENCHMARK_UNSATISFACTORY
                rejection_reasons.append(
                    f"Benchmark evidence binding invalid for '{eff_source}': {binding_err}"
                )
            elif evidence.is_passed:
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
            rejection_reasons.append(
                f"Source '{eff_source}' has no empirical benchmark evidence on file (unverified)."
            )

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
        model_identifier: Optional[str] = None,
        model_artifact_sha256: Optional[str] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        feature_contract_version: Optional[str] = None,
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

        # Check for NaN / Inf / non-finite values across target columns
        X_sub = df[self.target_features]
        cols_with_invalid: Dict[str, int] = {}
        row_is_finite = pd.Series(True, index=df.index)

        for col in self.target_features:
            s_num = pd.to_numeric(X_sub[col], errors="coerce")
            finite_s = s_num.notna() & np.isfinite(s_num)
            inv_count = int((~finite_s).sum())
            if inv_count > 0:
                cols_with_invalid[col] = inv_count
            row_is_finite &= finite_s

        rejection_reasons: List[str] = []
        if cols_with_invalid:
            rejection_reasons.append(
                f"Missing, NaN, or non-finite (Inf) values detected in column(s): {list(cols_with_invalid.keys())[:5]}"
            )
            rejection_reasons.append("Strict anti-imputation policy: Zero/median synthetic filling is prohibited.")
            return CompatibilityEvaluationReport(
                source_id=source_id,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                inference_eligibility=InferenceEligibility.FEATURE_INCOMPLETE,
                total_events=len(df),
                eligible_events_count=int(row_is_finite.sum()),
                missing_features=list(cols_with_invalid.keys()),
                feature_statuses={
                    col: FeatureMappingStatus.EXACT if col not in cols_with_invalid else FeatureMappingStatus.MISSING
                    for col in self.target_features
                },
                rejection_reasons=rejection_reasons,
                trace_route_eligible=True,
                risk_route_eligible=True,
            )

        evidence = self.benchmark_registry.get(source_id)
        if evidence is not None:
            eff_model = model_identifier or self.expected_model_identifier
            eff_model_sha = model_artifact_sha256 or self.expected_model_sha256
            eff_prep_sha = preprocessor_artifact_sha256 or self.expected_preprocessor_sha256
            eff_contract = feature_contract_version or self.expected_feature_contract

            is_valid_binding, binding_err = evidence.verify_binding(
                model_identifier=eff_model,
                model_artifact_sha256=eff_model_sha,
                preprocessor_artifact_sha256=eff_prep_sha,
                feature_contract_version=eff_contract,
            )

            if not is_valid_binding:
                val_status = ValidationStatus.BENCHMARK_FAILED
                eligibility = InferenceEligibility.BENCHMARK_UNSATISFACTORY
                rejection_reasons.append(
                    f"Benchmark evidence binding invalid for '{source_id}': {binding_err}"
                )
            elif evidence.is_passed:
                val_status = ValidationStatus.MODEL_VALIDATED
                eligibility = InferenceEligibility.PREDICTION_AVAILABLE
            else:
                val_status = ValidationStatus.BENCHMARK_FAILED
                eligibility = InferenceEligibility.BENCHMARK_UNSATISFACTORY
                rejection_reasons.append(f"Model benchmark failed for '{source_id}': {evidence.reason}")
        else:
            val_status = ValidationStatus.SEMANTICALLY_COMPATIBLE
            eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED
            rejection_reasons.append(
                f"Source '{source_id}' has no empirical benchmark evidence on file (unverified)."
            )

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
