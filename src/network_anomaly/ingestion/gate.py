"""Inference Eligibility and Prediction Abstention Gate (Issue #46).

Enforces fail-closed validation before ML inference:
- Validates schema and semantic compatibility.
- Detects out-of-distribution values and lab shortcut collapse.
- Implements strict anti-imputation policy (no fake 0/median filling).
- Routes ineligible events to Trace and Risk engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters.base import BaseSourceAdapter
from network_anomaly.ingestion.compatibility import (
    CompatibilityEvaluationReport,
    FeatureCompatibilityEvaluator,
)
from network_anomaly.ingestion.exceptions import (
    AbstentionError,
    FeatureIncompatibleError,
    SchemaValidationError,
    SemanticMismatchError,
    SourceUnsupportedError,
)
from network_anomaly.ingestion.ood import OODReport, OODValidator
from network_anomaly.ingestion.registry import SourceRegistry
from network_anomaly.ingestion.schemas import (
    CanonicalNetworkEvent,
    InferenceEligibility,
    ValidationStatus,
)


@dataclass
class GateDecision:
    """Outcome of pre-inference eligibility gate evaluation."""

    can_proceed_to_ml: bool
    eligibility_status: InferenceEligibility
    validation_status: ValidationStatus
    ood_report: Optional[OODReport] = None
    compatibility_report: Optional[CompatibilityEvaluationReport] = None
    abstention_reasons: List[str] = field(default_factory=list)
    warning_flags: List[str] = field(default_factory=list)
    route_to_trace_engine: bool = True
    route_to_risk_engine: bool = True
    accepted_indices: List[int] = field(default_factory=list)
    rejected_indices: List[int] = field(default_factory=list)
    abstained_indices: List[int] = field(default_factory=list)
    row_rejection_reasons: Dict[int, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "can_proceed_to_ml": self.can_proceed_to_ml,
            "eligibility_status": self.eligibility_status.value,
            "validation_status": self.validation_status.value,
            "abstention_reasons": self.abstention_reasons,
            "warning_flags": self.warning_flags,
            "route_to_trace_engine": self.route_to_trace_engine,
            "route_to_risk_engine": self.route_to_risk_engine,
            "accepted_indices": self.accepted_indices,
            "rejected_indices": self.rejected_indices,
            "abstained_indices": self.abstained_indices,
            "row_rejection_reasons": {str(k): v for k, v in self.row_rejection_reasons.items()},
            "ood_summary": self.ood_report.summary() if self.ood_report else None,
        }


class InferenceEligibilityGate:
    """Fail-closed pre-inference gate controlling model access and abstention."""

    def __init__(
        self,
        registry: Optional[SourceRegistry] = None,
        evaluator: Optional[FeatureCompatibilityEvaluator] = None,
        ood_validator: Optional[OODValidator] = None,
        strict_ood_abstain: bool = True,
        max_allowed_shortcut_drift_ratio: float = 0.50,
    ) -> None:
        if not (0.0 <= max_allowed_shortcut_drift_ratio <= 1.0):
            raise ValueError(
                f"max_allowed_shortcut_drift_ratio must be in [0.0, 1.0], got {max_allowed_shortcut_drift_ratio}"
            )
        self.registry = registry or SourceRegistry()
        self.evaluator = evaluator or FeatureCompatibilityEvaluator()
        self.ood_validator = ood_validator or OODValidator(check_shortcut_drift=True)
        self.strict_ood_abstain = strict_ood_abstain
        self.max_allowed_shortcut_drift_ratio = max_allowed_shortcut_drift_ratio

    def evaluate(
        self,
        events: Optional[List[CanonicalNetworkEvent]] = None,
        source_id: Optional[str] = None,
        df: Optional[pd.DataFrame] = None,
        model_identifier: Optional[str] = None,
        model_artifact_sha256: Optional[str] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        feature_contract_version: Optional[str] = None,
        allow_unverified: bool = False,
    ) -> GateDecision:
        """Evaluate events against schema compatibility, network metadata, OOD metrics, and abstention policies."""
        if not events and df is None:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.SCHEMA_INVALID,
                validation_status=ValidationStatus.PARSEABLE,
                abstention_reasons=["No input events provided to gate."],
            )

        eff_source = source_id or (events[0].metadata.source_id if events else "unknown")

        # 1. Source registry check
        try:
            source_def = self.registry.get_source(eff_source)
        except SourceUnsupportedError as err:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.SOURCE_UNSUPPORTED,
                validation_status=ValidationStatus.PARSEABLE,
                abstention_reasons=[str(err)],
                route_to_trace_engine=False,
                route_to_risk_engine=False,
            )

        # 2. Check if source is explicitly unsupported for ML (metadata-only e.g. Zeek, NetFlow v5)
        if not source_def.ml_supported:
            total_n = len(events) if events else (len(df) if df is not None else 0)
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.FEATURE_INCOMPATIBLE,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                abstention_reasons=[
                    f"Source '{eff_source}' is a metadata-only telemetry source and does not provide 47 features for ML.",
                    "Strict anti-imputation policy: Zero/median synthetic filling is prohibited.",
                ],
                route_to_trace_engine=source_def.trace_supported,
                route_to_risk_engine=True,
                rejected_indices=list(range(total_n)),
            )

        # 3. Compatibility Evaluation with artifact binding verification
        if df is not None:
            comp_report = self.evaluator.evaluate_dataframe(
                df,
                source_id=eff_source,
                model_identifier=model_identifier,
                model_artifact_sha256=model_artifact_sha256,
                preprocessor_artifact_sha256=preprocessor_artifact_sha256,
                feature_contract_version=feature_contract_version,
            )
        else:
            comp_report = self.evaluator.evaluate_events(
                events or [],
                source_id=eff_source,
                model_identifier=model_identifier,
                model_artifact_sha256=model_artifact_sha256,
                preprocessor_artifact_sha256=preprocessor_artifact_sha256,
                feature_contract_version=feature_contract_version,
            )

        total_n = len(events) if events else (len(df) if df is not None else 0)

        # Check for benchmark failure (e.g. external source with Recall=0 and high FPR or mismatched hashes)
        if comp_report.validation_status == ValidationStatus.BENCHMARK_FAILED:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.BENCHMARK_UNSATISFACTORY,
                validation_status=ValidationStatus.BENCHMARK_FAILED,
                compatibility_report=comp_report,
                abstention_reasons=comp_report.rejection_reasons,
                route_to_trace_engine=True,
                route_to_risk_engine=True,
                rejected_indices=list(range(total_n)),
            )

        # Check for feature incompleteness (missing columns, NaN/Inf values)
        if comp_report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=comp_report.inference_eligibility,
                validation_status=comp_report.validation_status,
                compatibility_report=comp_report,
                abstention_reasons=comp_report.rejection_reasons,
                route_to_trace_engine=comp_report.trace_route_eligible,
                route_to_risk_engine=comp_report.risk_route_eligible,
                rejected_indices=list(range(total_n)),
            )

        # Unverified benchmark sources: refuse certified inference unless allow_unverified is explicitly granted
        if comp_report.validation_status == ValidationStatus.SEMANTICALLY_COMPATIBLE and not allow_unverified:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.VALIDATION_NOT_VERIFIED,
                validation_status=ValidationStatus.SEMANTICALLY_COMPATIBLE,
                compatibility_report=comp_report,
                abstention_reasons=[
                    f"Source '{eff_source}' is semantically compatible but has no verified empirical benchmark evidence.",
                    "Inference refused fail-closed: Pass allow_unverified=True for uncertified evaluation.",
                ],
                route_to_trace_engine=comp_report.trace_route_eligible,
                route_to_risk_engine=comp_report.risk_route_eligible,
                rejected_indices=list(range(total_n)),
            )

        if not comp_report.is_eligible_for_inference and not allow_unverified:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=comp_report.inference_eligibility,
                validation_status=comp_report.validation_status,
                compatibility_report=comp_report,
                abstention_reasons=comp_report.rejection_reasons,
                route_to_trace_engine=comp_report.trace_route_eligible,
                route_to_risk_engine=comp_report.risk_route_eligible,
                rejected_indices=list(range(total_n)),
            )

        # 4. Extract feature and metadata matrices for OOD & network invariant inspection
        metadata_violations: List[str] = []
        rejected_indices: List[int] = []
        row_rejection_reasons: Dict[int, str] = {}

        if df is not None:
            audit_df = df
            eligible_indices = list(range(len(df)))
        else:
            X_df, eligible_indices = BaseSourceAdapter.extract_ml_matrix(events or [])
            meta_df, _ = BaseSourceAdapter.extract_metadata_dataframe(events or [])
            audit_df = X_df.copy()
            for col in meta_df.columns:
                if col not in audit_df.columns:
                    audit_df[col] = meta_df[col]

            for idx, ev in enumerate(events or []):
                if ev.invalid_metadata:
                    rejected_indices.append(idx)
                    row_rejection_reasons[idx] = f"Invalid metadata: {ev.invalid_metadata}"
                    metadata_violations.append(f"Row {idx}: {ev.invalid_metadata}")
                elif ev.ml_features is None or ev.missing_features or ev.invalid_features:
                    rejected_indices.append(idx)
                    row_rejection_reasons[idx] = "Incomplete or non-finite ML feature vector."

        # 5. OOD & Physical Network Invariant Audit
        ood_report = self.ood_validator.audit_dataframe(audit_df)
        warning_flags = list(ood_report.ood_flags)

        total_hard_violations = ood_report.hard_violation_count + len(metadata_violations)

        # Fail-closed condition A: Hard boundary / physical protocol invariant violation
        if total_hard_violations > 0:
            combined_reasons = []
            if ood_report.hard_violation_count > 0:
                combined_reasons.append(
                    f"Hard constraint violation: {ood_report.hard_violation_count} row(s) violate physical network invariants."
                )
            if metadata_violations:
                combined_reasons.append(
                    f"Hard constraint violation: {len(metadata_violations)} record(s) have invalid network metadata."
                )
            combined_reasons.extend(ood_report.ood_flags[:3])
            combined_reasons.extend(metadata_violations[:3])

            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.ABSTAINED,
                validation_status=comp_report.validation_status,
                ood_report=ood_report,
                compatibility_report=comp_report,
                abstention_reasons=combined_reasons,
                warning_flags=warning_flags,
                route_to_trace_engine=True,
                route_to_risk_engine=True,
                abstained_indices=list(range(total_n)),
                rejected_indices=rejected_indices,
                row_rejection_reasons=row_rejection_reasons,
            )

        # Fail-closed condition B: Critical shortcut drift across batch
        if (
            self.strict_ood_abstain
            and ood_report.shortcut_drift_ratio >= self.max_allowed_shortcut_drift_ratio
        ):
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.ABSTAINED,
                validation_status=comp_report.validation_status,
                ood_report=ood_report,
                compatibility_report=comp_report,
                abstention_reasons=[
                    f"Strict OOD shortcut abstention: {ood_report.shortcut_drift_ratio*100:.1f}% rows exhibit "
                    f"critical MIN_TTL distribution shift (>= {self.max_allowed_shortcut_drift_ratio*100:.0f}% threshold). "
                    "Fail-closed prediction abstention engaged to prevent false alert flood."
                ],
                warning_flags=warning_flags,
                route_to_trace_engine=True,
                route_to_risk_engine=True,
                abstained_indices=list(range(total_n)),
                rejected_indices=rejected_indices,
                row_rejection_reasons=row_rejection_reasons,
            )

        # 7. Approved for inference with row-level tracking
        accepted_set = set(eligible_indices)
        all_indices = set(range(total_n))
        rejected_set = all_indices - accepted_set

        return GateDecision(
            can_proceed_to_ml=True,
            eligibility_status=comp_report.inference_eligibility,
            validation_status=comp_report.validation_status,
            ood_report=ood_report,
            compatibility_report=comp_report,
            warning_flags=warning_flags,
            route_to_trace_engine=True,
            route_to_risk_engine=True,
            accepted_indices=sorted(accepted_set),
            rejected_indices=sorted(rejected_set),
            row_rejection_reasons=row_rejection_reasons,
        )
