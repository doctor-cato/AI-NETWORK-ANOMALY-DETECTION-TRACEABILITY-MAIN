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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "can_proceed_to_ml": self.can_proceed_to_ml,
            "eligibility_status": self.eligibility_status.value,
            "validation_status": self.validation_status.value,
            "abstention_reasons": self.abstention_reasons,
            "warning_flags": self.warning_flags,
            "route_to_trace_engine": self.route_to_trace_engine,
            "route_to_risk_engine": self.route_to_risk_engine,
            "ood_summary": self.ood_report.summary() if self.ood_report else None,
        }


class InferenceEligibilityGate:
    """Fail-closed pre-inference gate controlling model access and abstention."""

    def __init__(
        self,
        registry: Optional[SourceRegistry] = None,
        evaluator: Optional[FeatureCompatibilityEvaluator] = None,
        ood_validator: Optional[OODValidator] = None,
        strict_ood_abstain: bool = False,
    ) -> None:
        self.registry = registry or SourceRegistry()
        self.evaluator = evaluator or FeatureCompatibilityEvaluator()
        self.ood_validator = ood_validator or OODValidator(check_shortcut_drift=True)
        self.strict_ood_abstain = strict_ood_abstain

    def evaluate(
        self,
        events: List[CanonicalNetworkEvent],
        source_id: Optional[str] = None,
        df: Optional[pd.DataFrame] = None,
    ) -> GateDecision:
        """Evaluate events against schema compatibility, OOD metrics, and abstention policies."""
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

        # 2. Check if source is explicitly unsupported for ML
        if not source_def.ml_supported:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.FEATURE_INCOMPATIBLE,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                abstention_reasons=[
                    f"Source '{eff_source}' is a metadata-only telemetry source and does not support ML inference.",
                    "Anti-imputation policy: Missing 47-feature vector cannot be imputed.",
                ],
                route_to_trace_engine=source_def.trace_supported,
                route_to_risk_engine=True,
            )

        # 3. Compatibility Evaluation
        comp_report = self.evaluator.evaluate_events(events, source_id=eff_source)
        if not comp_report.is_eligible_for_inference:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=comp_report.inference_eligibility,
                validation_status=comp_report.validation_status,
                compatibility_report=comp_report,
                abstention_reasons=comp_report.rejection_reasons,
                route_to_trace_engine=comp_report.trace_route_eligible,
                route_to_risk_engine=comp_report.risk_route_eligible,
            )

        # 4. Extract feature matrix for OOD inspection
        if df is not None:
            X_df = df[[c for c in ML_FEATURE_COLUMNS if c in df.columns]]
        else:
            X_df, _ = BaseSourceAdapter.extract_ml_matrix(events)

        # 5. OOD & Range Audit
        ood_report = self.ood_validator.audit_dataframe(X_df)
        warning_flags = list(ood_report.ood_flags)

        if ood_report.has_ood_warning:
            if self.strict_ood_abstain and ood_report.affected_rows_count > 0:
                # Abstain when strictly configured and critical boundary violated
                return GateDecision(
                    can_proceed_to_ml=False,
                    eligibility_status=InferenceEligibility.ABSTAINED,
                    validation_status=comp_report.validation_status,
                    ood_report=ood_report,
                    compatibility_report=comp_report,
                    abstention_reasons=[
                        f"Strict OOD abstention: {ood_report.affected_rows_count} row(s) violate boundary constraints."
                    ],
                    warning_flags=warning_flags,
                    route_to_trace_engine=True,
                    route_to_risk_engine=True,
                )

        # 6. Approved for inference
        return GateDecision(
            can_proceed_to_ml=True,
            eligibility_status=comp_report.inference_eligibility,
            validation_status=comp_report.validation_status,
            ood_report=ood_report,
            compatibility_report=comp_report,
            warning_flags=warning_flags,
            route_to_trace_engine=True,
            route_to_risk_engine=True,
        )
