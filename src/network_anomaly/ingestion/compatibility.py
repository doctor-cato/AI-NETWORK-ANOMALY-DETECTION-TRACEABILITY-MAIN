"""Feature Compatibility Evaluator and 4-Tier Data State Validator (Issue #46)."""

from __future__ import annotations

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


@dataclass
class CompatibilityEvaluationReport:
    """Detailed audit report on source and feature compatibility."""

    source_id: str
    validation_status: ValidationStatus
    inference_eligibility: InferenceEligibility
    total_events: int
    eligible_events_count: int
    missing_features: List[str] = field(default_factory=list)
    semantic_mismatch_features: List[str] = field(default_factory=list)
    feature_statuses: Dict[str, FeatureMappingStatus] = field(default_factory=dict)
    rejection_reasons: List[str] = field(default_factory=list)
    trace_route_eligible: bool = True
    risk_route_eligible: bool = True

    @property
    def is_eligible_for_inference(self) -> bool:
        """True only if the source reaches SEMANTICALLY_COMPATIBLE or MODEL_VALIDATED."""
        return self.inference_eligibility in (
            InferenceEligibility.PREDICTION_AVAILABLE,
            InferenceEligibility.VALIDATION_NOT_VERIFIED,
        )


class FeatureCompatibilityEvaluator:
    """Evaluates multi-source events against the 4-tier validation model and 47-feature ML contract."""

    BENCHMARKED_SOURCES: Set[str] = {
        "source:nf-v3-canonical",
        "source:nf-v3-external",
    }

    def __init__(self, target_features: Optional[List[str]] = None) -> None:
        self.target_features = target_features or list(ML_FEATURE_COLUMNS)

    def evaluate_events(
        self,
        events: List[CanonicalNetworkEvent],
        source_id: Optional[str] = None,
    ) -> CompatibilityEvaluationReport:
        """Evaluate a batch of CanonicalNetworkEvents."""
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
        first_event = events[0]

        # 1. Check if source provides ML features
        if first_event.ml_features is None:
            # Source lacks ML vector (e.g. Zeek, NetFlow v5, AWS VPC)
            missing = list(self.target_features)
            return CompatibilityEvaluationReport(
                source_id=eff_source,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                inference_eligibility=InferenceEligibility.FEATURE_INCOMPATIBLE,
                total_events=len(events),
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

        # 2. Check completeness of provided ML features
        available_keys = set(first_event.ml_features.keys())
        missing_features = [feat for feat in self.target_features if feat not in available_keys]

        if missing_features:
            return CompatibilityEvaluationReport(
                source_id=eff_source,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                inference_eligibility=InferenceEligibility.FEATURE_INCOMPATIBLE,
                total_events=len(events),
                eligible_events_count=0,
                missing_features=missing_features,
                feature_statuses={feat: FeatureMappingStatus.MISSING for feat in missing_features},
                rejection_reasons=[
                    f"Event missing {len(missing_features)} mandatory ML feature(s): {missing_features[:5]}...",
                ],
                trace_route_eligible=True,
                risk_route_eligible=True,
            )

        # 3. Check semantic compatibility and model validation tier
        if eff_source in self.BENCHMARKED_SOURCES:
            val_status = ValidationStatus.MODEL_VALIDATED
            eligibility = InferenceEligibility.PREDICTION_AVAILABLE
        else:
            val_status = ValidationStatus.SEMANTICALLY_COMPATIBLE
            eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED

        feature_statuses = {feat: FeatureMappingStatus.EXACT for feat in self.target_features}

        return CompatibilityEvaluationReport(
            source_id=eff_source,
            validation_status=val_status,
            inference_eligibility=eligibility,
            total_events=len(events),
            eligible_events_count=len(events),
            missing_features=[],
            feature_statuses=feature_statuses,
            rejection_reasons=[],
            trace_route_eligible=True,
            risk_route_eligible=True,
        )

    def evaluate_dataframe(
        self,
        df: pd.DataFrame,
        source_id: str = "source:detected",
    ) -> CompatibilityEvaluationReport:
        """Evaluate raw pandas DataFrame against 47-feature contract."""
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

        val_status = (
            ValidationStatus.MODEL_VALIDATED
            if source_id in self.BENCHMARKED_SOURCES
            else ValidationStatus.SEMANTICALLY_COMPATIBLE
        )

        return CompatibilityEvaluationReport(
            source_id=source_id,
            validation_status=val_status,
            inference_eligibility=InferenceEligibility.PREDICTION_AVAILABLE,
            total_events=len(df),
            eligible_events_count=len(df),
            missing_features=[],
            feature_statuses={col: FeatureMappingStatus.EXACT for col in self.target_features},
            rejection_reasons=[],
            trace_route_eligible=True,
            risk_route_eligible=True,
        )
