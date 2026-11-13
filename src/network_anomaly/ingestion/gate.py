"""Inference Eligibility and Prediction Abstention Gate (Issue #46, #58).

Enforces fail-closed validation before ML inference:
- Validates schema and semantic compatibility.
- Detects out-of-distribution values and lab shortcut collapse.
- Implements strict anti-imputation policy (no fake 0/median filling).
- Decouples Dataset Identity from physical Content Checksums.
- Routes ineligible events to Trace and Risk engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from network_anomaly.ingestion.adapters.base import BaseSourceAdapter
from network_anomaly.ingestion.compatibility import (
    CompatibilityEvaluationReport,
    FeatureCompatibilityEvaluator,
)
from network_anomaly.ingestion.exceptions import (
    SourceUnsupportedError,
)
from network_anomaly.ingestion.ood import OODReport, OODValidator
from network_anomaly.ingestion.registry import SourceRegistry
from network_anomaly.ingestion.schemas import (
    CanonicalNetworkEvent,
    InferenceEligibility,
    ValidationStatus,
)


@dataclass(frozen=True)
class DatasetIdentity:
    """Dataset identity independent of physical file bytes, slices, or splits."""

    name: str
    doi: Optional[str] = None
    format: str = "NetFlow-v3"
    column_count: int = 55
    feature_count: int = 47
    publisher: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "doi": self.doi,
            "format": self.format,
            "column_count": self.column_count,
            "feature_count": self.feature_count,
            "publisher": self.publisher,
            "description": self.description,
        }


@dataclass(frozen=True)
class ContentChecksum:
    """Cryptographic content checksum for a specific physical file or sample slice."""

    sha256: str
    size_bytes: int
    row_count: int
    slice_type: str = "full"  # "full", "sample_slice", "validation_split", "train_split"
    manifest_sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "row_count": self.row_count,
            "slice_type": self.slice_type,
            "manifest_sha256": self.manifest_sha256,
        }


def verify_provenance_binding(
    identity: DatasetIdentity,
    checksum: ContentChecksum,
    manifest: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Verify dataset provenance while decoupling Dataset Identity from Content Checksum.

    A slice sample (e.g. 50k or 100k sample) has a different content checksum than
    the full multi-million-row raw dataset. It is valid as long as its provenance manifest
    authenticates the slice's checksum and attributes it to the identified dataset.
    """
    if manifest is None:
        # Without manifest, verify non-empty structural identity
        if not identity.name or not checksum.sha256:
            return False, "Dataset identity name and content checksum sha256 must be non-empty."
        return True, "Dataset identity and content checksum format valid (unmanifested)."

    manifest_dataset = manifest.get("dataset") or manifest.get("dataset_name")
    if manifest_dataset and manifest_dataset != identity.name:
        return (
            False,
            f"Dataset identity mismatch: expected '{identity.name}', got '{manifest_dataset}'",
        )

    # Slice-aware checksum verification
    if checksum.slice_type in ("sample_slice", "slice", "stratified"):
        manifest_sample_sha = manifest.get("sample_sha256")
        if manifest_sample_sha:
            if manifest_sample_sha.lower() != checksum.sha256.lower():
                return False, (
                    f"Sample content checksum mismatch: expected '{manifest_sample_sha[:12]}...', "
                    f"got '{checksum.sha256[:12]}...'"
                )
            return True, "Slice content checksum verified against companion sample manifest."

    manifest_full_sha = (
        manifest.get("dataset_sha256")
        or manifest.get("publisher_bagit_sha1")
        or manifest.get("archive_sha256")
    )
    if manifest_full_sha and checksum.slice_type == "full":
        if manifest_full_sha.lower() != checksum.sha256.lower():
            return False, (
                f"Full content checksum mismatch: expected '{manifest_full_sha[:12]}...', "
                f"got '{checksum.sha256[:12]}...'"
            )
        return True, "Full dataset content checksum verified."

    return True, "Provenance binding verified with valid companion manifest."


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
    dataset_identity: Optional[DatasetIdentity] = None
    content_checksum: Optional[ContentChecksum] = None

    @property
    def is_eligible(self) -> bool:
        """Boolean indicator of prediction eligibility."""
        return self.can_proceed_to_ml

    @property
    def decision(self) -> str:
        """Categorical decision string: 'PROCEED' or 'ABSTAINED'."""
        return "PROCEED" if self.can_proceed_to_ml else "ABSTAINED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "can_proceed_to_ml": self.can_proceed_to_ml,
            "is_eligible": self.is_eligible,
            "decision": self.decision,
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
            "dataset_identity": self.dataset_identity.to_dict() if self.dataset_identity else None,
            "content_checksum": self.content_checksum.to_dict() if self.content_checksum else None,
        }


@dataclass
class CheckAndFilterResult:
    """Convenience wrapper result supporting both object access and tuple unpacking.

    Usage:
        eligible_df, decision = gate.check_and_filter(df)
        OR
        result = gate.check_and_filter(df)
        if result.is_eligible:
            preds = model.predict(result.eligible_df)
    """

    eligible_df: pd.DataFrame
    decision: GateDecision
    is_eligible: bool
    reasons: List[str]

    def __iter__(self):
        """Allow tuple unpacking: eligible_df, decision = gate.check_and_filter(df)."""
        return iter((self.eligible_df, self.decision))


class InferenceEligibilityGate:
    """Fail-closed pre-inference gate controlling model access and abstention."""

    def __init__(
        self,
        registry: Optional[SourceRegistry] = None,
        evaluator: Optional[FeatureCompatibilityEvaluator] = None,
        ood_validator: Optional[OODValidator] = None,
        strict_ood_abstain: bool = True,
        max_allowed_shortcut_drift_ratio: float = 0.50,
        reject_zero_ttl: bool = True,
    ) -> None:
        if not (0.0 <= max_allowed_shortcut_drift_ratio <= 1.0):
            raise ValueError(
                f"max_allowed_shortcut_drift_ratio must be in [0.0, 1.0], "
                f"got {max_allowed_shortcut_drift_ratio}"
            )
        self.registry = registry or SourceRegistry()
        self.evaluator = evaluator or FeatureCompatibilityEvaluator()
        self.ood_validator = ood_validator or OODValidator(
            check_shortcut_drift=True,
            reject_zero_ttl=reject_zero_ttl,
        )
        self.strict_ood_abstain = strict_ood_abstain
        self.max_allowed_shortcut_drift_ratio = max_allowed_shortcut_drift_ratio
        self.reject_zero_ttl = reject_zero_ttl

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
        dataset_identity: Optional[DatasetIdentity] = None,
        content_checksum: Optional[ContentChecksum] = None,
        provenance_manifest: Optional[Dict[str, Any]] = None,
    ) -> GateDecision:
        """Evaluate input against schema compatibility, OOD metrics, and abstention policies."""
        if not events and df is None:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.SCHEMA_INVALID,
                validation_status=ValidationStatus.PARSEABLE,
                abstention_reasons=["No input events or DataFrame provided to gate."],
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
            )

        # Provenance verification if identity and checksum are supplied
        if dataset_identity is not None and content_checksum is not None:
            prov_ok, prov_msg = verify_provenance_binding(
                dataset_identity, content_checksum, provenance_manifest
            )
            if not prov_ok:
                total_n = len(df) if df is not None else (len(events) if events else 0)
                return GateDecision(
                    can_proceed_to_ml=False,
                    eligibility_status=InferenceEligibility.VALIDATION_NOT_VERIFIED,
                    validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                    abstention_reasons=[f"Dataset provenance validation failed: {prov_msg}"],
                    route_to_trace_engine=True,
                    route_to_risk_engine=True,
                    abstained_indices=list(range(total_n)),
                    rejected_indices=list(range(total_n)),
                    dataset_identity=dataset_identity,
                    content_checksum=content_checksum,
                )

        # Infer effective source ID
        eff_source = source_id
        if not eff_source:
            if events:
                eff_source = events[0].metadata.source_id
            elif df is not None:
                # Default to canonical baseline source for ML inference unless specified
                eff_source = "source:nf-v3-canonical"

        # 0. Always perform OOD & Physical Network Invariant Audit early
        metadata_violations: List[str] = []
        rejected_indices: List[int] = []
        abstained_indices: List[int] = []
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
                    abstained_indices.append(idx)
                    row_rejection_reasons[idx] = f"Invalid metadata: {ev.invalid_metadata}"
                    metadata_violations.append(f"Row {idx}: {ev.invalid_metadata}")
                elif ev.ml_features is None or ev.missing_features or ev.invalid_features:
                    rejected_indices.append(idx)
                    abstained_indices.append(idx)
                    row_rejection_reasons[idx] = "Incomplete or non-finite ML feature vector."

        ood_report = self.ood_validator.audit_dataframe(audit_df)
        warning_flags = list(ood_report.ood_flags)

        # Record row-level OOD violations
        for idx in ood_report.hard_violation_indices:
            if idx not in rejected_indices:
                rejected_indices.append(idx)
                abstained_indices.append(idx)
                row_rejection_reasons[idx] = "Hard physical network invariant violation."

        for idx in ood_report.zero_ttl_indices:
            if idx not in abstained_indices:
                abstained_indices.append(idx)
                if idx not in rejected_indices:
                    rejected_indices.append(idx)
                row_rejection_reasons[idx] = (
                    "OOD drift: MIN_TTL=0 (unobserved initial TTL / capture drop). "
                    "Anti-imputation policy: Synthetic filling prohibited -> ABSTAINED."
                )

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
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
            )

        # 2. Check if source is explicitly unsupported for ML
        total_n = len(df) if df is not None else (len(events) if events else 0)
        if not source_def.ml_supported:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.FEATURE_INCOMPATIBLE,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                abstention_reasons=[
                    f"Source '{eff_source}' lacks 47 ML features required for inference.",
                    "Strict anti-imputation policy: Zero/median synthetic filling is prohibited.",
                ],
                route_to_trace_engine=source_def.trace_supported,
                route_to_risk_engine=True,
                rejected_indices=list(range(total_n)),
                abstained_indices=list(range(total_n)),
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
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

        # Check for benchmark failure
        if comp_report.validation_status == ValidationStatus.BENCHMARK_FAILED:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.BENCHMARK_UNSATISFACTORY,
                validation_status=ValidationStatus.BENCHMARK_FAILED,
                ood_report=ood_report,
                compatibility_report=comp_report,
                abstention_reasons=comp_report.rejection_reasons,
                route_to_trace_engine=True,
                route_to_risk_engine=True,
                rejected_indices=list(range(total_n)),
                abstained_indices=list(range(total_n)),
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
            )

        # Check for feature incompleteness (missing columns, NaN/Inf values under anti-imputation)
        if comp_report.validation_status == ValidationStatus.SCHEMA_COMPATIBLE:
            reasons = list(comp_report.rejection_reasons)
            if not any("anti-imputation" in r.lower() for r in reasons):
                reasons.append(
                    "Strict anti-imputation policy: Zero/median synthetic filling is prohibited."
                )
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=comp_report.inference_eligibility,
                validation_status=comp_report.validation_status,
                ood_report=ood_report,
                compatibility_report=comp_report,
                abstention_reasons=reasons,
                route_to_trace_engine=comp_report.trace_route_eligible,
                route_to_risk_engine=comp_report.risk_route_eligible,
                rejected_indices=list(range(total_n)),
                abstained_indices=list(range(total_n)),
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
            )

        # Unverified benchmark sources
        is_semantic = comp_report.validation_status == ValidationStatus.SEMANTICALLY_COMPATIBLE
        if is_semantic and not allow_unverified:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=InferenceEligibility.VALIDATION_NOT_VERIFIED,
                validation_status=ValidationStatus.SEMANTICALLY_COMPATIBLE,
                ood_report=ood_report,
                compatibility_report=comp_report,
                abstention_reasons=[
                    f"Source '{eff_source}' has no verified empirical benchmark evidence.",
                    "Inference refused fail-closed: Pass allow_unverified=True for testing.",
                ],
                route_to_trace_engine=comp_report.trace_route_eligible,
                route_to_risk_engine=comp_report.risk_route_eligible,
                rejected_indices=list(range(total_n)),
                abstained_indices=list(range(total_n)),
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
            )

        if not comp_report.is_eligible_for_inference and not allow_unverified:
            return GateDecision(
                can_proceed_to_ml=False,
                eligibility_status=comp_report.inference_eligibility,
                validation_status=comp_report.validation_status,
                ood_report=ood_report,
                compatibility_report=comp_report,
                abstention_reasons=comp_report.rejection_reasons,
                route_to_trace_engine=comp_report.trace_route_eligible,
                route_to_risk_engine=comp_report.risk_route_eligible,
                rejected_indices=list(range(total_n)),
                abstained_indices=list(range(total_n)),
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
            )

        total_hard_violations = ood_report.hard_violation_count + len(metadata_violations)

        # Fail-closed condition A: Hard boundary / physical protocol invariant violation
        if total_hard_violations > 0:
            combined_reasons = []
            if ood_report.hard_violation_count > 0:
                combined_reasons.append(
                    f"Hard constraint violation: {ood_report.hard_violation_count} row(s) "
                    "violate physical network invariants (e.g. inverted TTL, negative duration)."
                )
            if metadata_violations:
                combined_reasons.append(
                    f"Hard constraint violation: {len(metadata_violations)} record(s) "
                    "have invalid network metadata."
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
                abstained_indices=sorted(set(abstained_indices or range(total_n))),
                rejected_indices=sorted(set(rejected_indices or range(total_n))),
                row_rejection_reasons=row_rejection_reasons,
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
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
                    f"Strict OOD shortcut abstention: {ood_report.shortcut_drift_ratio*100:.1f}% "
                    "rows exhibit critical MIN_TTL shift (>= "
                    f"{self.max_allowed_shortcut_drift_ratio*100:.0f}%). "
                    "Fail-closed prediction abstention engaged to prevent false alert flood."
                ],
                warning_flags=warning_flags,
                route_to_trace_engine=True,
                route_to_risk_engine=True,
                abstained_indices=list(range(total_n)),
                rejected_indices=rejected_indices,
                row_rejection_reasons=row_rejection_reasons,
                dataset_identity=dataset_identity,
                content_checksum=content_checksum,
            )

        # 7. Approved for inference with row-level tracking
        accepted_set = set(eligible_indices) - set(rejected_indices)
        all_indices = set(range(total_n))
        rejected_set = all_indices - accepted_set

        can_proceed = len(accepted_set) > 0 and len(rejected_set) == 0

        elig_status = (
            comp_report.inference_eligibility if can_proceed else InferenceEligibility.ABSTAINED
        )
        return GateDecision(
            can_proceed_to_ml=can_proceed,
            eligibility_status=elig_status,
            validation_status=comp_report.validation_status,
            ood_report=ood_report,
            compatibility_report=comp_report,
            warning_flags=warning_flags,
            route_to_trace_engine=True,
            route_to_risk_engine=True,
            accepted_indices=sorted(accepted_set),
            rejected_indices=sorted(rejected_set),
            abstained_indices=sorted(abstained_indices),
            row_rejection_reasons=row_rejection_reasons,
            dataset_identity=dataset_identity,
            content_checksum=content_checksum,
        )

    def check_and_filter(
        self,
        df: pd.DataFrame,
        source_id: Optional[str] = None,
        model_identifier: Optional[str] = None,
        model_artifact_sha256: Optional[str] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        feature_contract_version: Optional[str] = None,
        allow_unverified: bool = False,
        dataset_identity: Optional[DatasetIdentity] = None,
        content_checksum: Optional[ContentChecksum] = None,
        provenance_manifest: Optional[Dict[str, Any]] = None,
        row_level_filter: bool = True,
    ) -> CheckAndFilterResult:
        """Evaluate and filter DataFrame, returning eligible rows and gate decision.

        Implements strict Anti-Imputation: ineligible or OOD rows are never filled with
        synthetic values; they are marked ABSTAINED with reasons and excluded from eligible_df.
        Supports tuple unpacking:
            eligible_df, decision = gate.check_and_filter(df)
        """
        decision = self.evaluate(
            df=df,
            source_id=source_id,
            model_identifier=model_identifier,
            model_artifact_sha256=model_artifact_sha256,
            preprocessor_artifact_sha256=preprocessor_artifact_sha256,
            feature_contract_version=feature_contract_version,
            allow_unverified=allow_unverified,
            dataset_identity=dataset_identity,
            content_checksum=content_checksum,
            provenance_manifest=provenance_manifest,
        )

        if decision.can_proceed_to_ml:
            eligible_df = df.iloc[decision.accepted_indices].copy().reset_index(drop=True)
            return CheckAndFilterResult(
                eligible_df=eligible_df,
                decision=decision,
                is_eligible=True,
                reasons=[],
            )

        if row_level_filter and len(decision.accepted_indices) > 0:
            eligible_df = df.iloc[decision.accepted_indices].copy().reset_index(drop=True)
        else:
            eligible_df = df.iloc[[]].copy().reset_index(drop=True)

        return CheckAndFilterResult(
            eligible_df=eligible_df,
            decision=decision,
            is_eligible=decision.can_proceed_to_ml,
            reasons=decision.abstention_reasons,
        )
