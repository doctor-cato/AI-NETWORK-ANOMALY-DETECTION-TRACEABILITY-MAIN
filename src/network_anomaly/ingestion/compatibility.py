"""Feature Compatibility Evaluator, 4-Tier Data State Validator, and Benchmark Binding (Issue #46)."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

from network_anomaly.config import PROJECT_ROOT
from network_anomaly.data.split import SPLIT_PROTOCOL_VERSION
from network_anomaly.data.v2_schema import (
    DATASET_SUITE_NAME,
    FEATURE_CONTRACT_ID,
    ML_FEATURE_COLUMNS,
)
from network_anomaly.ingestion.schemas import (
    CanonicalNetworkEvent,
    FeatureMappingStatus,
    InferenceEligibility,
    ValidationStatus,
)


@dataclass(frozen=True)
class BenchmarkEvidence:
    """Empirical benchmark evidence binding a specific source domain to a v2 model and artifacts."""

    source_id: str
    model_identifier: str = ""
    model_artifact_sha256: str = ""
    preprocessor_artifact_sha256: str = ""
    feature_contract_version: str = FEATURE_CONTRACT_ID
    feature_contract_hash: Optional[str] = None
    dataset_name: str = DATASET_SUITE_NAME
    dataset_version: str = "2.0.0"
    dataset_sha256: Optional[str] = None
    evaluation_protocol: str = SPLIT_PROTOCOL_VERSION
    split_identity: str = "held-out-test-split"
    recall: float = 0.0
    fpr: float = 0.0
    accuracy: float = 0.0
    metrics: Dict[str, float] = field(default_factory=dict)
    acceptance_criteria: Dict[str, float] = field(default_factory=dict)
    validation_timestamp_utc: str = ""
    verification_status: str = "UNVALIDATED"
    is_passed: bool = False
    reason: str = ""
    model_version: str = ""
    model_family: Optional[str] = None
    is_research_only: bool = False

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
                {"min_recall": 0.70, "max_fpr": 0.10},
            )

    def verify_binding(
        self,
        model_identifier: Optional[str] = None,
        model_artifact_sha256: Optional[str] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        feature_contract_version: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Verify that runtime model, preprocessor, and contract match benchmarked evidence."""
        if model_identifier and self.model_identifier and model_identifier != self.model_identifier:
            return (
                False,
                f"Model identifier mismatch: expected '{self.model_identifier}', got '{model_identifier}'",
            )
        if (
            model_artifact_sha256
            and self.model_artifact_sha256
            and model_artifact_sha256 != self.model_artifact_sha256
        ):
            return (
                False,
                f"Model artifact SHA-256 mismatch: expected '{self.model_artifact_sha256[:12]}...', got '{model_artifact_sha256[:12]}...'",
            )
        if (
            preprocessor_artifact_sha256
            and self.preprocessor_artifact_sha256
            and preprocessor_artifact_sha256 != self.preprocessor_artifact_sha256
        ):
            return (
                False,
                f"Preprocessor artifact SHA-256 mismatch: expected '{self.preprocessor_artifact_sha256[:12]}...', got '{preprocessor_artifact_sha256[:12]}...'",
            )
        if feature_contract_version and feature_contract_version != self.feature_contract_version:
            return (
                False,
                f"Feature contract version mismatch: expected '{self.feature_contract_version}', got '{feature_contract_version}'",
            )
        if self.verification_status in ("STALE", "EXPIRED", "REVOKED", "UNVALIDATED"):
            return False, f"Benchmark evidence status is {self.verification_status}."
        if not self.is_passed and not self.is_research_only:
            return False, f"Benchmark empirical criteria not met: {self.reason}"
        return True, "Benchmark evidence binding verified."


def load_v2_benchmark_registry(
    manifest_root: Optional[Path] = None,
) -> Dict[str, BenchmarkEvidence]:
    """Build v2 benchmark evidence registry dynamically from verified v2 model manifests."""
    root = Path(manifest_root) if manifest_root else (PROJECT_ROOT / "reports" / "models")
    registry: Dict[str, BenchmarkEvidence] = {}
    manifest_files = {
        "random_forest": ("random_forest_manifest.json", "RandomForestClassifier", False),
        "xgboost": ("xgboost_manifest.json", "XGBClassifier", True),
        "isolation_forest": ("isolation_forest_manifest.json", "IsolationForest", True),
        "autoencoder": ("autoencoder_manifest.json", "Autoencoder", True),
    }

    for model_key, (fname, family, default_research) in manifest_files.items():
        mpath = root / fname
        if not mpath.is_file():
            continue
        try:
            data = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("feature_contract_version") != FEATURE_CONTRACT_ID:
            continue
        run_id = str(data.get("training_run_id") or data.get("run_id") or "")
        model_sha = str(data.get("artifact_sha256") or data.get("model_artifact_sha256") or "")
        prep_sha = str(data.get("preprocessor_artifact_sha256") or data.get("preprocessor_sha256") or "")
        test_eval = data.get("test_evaluation") or data.get("evaluation_metrics") or {}
        recall = float(test_eval.get("recall", 0.0) or 0.0)
        fpr = float(test_eval.get("fpr", test_eval.get("false_positive_rate", 0.0)) or 0.0)
        acc = float(test_eval.get("accuracy", 0.0) or 0.0)
        is_research = bool(data.get("is_research_only", default_research))
        passed = bool(data.get("benchmark_passed", True if (model_sha and prep_sha) else False))
        status = "RESEARCH_ONLY" if is_research else ("VERIFIED" if passed else "UNVALIDATED")

        for src_id in ("source:canonical-flow-v2", "source:ait-nds-v2"):
            ev = BenchmarkEvidence(
                source_id=src_id,
                model_identifier=run_id or f"{model_key}-v2",
                model_family=family,
                model_artifact_sha256=model_sha,
                preprocessor_artifact_sha256=prep_sha,
                feature_contract_version=FEATURE_CONTRACT_ID,
                dataset_name=str(data.get("dataset_name") or DATASET_SUITE_NAME),
                dataset_version="2.0.0",
                dataset_sha256=data.get("dataset_sha256"),
                evaluation_protocol=str(data.get("split_protocol_version") or SPLIT_PROTOCOL_VERSION),
                split_identity="scenario-disjoint-test-split",
                recall=recall,
                fpr=fpr,
                accuracy=acc,
                metrics={"recall": recall, "fpr": fpr, "accuracy": acc},
                validation_timestamp_utc=str(data.get("trained_at_utc") or ""),
                verification_status=status,
                is_passed=passed,
                is_research_only=is_research,
                reason=f"Verified v2 manifest ({fname}) under {FEATURE_CONTRACT_ID}.",
            )
            if model_key == "random_forest":
                registry[src_id] = ev
            if run_id:
                registry[f"{src_id}::{run_id}"] = ev
            registry[f"{src_id}::{model_key}"] = ev

    return registry


DEFAULT_BENCHMARK_REGISTRY: Dict[str, BenchmarkEvidence] = load_v2_benchmark_registry()


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
        return self.inference_eligibility in (
            InferenceEligibility.PREDICTION_AVAILABLE,
            InferenceEligibility.RESEARCH_ONLY,
        )


class FeatureCompatibilityEvaluator:
    """Evaluates multi-source events against the 4-tier validation model and canonical v2 ML contract."""

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

    def get_benchmark_evidence(
        self,
        source_id: str,
        model_identifier: Optional[str] = None,
    ) -> Optional[BenchmarkEvidence]:
        """Lookup benchmark evidence by compound key (source_id::model_identifier) or source_id."""
        if model_identifier:
            compound_key = f"{source_id}::{model_identifier}"
            if compound_key in self.benchmark_registry:
                return self.benchmark_registry[compound_key]
        evidence = self.benchmark_registry.get(source_id)
        if evidence is not None and model_identifier is not None:
            if evidence.model_identifier and evidence.model_identifier != model_identifier:
                return None
        return evidence

    def evaluate_events(
        self,
        events: List[CanonicalNetworkEvent],
        source_id: Optional[str] = None,
        model_identifier: Optional[str] = None,
        model_artifact_sha256: Optional[str] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        feature_contract_version: Optional[str] = None,
        allow_research_only: bool = False,
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
                    feature_statuses={
                        feat: FeatureMappingStatus.MISSING for feat in missing_or_invalid
                    },
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
                    f"Source '{eff_source}' does not provide the canonical v2 flow features required for ML baseline.",
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
                feature_statuses={
                    feat: FeatureMappingStatus.MISSING for feat in missing_or_invalid
                },
                rejection_reasons=rejection_reasons,
                trace_route_eligible=True,
                risk_route_eligible=True,
            )

        # 3. Benchmark evidence and tier verification
        eff_model = model_identifier or self.expected_model_identifier
        evidence = self.get_benchmark_evidence(eff_source, eff_model)

        if evidence is not None:
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
            elif getattr(evidence, "is_research_only", False):
                if allow_research_only:
                    val_status = ValidationStatus.RESEARCH_ONLY
                    eligibility = InferenceEligibility.RESEARCH_ONLY
                else:
                    val_status = ValidationStatus.UNVALIDATED
                    eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED
                    rejection_reasons.append(
                        f"Model '{eff_model or evidence.model_identifier}' on '{eff_source}' "
                        "is designated RESEARCH_ONLY and not certified for production inference."
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
            if allow_research_only:
                val_status = ValidationStatus.RESEARCH_ONLY
                eligibility = InferenceEligibility.RESEARCH_ONLY
            else:
                # Structurally and semantically complete, but unbenchmarked
                val_status = ValidationStatus.SEMANTICALLY_COMPATIBLE
                eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED
                rejection_reasons.append(
                    f"Source '{eff_source}' has no empirical benchmark evidence on file (unverified)."
                )

        feature_statuses = {
            feat: (
                FeatureMappingStatus.EXACT
                if feat not in (all_missing_keys | non_finite_keys)
                else FeatureMappingStatus.MISSING
            )
            for feat in self.target_features
        }

        is_research = eligibility == InferenceEligibility.RESEARCH_ONLY

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
            risk_route_eligible=not is_research,
        )

    def evaluate_dataframe(
        self,
        df: pd.DataFrame,
        source_id: str = "source:detected",
        model_identifier: Optional[str] = None,
        model_artifact_sha256: Optional[str] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        feature_contract_version: Optional[str] = None,
        allow_research_only: bool = False,
    ) -> CompatibilityEvaluationReport:
        """Evaluate raw pandas DataFrame against canonical v2 contract and Anti-Imputation."""
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
            rejection_reasons.append(
                "Strict anti-imputation policy: Zero/median synthetic filling is prohibited."
            )
            return CompatibilityEvaluationReport(
                source_id=source_id,
                validation_status=ValidationStatus.SCHEMA_COMPATIBLE,
                inference_eligibility=InferenceEligibility.FEATURE_INCOMPLETE,
                total_events=len(df),
                eligible_events_count=int(row_is_finite.sum()),
                missing_features=list(cols_with_invalid.keys()),
                feature_statuses={
                    col: (
                        FeatureMappingStatus.EXACT
                        if col not in cols_with_invalid
                        else FeatureMappingStatus.MISSING
                    )
                    for col in self.target_features
                },
                rejection_reasons=rejection_reasons,
                trace_route_eligible=True,
                risk_route_eligible=True,
            )

        eff_model = model_identifier or self.expected_model_identifier
        evidence = self.get_benchmark_evidence(source_id, eff_model)
        if evidence is not None:
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
            elif getattr(evidence, "is_research_only", False):
                if allow_research_only:
                    val_status = ValidationStatus.RESEARCH_ONLY
                    eligibility = InferenceEligibility.RESEARCH_ONLY
                else:
                    val_status = ValidationStatus.UNVALIDATED
                    eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED
                    rejection_reasons.append(
                        f"Model '{eff_model or evidence.model_identifier}' on '{source_id}' "
                        "is designated RESEARCH_ONLY and not certified for production inference."
                    )
            elif evidence.is_passed:
                val_status = ValidationStatus.MODEL_VALIDATED
                eligibility = InferenceEligibility.PREDICTION_AVAILABLE
            else:
                val_status = ValidationStatus.BENCHMARK_FAILED
                eligibility = InferenceEligibility.BENCHMARK_UNSATISFACTORY
                rejection_reasons.append(
                    f"Model benchmark failed for '{source_id}': {evidence.reason}"
                )
        else:
            if allow_research_only:
                val_status = ValidationStatus.RESEARCH_ONLY
                eligibility = InferenceEligibility.RESEARCH_ONLY
            else:
                val_status = ValidationStatus.SEMANTICALLY_COMPATIBLE
                eligibility = InferenceEligibility.VALIDATION_NOT_VERIFIED
                rejection_reasons.append(
                    f"Source '{source_id}' has no empirical benchmark evidence on file (unverified)."
                )

        is_research = eligibility == InferenceEligibility.RESEARCH_ONLY

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
            risk_route_eligible=not is_research,
        )
