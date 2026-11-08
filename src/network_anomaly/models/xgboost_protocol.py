"""XGBoost baseline protocol and configuration for NF-UNSW-NB15-v3 (Issue #31 / C3).

This module formalizes the protocol contracts for Issue #31 according to the shared
supervised protocol established by Random Forest (Issue #9, #10).
It does NOT execute model training, evaluation, or benchmark generation.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from network_anomaly.config import RANDOM_SEED
from network_anomaly.data.nf_unsw_nb15_v3 import (
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
)

PROTOCOL_IDENTIFIER: str = "xgb-baseline-nf-unsw-nb15-v3-v1"
FEATURE_CONTRACT_VERSION: str = "nf-unsw-nb15-v3-baseline-47"
SPLIT_PROTOCOL_ID: str = "nf-unsw-nb15-v3-chronological-group-purged-v1"
PREPROCESSING_CONTRACT_ID: str = "nf-unsw-nb15-v3-preproc-v1"

TARGET_COLUMN: str = "Label"
STRATIFICATION_COLUMN: str = "Attack"
POSITIVE_CLASS_NAME: str = "Attack"
POSITIVE_CLASS_LABEL: int = 1
NEGATIVE_CLASS_NAME: str = "Benign"
NEGATIVE_CLASS_LABEL: int = 0

EXPECTED_ATTACK_CATEGORIES: Tuple[str, ...] = (
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
)

ALL_ATTACK_CATEGORIES: Tuple[str, ...] = ("Benign",) + EXPECTED_ATTACK_CATEGORIES

DATASET_CSV_SHA256: str = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
DATASET_ARCHIVE_SHA256: str = "6d51554df43e324ba8d68fc31a02a83d860ba0a3a93d63320a4a6fc314c9cdfd"

CANONICAL_BASELINE_PARAMS: Dict[str, Any] = {
    "model_type": "XGBoost",
    "task": "binary_classification",
    "target": "Label",
    "positive_class": "Attack",
    "n_estimators": 200,
    "max_depth": 6,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "tree_method": "hist",
    "random_state": 42,
    "n_jobs": -1,
}


@dataclass(frozen=True)
class XGBoostBaselineConfig:
    """Locked baseline configuration for XGBClassifier on NF-UNSW-NB15-v3."""

    model_type: str = "XGBoost"
    task: str = "binary_classification"
    target: str = "Label"
    positive_class: str = "Attack"
    n_estimators: int = 200
    max_depth: int = 6
    learning_rate: float = 0.1
    subsample: float = 0.8
    colsample_bytree: float = 0.8
    objective: str = "binary:logistic"
    eval_metric: str = "logloss"
    tree_method: str = "hist"
    random_state: int = RANDOM_SEED
    n_jobs: int = -1
    configuration_id: str = "xgb-baseline-canonical-v1"
    is_canonical_baseline: bool = True

    def __post_init__(self) -> None:
        """Validate hyperparameter invariants upon instantiation."""
        canonical_matches = (
            self.model_type == CANONICAL_BASELINE_PARAMS["model_type"]
            and self.task == CANONICAL_BASELINE_PARAMS["task"]
            and self.target == CANONICAL_BASELINE_PARAMS["target"]
            and self.positive_class == CANONICAL_BASELINE_PARAMS["positive_class"]
            and self.n_estimators == CANONICAL_BASELINE_PARAMS["n_estimators"]
            and self.max_depth == CANONICAL_BASELINE_PARAMS["max_depth"]
            and abs(self.learning_rate - CANONICAL_BASELINE_PARAMS["learning_rate"]) < 1e-9
            and abs(self.subsample - CANONICAL_BASELINE_PARAMS["subsample"]) < 1e-9
            and abs(self.colsample_bytree - CANONICAL_BASELINE_PARAMS["colsample_bytree"]) < 1e-9
            and self.objective == CANONICAL_BASELINE_PARAMS["objective"]
            and self.eval_metric == CANONICAL_BASELINE_PARAMS["eval_metric"]
            and self.tree_method == CANONICAL_BASELINE_PARAMS["tree_method"]
            and self.random_state == CANONICAL_BASELINE_PARAMS["random_state"]
            and self.n_jobs == CANONICAL_BASELINE_PARAMS["n_jobs"]
        )
        if self.is_canonical_baseline is None:
            object.__setattr__(self, "is_canonical_baseline", canonical_matches)
        if self.configuration_id is None:
            object.__setattr__(
                self,
                "configuration_id",
                "xgb-baseline-canonical-v1" if self.is_canonical_baseline else "xgb-experimental-custom",
            )

    def validate(self) -> None:
        """Validate configuration parameters fail-closed."""
        if self.model_type != "XGBoost":
            raise ValueError(f"model_type must be 'XGBoost', got {self.model_type}")
        if self.task != "binary_classification":
            raise ValueError(f"task must be 'binary_classification', got {self.task}")
        if self.target != "Label":
            raise ValueError(f"target must be 'Label', got {self.target}")
        if self.positive_class != "Attack":
            raise ValueError(f"positive_class must be 'Attack', got {self.positive_class}")
        if self.n_estimators <= 0:
            raise ValueError(f"n_estimators must be positive, got {self.n_estimators}")
        if self.max_depth <= 0:
            raise ValueError(f"max_depth must be positive, got {self.max_depth}")
        if not (0.0 < self.learning_rate <= 1.0):
            raise ValueError(f"learning_rate must be in (0, 1], got {self.learning_rate}")
        if not (0.0 < self.subsample <= 1.0):
            raise ValueError(f"subsample must be in (0, 1], got {self.subsample}")
        if not (0.0 < self.colsample_bytree <= 1.0):
            raise ValueError(f"colsample_bytree must be in (0, 1], got {self.colsample_bytree}")
        if self.n_jobs == 0 or self.n_jobs < -1:
            raise ValueError(f"n_jobs must be -1 or a positive integer, got {self.n_jobs}")

        if self.is_canonical_baseline:
            for k, canonical_v in CANONICAL_BASELINE_PARAMS.items():
                actual_v = getattr(self, k)
                if isinstance(actual_v, float):
                    if abs(actual_v - canonical_v) >= 1e-9:
                        raise ValueError(f"Canonical baseline mismatch for '{k}'")
                elif actual_v != canonical_v:
                    raise ValueError(
                        f"Canonical baseline configuration mismatch for '{k}': "
                        f"expected {canonical_v}, got {actual_v}. If this is an intentional "
                        f"override, set is_canonical_baseline=False and provide a distinct configuration_id."
                    )
            if self.configuration_id != "xgb-baseline-canonical-v1":
                raise ValueError(
                    f"Canonical baseline must have configuration_id 'xgb-baseline-canonical-v1', got '{self.configuration_id}'"
                )
        else:
            if self.configuration_id == "xgb-baseline-canonical-v1":
                raise ValueError("Non-canonical configuration cannot use canonical ID 'xgb-baseline-canonical-v1'")
            if not self.configuration_id or not self.configuration_id.strip():
                raise ValueError("Experimental configuration must have a non-empty configuration_id")

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    def get_xgb_params(self) -> Dict[str, Any]:
        """Return parameters dictionary formatted for xgboost.XGBClassifier."""
        d = self.to_dict()
        d.pop("configuration_id", None)
        d.pop("is_canonical_baseline", None)
        d.pop("model_type", None)
        d.pop("task", None)
        d.pop("target", None)
        d.pop("positive_class", None)
        return d


@dataclass(frozen=True)
class TuningConfig:
    """Hyperparameter tuning policy configuration for XGBoost."""

    enabled: bool = False
    search_space_version: str = "xgb-tuning-search-v1"
    search_space: Dict[str, List[Any]] = field(
        default_factory=lambda: {
            "n_estimators": [100, 200, 300],
            "max_depth": [4, 6, 8],
            "learning_rate": [0.03, 0.1, 0.2],
            "subsample": [0.7, 0.8, 1.0],
            "colsample_bytree": [0.7, 0.8, 1.0],
        }
    )
    tuning_budget: Dict[str, Any] = field(
        default_factory=lambda: {
            "max_evals": 20,
            "cv_folds": 3,
            "time_budget_seconds": 3600,
        }
    )
    allowed_partitions: Tuple[str, ...] = ("train", "validation")
    scoring_metric: str = "macro_f1"
    random_state: int = RANDOM_SEED

    def validate(self) -> None:
        """Enforce strict tuning isolation: TEST must never be used."""
        if "test" in self.allowed_partitions:
            raise ValueError("Violation of tuning isolation: 'test' partition is strictly forbidden in tuning")
        valid_partitions = {"train", "validation"}
        if not set(self.allowed_partitions).issubset(valid_partitions):
            raise ValueError(f"allowed_partitions must only contain 'train' and/or 'validation'")
        if not self.allowed_partitions:
            raise ValueError("allowed_partitions cannot be empty")
        valid_metrics = {"macro_f1", "f1", "precision", "recall"}
        if self.scoring_metric not in valid_metrics:
            raise ValueError(f"Unsupported scoring_metric: {self.scoring_metric}")
        if self.random_state is None:
            raise ValueError("random_state must be an integer seed for reproducible tuning")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "search_space_version": self.search_space_version,
            "search_space": self.search_space,
            "tuning_budget": self.tuning_budget,
            "allowed_partitions": list(self.allowed_partitions),
            "scoring_metric": self.scoring_metric,
            "random_state": self.random_state,
        }


@dataclass(frozen=True)
class TestLockPolicy:
    """Enforces that the test partition is locked for one-shot final evaluation only."""

    __test__ = False

    locked: bool = True
    purpose: str = "final_evaluation_only"
    forbidden_uses: Tuple[str, ...] = (
        "feature_selection",
        "hyperparameter_tuning",
        "threshold_selection",
        "preprocessing_fitting",
        "model_selection",
        "model_iteration",
    )
    max_evaluation_count: int = 1

    def validate(self) -> None:
        if not self.locked:
            raise ValueError("TestLockPolicy violation: locked must be True.")
        required_forbidden = {
            "feature_selection",
            "hyperparameter_tuning",
            "threshold_selection",
            "preprocessing_fitting",
            "model_selection",
            "model_iteration",
        }
        if not required_forbidden.issubset(set(self.forbidden_uses)):
            missing = required_forbidden - set(self.forbidden_uses)
            raise ValueError(f"TestLockPolicy missing required forbidden uses: {missing}")
        if self.max_evaluation_count != 1:
            raise ValueError("Test partition evaluation count must be exactly 1.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "locked": self.locked,
            "purpose": self.purpose,
            "forbidden_uses": list(self.forbidden_uses),
            "max_evaluation_count": self.max_evaluation_count,
        }


@dataclass(frozen=True)
class EvaluationMetricProtocol:
    """Metric and evaluation protocol for binary anomaly detection."""

    task: str = "binary_classification"
    target_column: str = TARGET_COLUMN
    stratification_column: str = STRATIFICATION_COLUMN
    positive_class_name: str = POSITIVE_CLASS_NAME
    positive_class_label: int = POSITIVE_CLASS_LABEL
    negative_class_name: str = NEGATIVE_CLASS_NAME
    negative_class_label: int = NEGATIVE_CLASS_LABEL
    primary_metrics: Tuple[str, ...] = (
        "precision",
        "recall",
        "f1",
        "macro_f1",
        "false_positive_rate",
        "confusion_matrix",
    )
    confusion_matrix_labels: Tuple[int, ...] = (0, 1)
    error_analysis_breakdown_column: str = "Attack"
    expected_attack_categories: Tuple[str, ...] = EXPECTED_ATTACK_CATEGORIES

    def validate(self) -> None:
        if self.task != "binary_classification":
            raise ValueError(f"Task must be 'binary_classification', got {self.task}")
        if self.target_column != TARGET_COLUMN:
            raise ValueError(f"Target column must be '{TARGET_COLUMN}'")
        if self.stratification_column != STRATIFICATION_COLUMN:
            raise ValueError(f"Stratification column must be '{STRATIFICATION_COLUMN}'")
        if self.positive_class_name != "Attack" or self.positive_class_label != 1:
            raise ValueError("Positive class must be 'Attack' with integer label 1")
        if self.negative_class_name != "Benign" or self.negative_class_label != 0:
            raise ValueError("Negative class must be 'Benign' with integer label 0")
        required_metrics = {
            "precision",
            "recall",
            "f1",
            "macro_f1",
            "false_positive_rate",
            "confusion_matrix",
        }
        if not required_metrics.issubset(set(self.primary_metrics)):
            missing = required_metrics - set(self.primary_metrics)
            raise ValueError(f"Missing required primary metrics: {missing}")
        if self.confusion_matrix_labels != (0, 1):
            raise ValueError("confusion_matrix_labels must be ordered (0, 1)")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task": self.task,
            "target_column": self.target_column,
            "stratification_column": self.stratification_column,
            "positive_class_name": self.positive_class_name,
            "positive_class_label": self.positive_class_label,
            "negative_class_name": self.negative_class_name,
            "negative_class_label": self.negative_class_label,
            "primary_metrics": list(self.primary_metrics),
            "confusion_matrix_labels": list(self.confusion_matrix_labels),
            "error_analysis_breakdown_column": self.error_analysis_breakdown_column,
            "expected_attack_categories": list(self.expected_attack_categories),
        }


@dataclass(frozen=True)
class SplitReference:
    """Reference binding to the official split protocol."""

    protocol_id: str = SPLIT_PROTOCOL_ID
    manifest_path: str = "reports/splits/nf_unsw_nb15_v3_split_manifest.json"
    manifest_sha256: str = "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88"
    status: str = "PASS"

    def validate(self) -> None:
        if self.protocol_id != SPLIT_PROTOCOL_ID:
            raise ValueError(f"Split protocol mismatch: expected {SPLIT_PROTOCOL_ID}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PreprocessingReference:
    """Reference binding to the official train-only preprocessing artifact."""

    contract_id: str = PREPROCESSING_CONTRACT_ID
    artifact_path: str = "artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib"
    artifact_sha256: str = "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"
    manifest_path: str = "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json"
    manifest_sha256: str = "af07dc3b6c7cbc9e75426eeb5b96d52dbd191e8a09161699df2fad1bb5555441"
    status: str = "PASS"

    def validate(self) -> None:
        if self.contract_id != PREPROCESSING_CONTRACT_ID:
            raise ValueError(f"Preprocessing contract mismatch: expected {PREPROCESSING_CONTRACT_ID}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class XGBoostBaselineProtocol:
    """Full protocol specification for XGBoost baseline on NF-UNSW-NB15-v3."""

    protocol_version: str = PROTOCOL_IDENTIFIER
    feature_contract_version: str = FEATURE_CONTRACT_VERSION
    dataset_name: str = DATASET_NAME
    dataset_csv_sha256: str = DATASET_CSV_SHA256
    split_reference: SplitReference = field(default_factory=SplitReference)
    preprocessing_reference: PreprocessingReference = field(default_factory=PreprocessingReference)
    model_config: XGBoostBaselineConfig = field(default_factory=XGBoostBaselineConfig)
    selected_features: Tuple[str, ...] = field(default_factory=lambda: tuple(ML_FEATURE_COLUMNS))
    excluded_metadata_features: Tuple[str, ...] = field(default_factory=lambda: tuple(TRACE_METADATA_COLUMNS))
    excluded_target_columns: Tuple[str, ...] = field(default_factory=lambda: tuple(TARGET_COLUMNS))
    tuning_policy: TuningConfig = field(default_factory=TuningConfig)
    test_lock_policy: TestLockPolicy = field(default_factory=TestLockPolicy)
    evaluation_protocol: EvaluationMetricProtocol = field(default_factory=EvaluationMetricProtocol)

    def validate(self) -> None:
        """Validate protocol compliance fail-closed."""
        if self.protocol_version != PROTOCOL_IDENTIFIER:
            raise ValueError(f"Protocol version mismatch: {self.protocol_version}")
        if self.feature_contract_version != FEATURE_CONTRACT_VERSION:
            raise ValueError(f"Feature contract mismatch: {self.feature_contract_version}")
        if len(self.selected_features) != 47:
            raise ValueError(f"Expected 47 ML features, got {len(self.selected_features)}")
        validate_feature_selection(list(self.selected_features))

        self.split_reference.validate()
        self.preprocessing_reference.validate()
        self.model_config.validate()
        self.tuning_policy.validate()
        self.test_lock_policy.validate()
        self.evaluation_protocol.validate()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "feature_contract_version": self.feature_contract_version,
            "dataset_name": self.dataset_name,
            "dataset_csv_sha256": self.dataset_csv_sha256,
            "split_reference": self.split_reference.to_dict(),
            "preprocessing_reference": self.preprocessing_reference.to_dict(),
            "model_config": self.model_config.to_dict(),
            "selected_features": list(self.selected_features),
            "excluded_metadata_features": list(self.excluded_metadata_features),
            "excluded_target_columns": list(self.excluded_target_columns),
            "tuning_policy": self.tuning_policy.to_dict(),
            "test_lock_policy": self.test_lock_policy.to_dict(),
            "evaluation_protocol": self.evaluation_protocol.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def create_xgb_baseline_protocol(
    random_seed: int = RANDOM_SEED,
    n_estimators: int = 200,
    max_depth: int = 6,
    learning_rate: float = 0.1,
    is_canonical: bool = True,
    configuration_id: str = "xgb-baseline-canonical-v1",
) -> XGBoostBaselineProtocol:
    """Factory function for creating an XGBoostBaselineProtocol instance."""
    cfg = XGBoostBaselineConfig(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        random_state=random_seed,
        is_canonical_baseline=is_canonical,
        configuration_id=configuration_id,
    )
    protocol = XGBoostBaselineProtocol(model_config=cfg)
    protocol.validate()
    return protocol
