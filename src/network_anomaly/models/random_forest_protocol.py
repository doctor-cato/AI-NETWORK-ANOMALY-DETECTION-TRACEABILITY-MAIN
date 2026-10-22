"""Random Forest baseline protocol and configuration for NF-UNSW-NB15-v3.

This module formalizes the protocol contracts for Issue #9.
It does NOT execute model training, evaluation, or benchmark generation.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from network_anomaly.config import RANDOM_FOREST_DEFAULTS, RANDOM_SEED
from network_anomaly.data.nf_unsw_nb15_v3 import (
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
)

PROTOCOL_IDENTIFIER: str = "rf-baseline-nf-unsw-nb15-v3-v1"
FEATURE_CONTRACT_VERSION: str = "nf-unsw-nb15-v3-baseline-47"
SPLIT_PROTOCOL_ID: str = "nf-unsw-nb15-v3-temporal-group-v1"
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


@dataclass(frozen=True)
class RandomForestBaselineConfig:
    """Hyperparameter and metadata configuration for the Random Forest baseline model."""

    model_type: str = "RandomForest"
    task: str = "binary_classification"
    target: str = "Label"
    positive_class: str = "Attack"
    n_estimators: int = 200
    max_depth: Optional[int] = 16
    min_samples_split: int = 2
    min_samples_leaf: int = 1
    criterion: str = "gini"
    max_features: Union[str, int, float, None] = "sqrt"
    class_weight: Optional[Union[str, Dict[Any, Any]]] = None
    random_state: int = RANDOM_SEED
    n_jobs: int = -1
    bootstrap: bool = True

    def validate(self) -> None:
        """Validate hyperparameter invariants."""
        if self.model_type != "RandomForest":
            raise ValueError(f"model_type must be 'RandomForest', got {self.model_type}")
        if self.task != "binary_classification":
            raise ValueError(f"task must be 'binary_classification', got {self.task}")
        if self.target != "Label":
            raise ValueError(f"target must be 'Label', got {self.target}")
        if self.positive_class != "Attack":
            raise ValueError(f"positive_class must be 'Attack', got {self.positive_class}")
        if self.n_estimators <= 0:
            raise ValueError(f"n_estimators must be positive, got {self.n_estimators}")
        if self.max_depth is not None and self.max_depth <= 0:
            raise ValueError(f"max_depth must be positive or None, got {self.max_depth}")
        if self.min_samples_split < 2:
            raise ValueError(f"min_samples_split must be >= 2, got {self.min_samples_split}")
        if self.min_samples_leaf < 1:
            raise ValueError(f"min_samples_leaf must be >= 1, got {self.min_samples_leaf}")
        if self.criterion not in {"gini", "entropy", "log_loss"}:
            raise ValueError(f"Unsupported criterion: {self.criterion}")
        if self.random_state is None:
            raise ValueError("random_state must be an integer seed for reproducibility")

    def to_sklearn_params(self) -> Dict[str, Any]:
        """Extract only the kwargs accepted by sklearn's RandomForestClassifier."""
        return {
            "n_estimators": self.n_estimators,
            "max_depth": self.max_depth,
            "min_samples_split": self.min_samples_split,
            "min_samples_leaf": self.min_samples_leaf,
            "criterion": self.criterion,
            "max_features": self.max_features,
            "class_weight": self.class_weight,
            "random_state": self.random_state,
            "n_jobs": self.n_jobs,
            "bootstrap": self.bootstrap,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RandomForestBaselineConfig:
        """Create and validate configuration from dictionary."""
        valid_fields = cls.__annotations__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        config = cls(**filtered)
        config.validate()
        return config


@dataclass(frozen=True)
class TuningConfig:
    """Hyperparameter tuning policy configuration.

    Enforces that hyperparameter exploration only occurs on train and validation
    partitions, strictly preventing test partition contamination.
    """

    enabled: bool = False
    search_space_version: str = "rf-tuning-search-v1"
    search_space: Dict[str, List[Any]] = field(
        default_factory=lambda: {
            "n_estimators": [100, 200, 300],
            "max_depth": [12, 16, 24, None],
            "min_samples_split": [2, 5, 10],
            "min_samples_leaf": [1, 2, 4],
            "max_features": ["sqrt", "log2"],
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
            raise ValueError(
                "Violation of tuning isolation: 'test' partition is strictly forbidden in tuning"
            )
        valid_partitions = {"train", "validation"}
        if not set(self.allowed_partitions).issubset(valid_partitions):
            raise ValueError(
                f"allowed_partitions must only contain 'train' and/or 'validation', "
                f"got {self.allowed_partitions}"
            )
        if not self.allowed_partitions:
            raise ValueError("allowed_partitions cannot be empty")
        valid_metrics = {"macro_f1", "f1", "precision", "recall"}
        if self.scoring_metric not in valid_metrics:
            raise ValueError(
                f"Unsupported scoring_metric: {self.scoring_metric}. Must be one of {valid_metrics}"
            )
        if self.random_state is None:
            raise ValueError("random_state must be an integer seed for reproducible tuning")

    def to_dict(self) -> Dict[str, Any]:
        """Convert tuning policy to dictionary."""
        return {
            "enabled": self.enabled,
            "search_space_version": self.search_space_version,
            "search_space": self.search_space,
            "tuning_budget": self.tuning_budget,
            "allowed_partitions": list(self.allowed_partitions),
            "scoring_metric": self.scoring_metric,
            "random_state": self.random_state,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TuningConfig:
        """Create and validate tuning configuration from dictionary."""
        d = data.copy()
        if "allowed_partitions" in d and isinstance(d["allowed_partitions"], (list, tuple)):
            d["allowed_partitions"] = tuple(d["allowed_partitions"])
        cfg = cls(**d)
        cfg.validate()
        return cfg


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
        """Validate that test lock policy cannot be bypassed."""
        if not self.locked:
            raise ValueError(
                "TestLockPolicy violation: locked must be True. Test partition cannot be unlocked."
            )
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
            raise ValueError(
                "Test partition evaluation count must be exactly 1 (one-shot final evaluation)."
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert test lock policy to dictionary."""
        return {
            "locked": self.locked,
            "purpose": self.purpose,
            "forbidden_uses": list(self.forbidden_uses),
            "max_evaluation_count": self.max_evaluation_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TestLockPolicy:
        """Create and validate test lock policy from dictionary."""
        d = data.copy()
        if "forbidden_uses" in d and isinstance(d["forbidden_uses"], (list, tuple)):
            d["forbidden_uses"] = tuple(d["forbidden_uses"])
        policy = cls(**d)
        policy.validate()
        return policy


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
        """Validate evaluation invariants."""
        if self.task != "binary_classification":
            raise ValueError(f"Task must be 'binary_classification', got {self.task}")
        if self.target_column != TARGET_COLUMN:
            raise ValueError(f"Target column must be '{TARGET_COLUMN}', got {self.target_column}")
        if self.stratification_column != STRATIFICATION_COLUMN:
            raise ValueError(
                f"Stratification column must be '{STRATIFICATION_COLUMN}', "
                f"got {self.stratification_column}"
            )
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
            raise ValueError("confusion_matrix_labels must be ordered (0, 1) for [Benign, Attack]")

    def to_dict(self) -> Dict[str, Any]:
        """Convert evaluation protocol to dictionary."""
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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvaluationMetricProtocol:
        """Create and validate evaluation protocol from dictionary."""
        d = data.copy()
        if "primary_metrics" in d and isinstance(d["primary_metrics"], (list, tuple)):
            d["primary_metrics"] = tuple(d["primary_metrics"])
        if "confusion_matrix_labels" in d and isinstance(
            d["confusion_matrix_labels"], (list, tuple)
        ):
            d["confusion_matrix_labels"] = tuple(d["confusion_matrix_labels"])
        if "expected_attack_categories" in d and isinstance(
            d["expected_attack_categories"], (list, tuple)
        ):
            d["expected_attack_categories"] = tuple(d["expected_attack_categories"])
        proto = cls(**d)
        proto.validate()
        return proto


@dataclass(frozen=True)
class SplitReference:
    """Reference to the official NF-UNSW-NB15-v3 split artifact (Issue #7 dependency)."""

    dataset_name: str = DATASET_NAME
    dataset_csv_sha256: str = DATASET_CSV_SHA256
    dataset_archive_sha256: str = DATASET_ARCHIVE_SHA256
    split_protocol_id: str = SPLIT_PROTOCOL_ID
    split_id: str = "nf-unsw-nb15-v3-temporal-group-v1"
    split_status: str = "PLANNED / NOT VERIFIED"
    ml_ready: bool = False
    partitions: Tuple[str, ...] = ("train", "validation", "test")

    def validate(self) -> None:
        """Validate split reference invariants."""
        if self.dataset_name != DATASET_NAME:
            raise ValueError(f"Dataset name must be '{DATASET_NAME}', got {self.dataset_name}")
        if not self.split_id or not isinstance(self.split_id, str) or not self.split_id.strip():
            raise ValueError("split_id must be a non-empty string referencing the split artifact")
        if self.partitions != ("train", "validation", "test"):
            raise ValueError("partitions must be ('train', 'validation', 'test')")

    def to_dict(self) -> Dict[str, Any]:
        """Convert split reference to dictionary."""
        return {
            "dataset_name": self.dataset_name,
            "dataset_csv_sha256": self.dataset_csv_sha256,
            "dataset_archive_sha256": self.dataset_archive_sha256,
            "split_protocol_id": self.split_protocol_id,
            "split_id": self.split_id,
            "split_status": self.split_status,
            "ml_ready": self.ml_ready,
            "partitions": list(self.partitions),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SplitReference:
        """Create and validate split reference from dictionary."""
        d = data.copy()
        if "partitions" in d and isinstance(d["partitions"], (list, tuple)):
            d["partitions"] = tuple(d["partitions"])
        ref = cls(**d)
        ref.validate()
        return ref


@dataclass(frozen=True)
class PreprocessingReference:
    """Reference to train-only preprocessing artifact contract (Issue #8 dependency)."""

    preprocessing_contract_id: str = PREPROCESSING_CONTRACT_ID
    fit_boundary: str = "train_only"
    preprocessing_status: str = "PLANNED / NOT VERIFIED"
    fitted_artifact_path: Optional[str] = None

    def validate(self) -> None:
        """Validate preprocessing reference invariants."""
        if self.fit_boundary != "train_only":
            raise ValueError(
                f"Fit boundary violation: fit_boundary must be 'train_only', "
                f"got {self.fit_boundary}"
            )
        if not self.preprocessing_contract_id or not self.preprocessing_contract_id.strip():
            raise ValueError("preprocessing_contract_id must be a non-empty string")

    def to_dict(self) -> Dict[str, Any]:
        """Convert preprocessing reference to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PreprocessingReference:
        """Create and validate preprocessing reference from dictionary."""
        ref = cls(**data)
        ref.validate()
        return ref


@dataclass(frozen=True)
class RandomForestBaselineProtocol:
    """Complete, versioned protocol specification for Random Forest baseline."""

    protocol_version: str = PROTOCOL_IDENTIFIER
    protocol_name: str = "NF-UNSW-NB15-v3 Random Forest Baseline Protocol"
    feature_contract_version: str = FEATURE_CONTRACT_VERSION
    selected_features: Tuple[str, ...] = ML_FEATURE_COLUMNS
    excluded_metadata: Tuple[str, ...] = TRACE_METADATA_COLUMNS
    excluded_targets: Tuple[str, ...] = TARGET_COLUMNS
    model_config: RandomForestBaselineConfig = field(default_factory=RandomForestBaselineConfig)
    tuning_policy: TuningConfig = field(default_factory=TuningConfig)
    test_lock: TestLockPolicy = field(default_factory=TestLockPolicy)
    evaluation_protocol: EvaluationMetricProtocol = field(
        default_factory=EvaluationMetricProtocol
    )
    split_reference: SplitReference = field(default_factory=SplitReference)
    preprocessing_reference: PreprocessingReference = field(
        default_factory=PreprocessingReference
    )
    metadata: Dict[str, Any] = field(
        default_factory=lambda: {
            "issue": 9,
            "status": "IMPLEMENTED / TESTED",
            "dependencies": "#7 -> #8 -> #9 -> #10 -> #12",
            "training_status": "PLANNED (Issue #10)",
            "evaluation_status": "PLANNED (Issue #12)",
            "benchmark_claim": "NOT_AVAILABLE_YET",
            "synthetic_data_used": False,
        }
    )

    def validate(self) -> None:
        """Validate entire protocol against all safety invariants."""
        # 1. Feature contract validation
        validate_feature_selection(self.selected_features, require_complete=True)
        if self.selected_features != ML_FEATURE_COLUMNS:
            raise ValueError(
                "selected_features does not match the ordered 47 ML feature baseline contract"
            )
        if len(self.selected_features) != 47:
            raise ValueError(
                f"selected_features must have exactly 47 features, got {len(self.selected_features)}"
            )

        # 2. Strict target and metadata exclusion
        overlap_targets = set(self.selected_features) & set(self.excluded_targets)
        if overlap_targets:
            raise ValueError(
                f"Target leakage violation: features contain targets: {overlap_targets}"
            )
        if "Label" in self.selected_features:
            raise ValueError("Target leakage violation: 'Label' found in feature selection")
        if "Attack" in self.selected_features:
            raise ValueError("Target leakage violation: 'Attack' found in feature selection")

        overlap_meta = set(self.selected_features) & set(self.excluded_metadata)
        if overlap_meta:
            raise ValueError(
                f"Metadata leakage violation: features contain trace metadata: {overlap_meta}"
            )

        # 3. Child component validations
        self.model_config.validate()
        self.tuning_policy.validate()
        self.test_lock.validate()
        self.evaluation_protocol.validate()
        self.split_reference.validate()
        self.preprocessing_reference.validate()

    def to_dict(self) -> Dict[str, Any]:
        """Convert protocol to serializable dictionary."""
        return {
            "protocol_version": self.protocol_version,
            "protocol_name": self.protocol_name,
            "feature_contract_version": self.feature_contract_version,
            "selected_features": list(self.selected_features),
            "excluded_metadata": list(self.excluded_metadata),
            "excluded_targets": list(self.excluded_targets),
            "model_config": self.model_config.to_dict(),
            "tuning_policy": self.tuning_policy.to_dict(),
            "test_lock": self.test_lock.to_dict(),
            "evaluation_protocol": self.evaluation_protocol.to_dict(),
            "split_reference": self.split_reference.to_dict(),
            "preprocessing_reference": self.preprocessing_reference.to_dict(),
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert protocol to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RandomForestBaselineProtocol:
        """Reconstruct and validate protocol from dictionary."""
        d = data.copy()
        selected_features = tuple(d.get("selected_features", ML_FEATURE_COLUMNS))
        excluded_metadata = tuple(d.get("excluded_metadata", TRACE_METADATA_COLUMNS))
        excluded_targets = tuple(d.get("excluded_targets", TARGET_COLUMNS))
        model_config = RandomForestBaselineConfig.from_dict(d.get("model_config", {}))
        tuning_policy = TuningConfig.from_dict(d.get("tuning_policy", {}))
        test_lock = TestLockPolicy.from_dict(d.get("test_lock", {}))
        evaluation_protocol = EvaluationMetricProtocol.from_dict(d.get("evaluation_protocol", {}))
        split_reference = SplitReference.from_dict(d.get("split_reference", {}))
        preprocessing_reference = PreprocessingReference.from_dict(
            d.get("preprocessing_reference", {})
        )
        metadata = d.get("metadata", {})

        protocol = cls(
            protocol_version=d.get("protocol_version", PROTOCOL_IDENTIFIER),
            protocol_name=d.get(
                "protocol_name", "NF-UNSW-NB15-v3 Random Forest Baseline Protocol"
            ),
            feature_contract_version=d.get("feature_contract_version", FEATURE_CONTRACT_VERSION),
            selected_features=selected_features,
            excluded_metadata=excluded_metadata,
            excluded_targets=excluded_targets,
            model_config=model_config,
            tuning_policy=tuning_policy,
            test_lock=test_lock,
            evaluation_protocol=evaluation_protocol,
            split_reference=split_reference,
            preprocessing_reference=preprocessing_reference,
            metadata=metadata,
        )
        protocol.validate()
        return protocol

    @classmethod
    def from_json(cls, json_str: str) -> RandomForestBaselineProtocol:
        """Reconstruct and validate protocol from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def save(self, path: Union[str, Path]) -> None:
        """Save validated protocol JSON to specified path."""
        self.validate()
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: Union[str, Path]) -> RandomForestBaselineProtocol:
        """Load and validate protocol from JSON file."""
        p = Path(path)
        return cls.from_json(p.read_text(encoding="utf-8"))


def create_rf_baseline_protocol(
    split_id: str = "nf-unsw-nb15-v3-temporal-group-v1",
    random_seed: int = RANDOM_SEED,
    n_estimators: int = 200,
    max_depth: Optional[int] = 16,
    **kwargs: Any,
) -> RandomForestBaselineProtocol:
    """Factory function to instantiate a validated Random Forest baseline protocol."""
    model_cfg = RandomForestBaselineConfig(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_seed,
        **{k: v for k, v in kwargs.items() if k in RandomForestBaselineConfig.__annotations__},
    )
    split_ref = SplitReference(split_id=split_id)
    tuning_cfg = TuningConfig(random_state=random_seed)
    protocol = RandomForestBaselineProtocol(
        model_config=model_cfg,
        split_reference=split_ref,
        tuning_policy=tuning_cfg,
    )
    protocol.validate()
    return protocol
