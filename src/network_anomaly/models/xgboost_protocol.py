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
                if actual_v != canonical_v:
                    raise ValueError(
                        f"Canonical baseline configuration mismatch for '{k}': "
                        f"expected {canonical_v}, got {actual_v}. If this is an intentional "
                        f"override, set is_canonical_baseline=False and provide a distinct configuration_id."
                    )

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


@dataclass
class XGBoostBaselineProtocol:
    """Full protocol specification for XGBoost baseline on NF-UNSW-NB15-v3."""

    protocol_id: str = PROTOCOL_IDENTIFIER
    feature_contract_version: str = FEATURE_CONTRACT_VERSION
    split_protocol_id: str = SPLIT_PROTOCOL_ID
    preprocessing_contract_id: str = PREPROCESSING_CONTRACT_ID
    dataset_name: str = DATASET_NAME
    model_config: XGBoostBaselineConfig = field(default_factory=XGBoostBaselineConfig)
    selected_features: List[str] = field(default_factory=lambda: list(ML_FEATURE_COLUMNS))

    def validate(self) -> None:
        """Validate protocol compliance fail-closed."""
        self.model_config.validate()
        validate_feature_selection(self.selected_features)
        if len(self.selected_features) != 47:
            raise ValueError(
                f"Feature contract violation: expected 47 ML features, got {len(self.selected_features)}"
            )


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
