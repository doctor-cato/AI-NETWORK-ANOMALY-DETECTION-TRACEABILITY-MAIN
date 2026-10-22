"""Random Forest supervised model and baseline protocol integration."""

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import NotFittedError

from network_anomaly.config import RANDOM_FOREST_DEFAULTS
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.models.random_forest_protocol import (
    ALL_ATTACK_CATEGORIES,
    EXPECTED_ATTACK_CATEGORIES,
    FEATURE_CONTRACT_VERSION,
    NEGATIVE_CLASS_LABEL,
    NEGATIVE_CLASS_NAME,
    POSITIVE_CLASS_LABEL,
    POSITIVE_CLASS_NAME,
    PREPROCESSING_CONTRACT_ID,
    PROTOCOL_IDENTIFIER,
    SPLIT_PROTOCOL_ID,
    STRATIFICATION_COLUMN,
    TARGET_COLUMN,
    EvaluationMetricProtocol,
    PreprocessingReference,
    RandomForestBaselineConfig,
    RandomForestBaselineProtocol,
    SplitReference,
    TestLockPolicy,
    TuningConfig,
    create_rf_baseline_protocol,
)


class RandomForestModel:
    """Random Forest supervised model component for network anomaly detection.

    Implements the model component required for Issue #10 based on the Issue #9 protocol.
    Provides standard model interfaces:
      - __init__(config=None, protocol=None)
      - build_model()
      - fit(X, y, **fit_params)
      - predict(X)
      - predict_proba(X)

    Note:
      fit() is an interface for future training on real NF-UNSW-NB15-v3 data once
      Issue #7 and #8 are completed. It is NOT executed in this setup phase.
    """

    def __init__(
        self,
        config: Optional[
            Union[Dict[str, Any], RandomForestBaselineConfig, RandomForestBaselineProtocol]
        ] = None,
        protocol: Optional[RandomForestBaselineProtocol] = None,
    ) -> None:
        if protocol is not None:
            self.protocol: Optional[RandomForestBaselineProtocol] = protocol
            self.config: RandomForestBaselineConfig = protocol.model_config
        elif isinstance(config, RandomForestBaselineProtocol):
            self.protocol = config
            self.config = config.model_config
        elif isinstance(config, RandomForestBaselineConfig):
            self.protocol = None
            self.config = config
        elif isinstance(config, dict):
            self.protocol = None
            self.config = RandomForestBaselineConfig.from_dict(config)
        elif config is None:
            self.protocol = None
            self.config = RandomForestBaselineConfig()
        else:
            raise TypeError(f"Unsupported config type: {type(config)}")

        self.model_type: str = self.config.model_type
        self.task: str = self.config.task
        self.target: str = self.config.target
        self.positive_class: str = self.config.positive_class
        self.random_state: int = self.config.random_state
        self.feature_names: tuple[str, ...] = (
            tuple(self.protocol.selected_features)
            if self.protocol is not None
            else tuple(ML_FEATURE_COLUMNS)
        )

        self._estimator: RandomForestClassifier = self.build_model()
        self._is_fitted: bool = False

    def build_model(self) -> RandomForestClassifier:
        """Construct the underlying scikit-learn RandomForestClassifier from config."""
        return RandomForestClassifier(**self.config.to_sklearn_params())

    @property
    def estimator(self) -> RandomForestClassifier:
        """Access the underlying scikit-learn estimator instance."""
        return self._estimator

    @property
    def is_fitted(self) -> bool:
        """Indicate whether the model has been fitted with real training data."""
        return self._is_fitted

    def fit(self, X: Any, y: Any, **fit_params: Any) -> "RandomForestModel":
        """Fit interface for future training on verified NF-UNSW-NB15-v3 data."""
        self._estimator.fit(X, y, **fit_params)
        self._is_fitted = True
        return self

    def predict(self, X: Any) -> Any:
        """Predict binary labels (0 for Benign, 1 for Attack)."""
        if not self._is_fitted:
            raise NotFittedError(
                "This RandomForestModel instance is not fitted yet. "
                "Call 'fit' with verified NF-UNSW-NB15-v3 training data before using 'predict'."
            )
        return self._estimator.predict(X)

    def predict_proba(self, X: Any) -> Any:
        """Predict class probabilities for anomaly detection."""
        if not self._is_fitted:
            raise NotFittedError(
                "This RandomForestModel instance is not fitted yet. "
                "Call 'fit' with verified NF-UNSW-NB15-v3 training data before using 'predict_proba'."
            )
        return self._estimator.predict_proba(X)


def build_model(
    config: Optional[
        Union[Dict[str, Any], RandomForestBaselineConfig, RandomForestBaselineProtocol]
    ] = None,
) -> RandomForestClassifier:
    """Build a RandomForestClassifier instance from a configuration or protocol."""
    if config is None:
        cfg = RANDOM_FOREST_DEFAULTS.copy()
    elif isinstance(config, RandomForestBaselineProtocol):
        cfg = config.model_config.to_sklearn_params()
    elif isinstance(config, RandomForestBaselineConfig):
        cfg = config.to_sklearn_params()
    elif isinstance(config, dict):
        cfg = config.copy()
        sklearn_keys = {
            "n_estimators",
            "max_depth",
            "min_samples_split",
            "min_samples_leaf",
            "criterion",
            "max_features",
            "class_weight",
            "random_state",
            "n_jobs",
            "bootstrap",
        }
        cfg = {k: v for k, v in cfg.items() if k in sklearn_keys}
    else:
        raise TypeError(f"Unsupported config type: {type(config)}")
    return RandomForestClassifier(**cfg)


__all__ = [
    "RandomForestModel",
    "build_model",
    "PROTOCOL_IDENTIFIER",
    "FEATURE_CONTRACT_VERSION",
    "SPLIT_PROTOCOL_ID",
    "PREPROCESSING_CONTRACT_ID",
    "TARGET_COLUMN",
    "STRATIFICATION_COLUMN",
    "POSITIVE_CLASS_NAME",
    "POSITIVE_CLASS_LABEL",
    "NEGATIVE_CLASS_NAME",
    "NEGATIVE_CLASS_LABEL",
    "EXPECTED_ATTACK_CATEGORIES",
    "ALL_ATTACK_CATEGORIES",
    "RandomForestBaselineConfig",
    "TuningConfig",
    "TestLockPolicy",
    "EvaluationMetricProtocol",
    "SplitReference",
    "PreprocessingReference",
    "RandomForestBaselineProtocol",
    "create_rf_baseline_protocol",
]
