"""XGBoost supervised model and baseline protocol integration (Issue #31 / C3).

Follows the identical shared supervised protocol and component structure as Random Forest:
  - XGBoostModel wrapper class providing fit(), predict(), predict_proba(), save(), load(), load_verified().
  - build_model() factory returning XGBClassifier for backward compatibility.
  - Strict 47-feature NetFlow v3 contract enforcement.
  - Fail-closed manifest verification with byte-for-byte SHA-256 integrity check.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.exceptions import NotFittedError
from xgboost import XGBClassifier

from network_anomaly.config import RANDOM_SEED, XGBOOST_DEFAULTS
from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
)
from network_anomaly.models.xgboost_protocol import (
    ALL_ATTACK_CATEGORIES,
    CANONICAL_BASELINE_PARAMS,
    EXPECTED_ATTACK_CATEGORIES,
    FEATURE_CONTRACT_VERSION,
    NEGATIVE_CLASS_LABEL,
    NEGATIVE_CLASS_NAME,
    POSITIVE_CLASS_LABEL,
    POSITIVE_CLASS_NAME,
    PREPROCESSING_CONTRACT_ID,
    PROTOCOL_IDENTIFIER,
    SPLIT_PROTOCOL_ID,
    TARGET_COLUMN,
    XGBoostBaselineConfig,
    XGBoostBaselineProtocol,
    create_xgb_baseline_protocol,
)


class XGBoostModel:
    """XGBoost supervised model component for network anomaly detection.

    Implements the model component required for Issue #31 / C3 consistent with RandomForestModel.
    Provides standard model interfaces:
      - __init__(config=None, protocol=None)
      - build_model()
      - fit(X, y, **fit_params)
      - predict(X)
      - predict_proba(X)
      - save(model_path, manifest_path=None)
      - load(model_path)
      - load_verified(model_path, manifest_path=None)
    """

    def __init__(
        self,
        config: Optional[
            Union[Dict[str, Any], XGBoostBaselineConfig, XGBoostBaselineProtocol]
        ] = None,
        protocol: Optional[XGBoostBaselineProtocol] = None,
    ) -> None:
        if protocol is not None:
            protocol.validate()
            self.protocol: Optional[XGBoostBaselineProtocol] = protocol
            self.config: XGBoostBaselineConfig = protocol.model_config
            self.config.validate()
        elif isinstance(config, XGBoostBaselineProtocol):
            config.validate()
            self.protocol = config
            self.config = config.model_config
            self.config.validate()
        elif isinstance(config, XGBoostBaselineConfig):
            config.validate()
            self.protocol = None
            self.config = config
        elif isinstance(config, dict):
            cfg_dict = copy.deepcopy(config)
            is_canonical = cfg_dict.pop("is_canonical_baseline", False)
            config_id = cfg_dict.pop("configuration_id", "xgb-custom")
            self.config = XGBoostBaselineConfig(
                **cfg_dict,
                is_canonical_baseline=is_canonical,
                configuration_id=config_id,
            )
            self.config.validate()
            self.protocol = None
        else:
            self.config = XGBoostBaselineConfig()
            self.config.validate()
            self.protocol = None

        self.model_type: str = "XGBoost"
        self.task: str = "binary_classification"
        self.target: str = TARGET_COLUMN
        self.positive_class: str = POSITIVE_CLASS_NAME
        self.random_state: int = self.config.random_state

        if self.protocol is not None:
            self.feature_names: Tuple[str, ...] = tuple(self.protocol.selected_features)
        else:
            self.feature_names = tuple(ML_FEATURE_COLUMNS)

        self.estimator: XGBClassifier = self.build_model()
        self._is_fitted: bool = False
        self._classes: Optional[np.ndarray] = None

    @property
    def is_fitted(self) -> bool:
        """Indicate whether the model has been fitted."""
        return self._is_fitted

    @property
    def classes_(self) -> Any:
        """Class labels known to the classifier."""
        return getattr(self.estimator, "classes_", None)

    def build_model(self) -> XGBClassifier:
        """Instantiate untracked XGBClassifier with configured parameters."""
        params = self.config.get_xgb_params()
        params.setdefault("verbosity", 0)
        return XGBClassifier(**params)

    def fit(self, X: Any, y: Any, **fit_params: Any) -> "XGBoostModel":
        """Fit model enforcing 47 ML features contract and target contract."""
        if isinstance(X, pd.DataFrame):
            missing_feats = set(self.feature_names) - set(X.columns)
            if missing_feats:
                raise ValueError(f"Feature contract violation: missing required features {missing_feats}")
            X_mat = X[list(self.feature_names)].values
        else:
            X_mat = np.asarray(X)
            if X_mat.ndim != 2 or X_mat.shape[1] != len(self.feature_names):
                raise ValueError(
                    f"Feature dimension mismatch: expected {len(self.feature_names)} features, got {X_mat.shape[1] if X_mat.ndim == 2 else 'non-2d'}"
                )

        y_arr = np.asarray(y)
        unique_labels = np.unique(y_arr)
        if not set(unique_labels).issubset({0, 1}):
            raise ValueError(f"Target Label contract violation: expected binary {0, 1}, got {unique_labels}")

        self.estimator.fit(X_mat, y_arr, **fit_params)
        self._is_fitted = True
        self._classes = getattr(self.estimator, "classes_", np.array([0, 1]))
        return self

    def predict(self, X: Any) -> np.ndarray:
        """Predict binary anomaly labels (0 or 1)."""
        if not self._is_fitted:
            raise NotFittedError("XGBoostModel is not fitted yet. Call fit() before predict().")
        if isinstance(X, pd.DataFrame):
            X_mat = X[list(self.feature_names)].values
        else:
            X_mat = np.asarray(X)
        return self.estimator.predict(X_mat)

    def predict_proba(self, X: Any) -> np.ndarray:
        """Predict class probabilities."""
        if not self._is_fitted:
            raise NotFittedError("XGBoostModel is not fitted yet. Call fit() before predict_proba().")
        if isinstance(X, pd.DataFrame):
            X_mat = X[list(self.feature_names)].values
        else:
            X_mat = np.asarray(X)
        return self.estimator.predict_proba(X_mat)

    def save(
        self,
        model_path: Union[str, Path],
        manifest_path: Optional[Union[str, Path]] = None,
        extra_manifest_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Save fitted model artifact and generate companion provenance manifest."""
        if not self._is_fitted:
            raise NotFittedError("Cannot save an unfitted XGBoostModel.")

        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.estimator, model_path)

        with open(model_path, "rb") as f:
            artifact_sha256 = hashlib.sha256(f.read()).hexdigest()

        manifest_data: Dict[str, Any] = {
            "model_type": self.model_type,
            "task": self.task,
            "target": self.target,
            "feature_contract_version": FEATURE_CONTRACT_VERSION,
            "feature_names": list(self.feature_names),
            "num_features": len(self.feature_names),
            "configuration": self.config.to_dict(),
            "model_artifact_path": str(model_path.as_posix()),
            "model_artifact_sha256": artifact_sha256,
        }
        if extra_manifest_fields:
            manifest_data.update(extra_manifest_fields)

        if manifest_path is not None:
            manifest_path = Path(manifest_path)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2, ensure_ascii=False)

        return manifest_data

    @classmethod
    def load(cls, model_path: Union[str, Path]) -> "XGBoostModel":
        """Load fitted XGBoost model from artifact path without verification."""
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {model_path}")
        estimator = joblib.load(model_path)
        instance = cls()
        instance.estimator = estimator
        instance._is_fitted = True
        instance._classes = getattr(estimator, "classes_", np.array([0, 1]))
        return instance

    @classmethod
    def load_verified(
        cls,
        model_path: Union[str, Path],
        manifest_path: Optional[Union[str, Path]] = None,
        expected_sha256: Optional[str] = None,
    ) -> "XGBoostModel":
        """Load fitted XGBoost model and verify byte-for-byte SHA-256 integrity fail-closed."""
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {model_path}")

        with open(model_path, "rb") as f:
            actual_sha256 = hashlib.sha256(f.read()).hexdigest()

        target_sha256 = expected_sha256
        if target_sha256 is None and manifest_path is not None:
            manifest_path = Path(manifest_path)
            if not manifest_path.exists():
                raise FileNotFoundError(f"Manifest not found at {manifest_path}")
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            target_sha256 = manifest_data.get("model_artifact_sha256")

        if target_sha256 is None:
            raise ValueError("Integrity check failed: no expected SHA-256 provided or found in manifest.")

        if actual_sha256 != target_sha256:
            raise ValueError(
                f"Integrity check failed for {model_path}: expected SHA-256 {target_sha256}, got {actual_sha256}"
            )

        return cls.load(model_path)


def build_model(
    config: Optional[Union[Dict[str, Any], XGBoostBaselineConfig, XGBoostBaselineProtocol]] = None
) -> XGBClassifier:
    """Return an XGBClassifier instance configured with project defaults or *config*.

    Parameters
    ----------
    config : dict or XGBoostBaselineConfig or XGBoostBaselineProtocol or None
        Hyperparameter overrides. If None, CANONICAL_BASELINE_PARAMS is used.

    Returns
    -------
    xgboost.XGBClassifier
        Untrained estimator.
    """
    if isinstance(config, XGBoostBaselineProtocol):
        params = config.model_config.get_xgb_params()
    elif isinstance(config, XGBoostBaselineConfig):
        params = config.get_xgb_params()
    elif isinstance(config, dict):
        cfg = copy.deepcopy(config)
        cfg.pop("is_canonical_baseline", None)
        cfg.pop("configuration_id", None)
        cfg.pop("model_type", None)
        cfg.pop("task", None)
        cfg.pop("target", None)
        cfg.pop("positive_class", None)
        params = cfg
    else:
        params = XGBoostBaselineConfig().get_xgb_params()

    params.setdefault("verbosity", 0)
    return XGBClassifier(**params)
