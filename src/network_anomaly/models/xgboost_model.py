"""XGBoost supervised model and baseline protocol integration (Issue #31 / C3).

Follows the identical shared supervised protocol and component structure as Random Forest:
  - XGBoostModel wrapper class providing fit(), predict(), predict_proba(), save(), load(), load_verified().
  - build_model() factory returning XGBClassifier for backward compatibility.
  - Strict 47-feature NetFlow v3 contract enforcement.
  - Fail-closed manifest verification with byte-for-byte SHA-256 integrity check.
"""

from __future__ import annotations

import copy
import dataclasses
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
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
)
from network_anomaly.data.split import _sha256_file
from network_anomaly.models.xgboost_protocol import (
    ALL_ATTACK_CATEGORIES,
    CANONICAL_BASELINE_PARAMS,
    DATASET_CSV_SHA256,
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


def _estimator_is_fitted(estimator: XGBClassifier) -> bool:
    """Determine whether the underlying XGBClassifier has been fitted."""
    try:
        booster = estimator.get_booster()
        return booster is not None
    except Exception:
        return False


def _config_from_dict(cfg_dict: Optional[Dict[str, Any]]) -> XGBoostBaselineConfig:
    """Reconstruct an XGBoostBaselineConfig from a serialized dictionary."""
    if not isinstance(cfg_dict, dict) or not cfg_dict:
        raise ValueError("Model artifact payload is missing a valid configuration dict")
    known_fields = {f.name for f in dataclasses.fields(XGBoostBaselineConfig)}
    unknown = set(cfg_dict) - known_fields
    filtered = {k: v for k, v in cfg_dict.items() if k in known_fields}
    if unknown:
        raise ValueError(
            f"Unknown configuration fields in model artifact payload: {sorted(unknown)}"
        )
    missing = known_fields - set(filtered)
    if missing:
        raise ValueError(
            f"Configuration payload missing required fields: {sorted(missing)}"
        )
    config = XGBoostBaselineConfig(**filtered)
    config.validate()
    return config


def _protocol_from_dict(proto_dict: Optional[Dict[str, Any]]) -> Optional[XGBoostBaselineProtocol]:
    """Reconstruct an XGBoostBaselineProtocol from a serialized dictionary (or None)."""
    if proto_dict is None:
        return None
    if not isinstance(proto_dict, dict):
        raise ValueError("Model artifact payload stores a malformed protocol entry")
    config = _config_from_dict(proto_dict.get("model_config", {}))
    protocol = XGBoostBaselineProtocol(
        protocol_version=proto_dict.get("protocol_version", PROTOCOL_IDENTIFIER),
        feature_contract_version=proto_dict.get(
            "feature_contract_version", FEATURE_CONTRACT_VERSION
        ),
        dataset_name=proto_dict.get("dataset_name", DATASET_NAME),
        dataset_csv_sha256=proto_dict.get("dataset_csv_sha256", DATASET_CSV_SHA256),
        model_config=config,
        selected_features=tuple(proto_dict.get("selected_features") or ()),
        excluded_metadata_features=tuple(
            proto_dict.get("excluded_metadata_features") or TRACE_METADATA_COLUMNS
        ),
        excluded_target_columns=tuple(proto_dict.get("excluded_target_columns") or TARGET_COLUMNS),
    )
    try:
        protocol.validate()
    except Exception as e:
        raise ValueError(f"Failed to deserialize model protocol from artifact payload: {e}")
    return protocol


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
        X_mat = self._to_x_matrix(X, "fit")
        y_arr = np.asarray(y)
        if y_arr.ndim != 1:
            raise ValueError(f"Target must be 1-dimensional, got shape {y_arr.shape}")
        if len(y_arr) != len(X_mat):
            raise ValueError(
                f"X/y row mismatch: X has {len(X_mat)} rows, y has {len(y_arr)}"
            )
        unique_labels = np.unique(y_arr)
        if not set(unique_labels).issubset({0, 1}):
            raise ValueError(f"Target Label contract violation: expected binary {0, 1}, got {unique_labels}")
        if X_mat.size and not np.isfinite(X_mat).all():
            raise ValueError("X contains non-finite values (NaN or Inf)")

        self.estimator.fit(X_mat, y_arr, **fit_params)
        self._is_fitted = True
        self._classes = getattr(self.estimator, "classes_", np.array([0, 1]))
        return self

    def _to_x_matrix(self, X: Any, operation: str) -> np.ndarray:
        """Validate and convert input to the canonical 47-feature matrix (dataclass'd)."""
        names = list(self.feature_names)
        if isinstance(X, pd.DataFrame):
            duplicate_cols = X.columns[X.columns.duplicated()].unique().tolist()
            if duplicate_cols:
                raise ValueError(
                    f"Duplicate columns in {operation} input: {duplicate_cols}"
                )
            missing_feats = [c for c in names if c not in X.columns]
            if missing_feats:
                raise ValueError(
                    f"Feature contract violation in {operation}: "
                    f"missing required features {missing_feats}"
                )
            selected = X[names]
            if selected.shape[1] != len(names) or selected.columns.duplicated().any():
                raise ValueError(
                    f"Feature contract violation in {operation}: duplicated feature "
                    "columns collapse the canonical 47-feature selection"
                )
            return selected.values
        X_mat = np.asarray(X)
        if X_mat.ndim != 2 or X_mat.shape[1] != len(names):
            raise ValueError(
                f"Feature dimension mismatch in {operation}: "
                f"expected {len(names)} features, got "
                f"{X_mat.shape[1] if X_mat.ndim == 2 else 'non-2d'}"
            )
        return X_mat

    def predict(self, X: Any) -> np.ndarray:
        """Predict binary anomaly labels (0 or 1)."""
        if not self._is_fitted:
            raise NotFittedError("XGBoostModel is not fitted yet. Call fit() before predict().")
        X_mat = self._to_x_matrix(X, "predict")
        return self.estimator.predict(X_mat)

    def predict_proba(self, X: Any) -> np.ndarray:
        """Predict class probabilities."""
        if not self._is_fitted:
            raise NotFittedError(
                "XGBoostModel is not fitted yet. Call fit() before predict_proba()."
            )
        X_mat = self._to_x_matrix(X, "predict_proba")
        return self.estimator.predict_proba(X_mat)

    def save(
        self,
        model_path: Union[str, Path],
        manifest_path: Optional[Union[str, Path]] = None,
        extra_manifest_fields: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Save fitted model artifact (payload dict) and return the file SHA-256.

        The artifact payload mirrors ``RandomForestModel.save`` so the verified
        inference pipeline can transparently consume XGBoost artifacts:
        a dictionary containing the estimator, configuration, protocol, feature
        names, fitted state, classes, and optional run metadata.
        A companion manifest can optionally be written with runtime provenance.
        """
        if not self._is_fitted:
            raise NotFittedError("Cannot save an unfitted XGBoostModel.")

        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "model_type": self.model_type,
            "task": self.task,
            "target": self.target,
            "positive_class": self.positive_class,
            "is_fitted": self._is_fitted,
            "config": self.config.to_dict(),
            "protocol": self.protocol.to_dict() if self.protocol is not None else None,
            "classes": (
                list(self.estimator.classes_) if hasattr(self.estimator, "classes_") else None
            ),
            "configuration_id": getattr(
                self.config, "configuration_id", "xgb-baseline-canonical-v1"
            ),
            "is_canonical_baseline": getattr(self.config, "is_canonical_baseline", True),
            "estimator": self.estimator,
            "feature_names": list(self.feature_names),
            "feature_contract_version": FEATURE_CONTRACT_VERSION,
            "metadata": metadata or {},
        }
        joblib.dump(payload, model_path, compress=3)
        artifact_sha256 = _sha256_file(model_path)

        if manifest_path is not None:
            manifest_data: Dict[str, Any] = {
                "model_type": self.model_type,
                "task": self.task,
                "target": self.target,
                "positive_class": self.positive_class,
                "feature_contract_version": FEATURE_CONTRACT_VERSION,
                "feature_names": list(self.feature_names),
                "num_features": len(self.feature_names),
                "configuration": self.config.to_dict(),
                "model_artifact_path": str(model_path.as_posix()),
                "model_artifact_sha256": artifact_sha256,
            }
            if extra_manifest_fields:
                manifest_data.update(extra_manifest_fields)
            manifest_path = Path(manifest_path)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2, ensure_ascii=False)

        return artifact_sha256

    @classmethod
    def load(cls, model_path: Union[str, Path]) -> "XGBoostModel":
        """Load a fitted XGBoostModel from a joblib artifact payload."""
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {model_path}")
        payload = joblib.load(model_path)
        if not isinstance(payload, dict) or "estimator" not in payload:
            raise ValueError(f"Invalid model artifact payload at {model_path}")

        config = _config_from_dict(payload.get("config", {}))
        protocol = _protocol_from_dict(payload.get("protocol"))
        if protocol is not None:
            instance = cls(protocol=protocol)
        else:
            instance = cls(config=config)
        instance.estimator = payload["estimator"]
        instance._is_fitted = bool(payload.get("is_fitted", True)) and _estimator_is_fitted(
            instance.estimator
        )
        if "feature_names" in payload:
            instance.feature_names = tuple(payload["feature_names"])
        instance._classes = getattr(instance.estimator, "classes_", np.array([0, 1]))
        return instance

    @classmethod
    def load_verified(
        cls,
        model_path: Union[str, Path],
        manifest_path: Optional[Union[str, Path]] = None,
        expected_sha256: Optional[str] = None,
        expected_dataset_sha256: Optional[str] = None,
        expected_split_manifest_sha256: Optional[str] = None,
        expected_preprocessor_artifact_sha256: Optional[str] = None,
    ) -> "XGBoostModel":
        """Load a fitted XGBoostModel and verify artifact integrity fail-closed.

        Verifies, in order, before deserialization:
        1. Companion manifest exists (when provided), is valid JSON and carries a
           well-formed 64-hex ``model_artifact_sha256``.
        2. Byte-for-byte SHA-256 of the artifact file matches the expected hash.
        3. After deserialization: model_type, feature contract (47 ML features,
           exact order) and configuration consistency between artifact payload
           and companion manifest.
        4. When matching expectation arguments are provided, also cross-checks
           dataset, split manifest, and preprocessor artifact SHA-256 values.
        """
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {model_path}")

        manifest_data: Optional[Dict[str, Any]] = None
        if manifest_path is not None:
            manifest_path = Path(manifest_path)
            if not manifest_path.exists():
                raise FileNotFoundError(f"Model manifest not found: {manifest_path}")
            try:
                with manifest_path.open("r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
            except Exception as e:
                raise ValueError(f"Malformed model manifest JSON at {manifest_path}: {e}")
            if not isinstance(manifest_data, dict):
                raise ValueError(
                    f"Model manifest must be a JSON object, got {type(manifest_data).__name__}"
                )

        def _validate_hex_sha256(val: Any, field_name: str) -> str:
            if (
                not val
                or not isinstance(val, str)
                or len(val) != 64
                or not all(c in "0123456789abcdefABCDEF" for c in val)
            ):
                raise ValueError(
                    f"Invalid or malformed 64-character hexadecimal SHA-256 "
                    f"for '{field_name}': {val!r}"
                )
            return val.lower()

        target_sha256: Optional[str] = None
        if manifest_path is not None:
            if "model_artifact_sha256" not in manifest_data:
                raise ValueError(
                    f"Missing required field 'model_artifact_sha256' in manifest: {manifest_path}"
                )
            target_sha256 = _validate_hex_sha256(
                manifest_data["model_artifact_sha256"], "model_artifact_sha256"
            )
        elif expected_sha256 is not None:
            target_sha256 = _validate_hex_sha256(expected_sha256, "expected_sha256")

        if target_sha256 is None:
            raise ValueError(
                "Integrity check failed: no expected SHA-256 provided or found in manifest."
            )

        actual_sha256 = _sha256_file(model_path)
        if actual_sha256 != target_sha256:
            raise ValueError(
                f"Integrity check failed for {model_path}: "
                f"expected SHA-256 {target_sha256}, got {actual_sha256}"
            )

        instance = cls.load(model_path)

        if manifest_path is not None:
            if manifest_data.get("feature_contract_version") not in (None, FEATURE_CONTRACT_VERSION):
                raise ValueError(
                    f"Feature contract mismatch: manifest declares "
                    f"'{manifest_data.get('feature_contract_version')}', "
                    f"expected '{FEATURE_CONTRACT_VERSION}'"
                )
            manifest_features = manifest_data.get("feature_names") or manifest_data.get(
                "selected_features"
            )
            if manifest_features is not None:
                if list(manifest_features) != list(instance.feature_names):
                    raise ValueError(
                        "Feature contract mismatch: manifest feature list/order differs "
                        "from the restored model feature contract."
                    )
            for expected_field, expected_value in (
                ("dataset_sha256", expected_dataset_sha256),
                ("split_manifest_sha256", expected_split_manifest_sha256),
                ("preprocessor_artifact_sha256", expected_preprocessor_artifact_sha256),
            ):
                if expected_value is None:
                    continue
                manifest_value = manifest_data.get(expected_field)
                if not manifest_value or str(manifest_value).lower() != str(expected_value).lower():
                    raise ValueError(
                        f"Provenance verification mismatch for '{expected_field}': "
                        f"manifest declares {manifest_value!r}, "
                        f"expected {expected_value!r}"
                    )
            manifest_model_type = manifest_data.get("model_type")
            if manifest_model_type not in (None, instance.model_type):
                raise ValueError(
                    f"Model type mismatch: manifest declares '{manifest_model_type}', "
                    f"expected '{instance.model_type}'"
                )
            manifest_config = manifest_data.get("configuration") or manifest_data.get("config")
            if isinstance(manifest_config, dict) and manifest_config:
                restored_params = instance.config.get_xgb_params()
                for key, canon in manifest_config.items():
                    if key in restored_params and restored_params[key] != canon:
                        raise ValueError(
                            f"Configuration mismatch for '{key}': "
                            f"manifest declares {canon!r}, restored model has "
                            f"{restored_params[key]!r}"
                        )

        if not instance._is_fitted:
            raise ValueError(
                f"Restored XGBoostModel at {model_path} is not in a fitted state; "
                "artifact integrity check succeeded but model state is invalid."
            )
        return instance


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
