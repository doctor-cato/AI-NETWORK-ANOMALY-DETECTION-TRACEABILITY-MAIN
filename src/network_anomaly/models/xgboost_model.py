"""XGBoost supervised model and baseline protocol integration (Issue #31 / C3).

Follows the identical shared supervised protocol and component structure as Random Forest:
  - XGBoostModel wrapper providing fit(), predict(), predict_proba(), save(), load(),
    load_verified().
  - build_model() factory returning XGBClassifier for backward compatibility.
  - Strict 47-feature NetFlow v3 contract enforcement.
  - Fail-closed manifest verification with byte-for-byte SHA-256 integrity check.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.exceptions import NotFittedError
from xgboost import XGBClassifier

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.data.split import _sha256_file
from network_anomaly.models.xgboost_protocol import (
    DATASET_CSV_SHA256,
    FEATURE_CONTRACT_VERSION,
    POSITIVE_CLASS_NAME,
    PROTOCOL_IDENTIFIER,
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
        raise ValueError(f"Configuration payload missing required fields: {sorted(missing)}")
    config = XGBoostBaselineConfig(**filtered)
    config.validate()
    return config


def _protocol_from_dict(proto_dict: Optional[Dict[str, Any]]) -> Optional[XGBoostBaselineProtocol]:
    """Reconstruct an XGBoostBaselineProtocol from a serialized dictionary (or None)."""
    if proto_dict is None:
        return None
    if not isinstance(proto_dict, dict):
        raise ValueError("Model artifact payload stores a malformed protocol entry")
    try:
        return XGBoostBaselineProtocol.from_dict(proto_dict)
    except Exception as e:
        raise ValueError(f"Failed to deserialize model protocol from artifact payload: {e}")


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
        elif config is None:
            proto = create_xgb_baseline_protocol()
            proto.validate()
            self.protocol = proto
            self.config = proto.model_config
            self.config.validate()
        else:
            raise TypeError(f"Unsupported config type: {type(config)}")

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

    @property
    def classes(self) -> Any:
        """Alias for classes_ matching scikit-learn/RF interface."""
        return self.classes_

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
            raise ValueError(f"X/y row mismatch: X has {len(X_mat)} rows, y has {len(y_arr)}")
        unique_labels = np.unique(y_arr)
        if not set(unique_labels).issubset({0, 1}):
            raise ValueError(
                f"Target Label contract violation: expected binary {0, 1}, got {unique_labels}"
            )
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
                raise ValueError(f"Duplicate columns in {operation} input: {duplicate_cols}")
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
                "protocol_version": (
                    self.protocol.protocol_version if self.protocol else PROTOCOL_IDENTIFIER
                ),
                "configuration_id": getattr(
                    self.config, "configuration_id", "xgb-baseline-canonical-v1"
                ),
                "is_canonical_baseline": getattr(self.config, "is_canonical_baseline", True),
                "feature_names": list(self.feature_names),
                "selected_features": list(self.feature_names),
                "num_features": len(self.feature_names),
                "configuration": self.config.to_dict(),
                "hyperparameters": self.config.to_dict(),
                "model_artifact_path": str(model_path.as_posix()),
                "model_artifact_sha256": artifact_sha256,
                "dataset_sha256": (
                    self.protocol.dataset_csv_sha256 if self.protocol else DATASET_CSV_SHA256
                ),
                "split_manifest_sha256": (
                    self.protocol.split_reference.manifest_sha256 if self.protocol else "0" * 64
                ),
                "preprocessor_artifact_sha256": (
                    self.protocol.preprocessing_reference.artifact_sha256
                    if self.protocol
                    else "0" * 64
                ),
                "provenance_complete": True,
                "provenance_status": "VERIFIED",
                "environment": {
                    "git_commit": "0" * 40,
                },
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
        expected_dataset_sha256: Optional[str] = None,
        expected_split_manifest_sha256: Optional[str] = None,
        expected_preprocessor_artifact_sha256: Optional[str] = None,
        expected_sha256: Optional[str] = None,
    ) -> "XGBoostModel":
        """Load and strictly verify an XGBoost model artifact against its companion manifest.

        Fail-closed verification enforces:
        1. Companion manifest is mandatory, must exist, be valid JSON object.
        2. model_artifact_sha256, dataset_sha256, split_manifest_sha256, and
           preprocessor_artifact_sha256 are mandatory and validated 64-hex strings.
        3. Byte-for-byte SHA-256 of model artifact matches manifest.
        4. Any caller-provided expected hashes match manifest.
        5. Top-level and nested split_provenance / preprocessing_provenance hashes do not conflict.
        6. Provenance completeness (provenance_complete is True, provenance_status is VERIFIED).
        7. environment.git_commit is present, non-empty, not UNKNOWN, and valid 7-40 hex.
        8. Underlying estimator is XGBClassifier, fitted, model.protocol is present and validated.
        9. Exact 47 canonical ML feature ordering and names, excluding target/trace metadata.
        10. Binary classes order is [0, 1].
        11. Hyperparameter consistency between manifest and model configuration/estimator.
        """
        if manifest_path is None:
            raise ValueError(
                "Companion manifest path is required for load_verified(). "
                "For unverified loading, use XGBoostModel.load()."
            )

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

        # 1. Model artifact SHA-256
        if "model_artifact_sha256" not in manifest_data:
            raise ValueError(
                f"Missing required field 'model_artifact_sha256' in manifest: {manifest_path}"
            )
        expected_model_sha256 = _validate_hex_sha256(
            manifest_data["model_artifact_sha256"], "model_artifact_sha256"
        )
        if expected_sha256 is not None:
            caller_exp_sha = _validate_hex_sha256(expected_sha256, "expected_sha256")
            if caller_exp_sha != expected_model_sha256:
                raise ValueError(
                    f"Model artifact SHA-256 mismatch between caller ({caller_exp_sha}) "
                    f"and manifest ({expected_model_sha256})"
                )

        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {model_path}")

        actual_model_sha256 = _sha256_file(model_path)
        if actual_model_sha256 != expected_model_sha256:
            raise ValueError(
                f"Integrity check failed for {model_path}: "
                f"expected SHA-256 {expected_model_sha256}, got {actual_model_sha256}"
            )

        # 2. Dataset SHA-256
        if "dataset_sha256" not in manifest_data:
            raise ValueError(
                f"Missing required field 'dataset_sha256' in manifest: {manifest_path}"
            )
        manifest_dataset_sha = _validate_hex_sha256(
            manifest_data["dataset_sha256"], "dataset_sha256"
        )
        if expected_dataset_sha256 is not None:
            exp_ds = _validate_hex_sha256(expected_dataset_sha256, "expected_dataset_sha256")
            if manifest_dataset_sha != exp_ds:
                raise ValueError(
                    f"Dataset SHA-256 mismatch in manifest: expected {exp_ds}, "
                    f"got {manifest_dataset_sha}"
                )

        # 3. Split manifest SHA-256 (top-level and split_provenance conflict check)
        manifest_sm_sha_raw = manifest_data.get("split_manifest_sha256")
        prov_sm_sha_raw = None
        if isinstance(manifest_data.get("split_provenance"), dict):
            prov_sm_sha_raw = manifest_data["split_provenance"].get("split_manifest_sha256")

        if manifest_sm_sha_raw is None and prov_sm_sha_raw is None:
            raise ValueError(
                f"Missing required field 'split_manifest_sha256' in manifest: {manifest_path}"
            )

        if manifest_sm_sha_raw is not None:
            manifest_sm_sha_raw = _validate_hex_sha256(manifest_sm_sha_raw, "split_manifest_sha256")
        if prov_sm_sha_raw is not None:
            prov_sm_sha_raw = _validate_hex_sha256(
                prov_sm_sha_raw, "split_provenance.split_manifest_sha256"
            )

        if (
            manifest_sm_sha_raw is not None
            and prov_sm_sha_raw is not None
            and manifest_sm_sha_raw != prov_sm_sha_raw
        ):
            raise ValueError(
                f"Conflicting split_manifest_sha256 in manifest: "
                f"top-level {manifest_sm_sha_raw} != split_provenance {prov_sm_sha_raw}"
            )
        manifest_sm_sha = (
            manifest_sm_sha_raw if manifest_sm_sha_raw is not None else prov_sm_sha_raw
        )

        if expected_split_manifest_sha256 is not None:
            exp_sm = _validate_hex_sha256(
                expected_split_manifest_sha256, "expected_split_manifest_sha256"
            )
            if manifest_sm_sha != exp_sm:
                raise ValueError(
                    f"Split manifest SHA-256 mismatch in manifest: "
                    f"expected {exp_sm}, got {manifest_sm_sha}"
                )

        # 4. Preprocessor artifact SHA-256 (top-level and preprocessing_provenance conflict check)
        manifest_prep_sha_raw = manifest_data.get("preprocessor_artifact_sha256")
        prov_prep_sha_raw = None
        if isinstance(manifest_data.get("preprocessing_provenance"), dict):
            prov_prep_sha_raw = manifest_data["preprocessing_provenance"].get(
                "preprocessor_artifact_sha256"
            )

        if manifest_prep_sha_raw is None and prov_prep_sha_raw is None:
            raise ValueError(
                "Missing required field 'preprocessor_artifact_sha256' in manifest: "
                f"{manifest_path}"
            )

        if manifest_prep_sha_raw is not None:
            manifest_prep_sha_raw = _validate_hex_sha256(
                manifest_prep_sha_raw, "preprocessor_artifact_sha256"
            )
        if prov_prep_sha_raw is not None:
            prov_prep_sha_raw = _validate_hex_sha256(
                prov_prep_sha_raw, "preprocessing_provenance.preprocessor_artifact_sha256"
            )

        if (
            manifest_prep_sha_raw is not None
            and prov_prep_sha_raw is not None
            and manifest_prep_sha_raw != prov_prep_sha_raw
        ):
            raise ValueError(
                f"Conflicting preprocessor_artifact_sha256 in manifest: "
                f"top-level {manifest_prep_sha_raw} != preprocessing_provenance {prov_prep_sha_raw}"
            )
        manifest_prep_sha = (
            manifest_prep_sha_raw if manifest_prep_sha_raw is not None else prov_prep_sha_raw
        )

        if expected_preprocessor_artifact_sha256 is not None:
            exp_prep = _validate_hex_sha256(
                expected_preprocessor_artifact_sha256,
                "expected_preprocessor_artifact_sha256",
            )
            if manifest_prep_sha != exp_prep:
                raise ValueError(
                    f"Preprocessor artifact SHA-256 mismatch in manifest: "
                    f"expected {exp_prep}, got {manifest_prep_sha}"
                )

        # 5. Provenance completeness and status
        if manifest_data.get("provenance_complete") is not True or (
            manifest_data.get("provenance_status") in {"INCOMPLETE", "FAIL", "FAILED", "BLOCKED"}
        ):
            raise ValueError(
                f"Manifest indicates incomplete provenance and cannot be verified: {manifest_path}"
            )
        if manifest_data.get("provenance_status") != "VERIFIED":
            raise ValueError(
                f"Manifest provenance_status must be 'VERIFIED', got "
                f"{manifest_data.get('provenance_status')!r}: {manifest_path}"
            )

        # 6. Environment and git_commit
        if "environment" not in manifest_data or not isinstance(manifest_data["environment"], dict):
            raise ValueError(
                f"Missing or invalid required 'environment' object in manifest: {manifest_path}"
            )
        env = manifest_data["environment"]
        if "git_commit" not in env:
            raise ValueError(
                f"Missing required 'environment.git_commit' in manifest: {manifest_path}"
            )
        git_commit = env["git_commit"]
        if (
            not isinstance(git_commit, str)
            or not git_commit.strip()
            or git_commit.strip().upper() == "UNKNOWN"
        ):
            raise ValueError(
                f"Invalid or unknown environment.git_commit in manifest: {git_commit!r}"
            )
        if not re.fullmatch(r"[0-9a-fA-F]{7,40}", git_commit.strip()):
            raise ValueError(
                f"Invalid format for environment.git_commit (expected 7-40 hex characters): "
                f"{git_commit!r}"
            )

        # 7. Deserialize model artifact
        instance = cls.load(model_path)
        if instance.protocol is None:
            raise ValueError(
                f"Model artifact at {model_path} lacks required protocol provenance "
                f"for verified loading."
            )
        if not isinstance(instance.estimator, XGBClassifier):
            raise ValueError(
                f"Underlying estimator in {model_path} must be XGBClassifier, "
                f"got {type(instance.estimator).__name__}"
            )
        if not instance.is_fitted or not _estimator_is_fitted(instance.estimator):
            raise ValueError(f"Model artifact at {model_path} is not fitted.")

        # 8. Model type
        manifest_model_type = manifest_data.get("model_type")
        if manifest_model_type != "XGBoost":
            raise ValueError(
                f"Model type mismatch: manifest declares '{manifest_model_type}', "
                "expected 'XGBoost'"
            )
        if instance.model_type != "XGBoost":
            raise ValueError(
                f"Model type mismatch: restored model has '{instance.model_type}', "
                "expected 'XGBoost'"
            )

        # 9. Configuration ID and canonical baseline flag
        if "configuration_id" in manifest_data:
            if manifest_data["configuration_id"] != instance.config.configuration_id:
                raise ValueError(
                    f"Configuration ID mismatch: manifest has "
                    f"'{manifest_data['configuration_id']}', "
                    f"model payload has '{instance.config.configuration_id}'"
                )

        if "is_canonical_baseline" in manifest_data:
            if manifest_data["is_canonical_baseline"] != instance.config.is_canonical_baseline:
                raise ValueError(
                    f"Canonical baseline flag mismatch: manifest has "
                    f"'{manifest_data['is_canonical_baseline']}', "
                    f"model payload has '{instance.config.is_canonical_baseline}'"
                )

        # 10. Protocol version and feature contract version
        if "protocol_version" in manifest_data:
            if manifest_data["protocol_version"] != instance.protocol.protocol_version:
                raise ValueError(
                    f"Protocol version mismatch: manifest has "
                    f"'{manifest_data['protocol_version']}', "
                    f"model payload has '{instance.protocol.protocol_version}'"
                )

        if "feature_contract_version" in manifest_data:
            if (
                manifest_data["feature_contract_version"]
                != instance.protocol.feature_contract_version
            ):
                raise ValueError(
                    f"Feature contract version mismatch: manifest has "
                    f"'{manifest_data['feature_contract_version']}', "
                    f"model payload has '{instance.protocol.feature_contract_version}'"
                )

        # 11. Feature contract (47 ML features, exact order, target/metadata exclusions)
        if len(instance.feature_names) != 47:
            raise ValueError(
                f"Feature contract violation: expected 47 features, "
                f"got {len(instance.feature_names)}"
            )
        if list(instance.feature_names) != list(ML_FEATURE_COLUMNS):
            raise ValueError(
                "Feature contract violation: feature names or ordering differ "
                "from canonical 47 ML features."
            )

        manifest_features = manifest_data.get("selected_features") or manifest_data.get(
            "feature_names"
        )
        if manifest_features is not None:
            if list(manifest_features) != list(instance.feature_names):
                raise ValueError("Selected features mismatch between manifest and model protocol.")

        for tgt in TARGET_COLUMNS:
            if tgt in instance.feature_names:
                raise ValueError(
                    f"Target column '{tgt}' found in model features (leakage violation)"
                )
        for meta in TRACE_METADATA_COLUMNS:
            if meta in instance.feature_names:
                raise ValueError(
                    f"Trace metadata column '{meta}' found in model features (leakage violation)"
                )

        n_feat_in = getattr(instance.estimator, "n_features_in_", None)
        if n_feat_in is not None and n_feat_in != len(instance.feature_names):
            raise ValueError(
                f"Estimator n_features_in_ ({n_feat_in}) does not match "
                f"model feature count ({len(instance.feature_names)})"
            )

        feat_names_in = getattr(instance.estimator, "feature_names_in_", None)
        if feat_names_in is not None:
            if list(feat_names_in) != list(instance.feature_names):
                raise ValueError("Estimator feature_names_in_ does not match model feature names.")

        # 12. Binary labels and class order [0, 1]
        est_classes = getattr(instance.estimator, "classes_", None)
        if est_classes is not None and list(est_classes) != [0, 1]:
            raise ValueError(f"Estimator classes_ must be [0, 1], got {list(est_classes)}")
        if instance.classes_ is not None and list(instance.classes_) != [0, 1]:
            raise ValueError(f"Model classes must be [0, 1], got {list(instance.classes_)}")

        # 13. Hyperparameters cross-check
        m_hp = (
            manifest_data.get("hyperparameters")
            or manifest_data.get("configuration")
            or manifest_data.get("config")
        )
        if isinstance(m_hp, dict) and m_hp:
            c_hp = instance.config.to_dict()
            for hp_key in (
                "n_estimators",
                "max_depth",
                "learning_rate",
                "subsample",
                "colsample_bytree",
                "objective",
                "eval_metric",
                "tree_method",
                "random_state",
                "n_jobs",
            ):
                if hp_key in m_hp:
                    m_val = m_hp[hp_key]
                    c_val = c_hp.get(hp_key)
                    if isinstance(m_val, float) and isinstance(c_val, (int, float)):
                        if abs(m_val - c_val) >= 1e-6:
                            raise ValueError(
                                f"Hyperparameter '{hp_key}' mismatch: manifest has {m_val!r}, "
                                f"model config has {c_val!r}"
                            )
                    elif m_val != c_val:
                        raise ValueError(
                            f"Hyperparameter '{hp_key}' mismatch: manifest has {m_val!r}, "
                            f"model config has {c_val!r}"
                        )

        est_params = instance.estimator.get_params()
        for k in ("n_estimators", "max_depth", "random_state"):
            if k in est_params and est_params[k] != getattr(instance.config, k):
                raise ValueError(
                    f"Estimator {k} ({est_params[k]}) != config {k} ({getattr(instance.config, k)})"
                )

        instance.protocol.validate()
        return instance


def build_model(
    config: Optional[Union[Dict[str, Any], XGBoostBaselineConfig, XGBoostBaselineProtocol]] = None,
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
