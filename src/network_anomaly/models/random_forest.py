"""Random Forest supervised model and baseline protocol integration."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, Union

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import NotFittedError

from network_anomaly.config import RANDOM_FOREST_DEFAULTS
from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
)
from network_anomaly.models.random_forest_protocol import (
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
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if protocol is not None:
            if not isinstance(protocol, RandomForestBaselineProtocol):
                raise TypeError(
                    f"Unsupported protocol type: {type(protocol)}, "
                    f"expected RandomForestBaselineProtocol"
                )
            protocol.validate()
            if config is not None:
                if isinstance(config, RandomForestBaselineProtocol):
                    config.validate()
                    if config.to_dict() != protocol.to_dict():
                        raise ValueError(
                            "Provided config protocol conflicts with explicit protocol argument."
                        )
                elif isinstance(config, RandomForestBaselineConfig):
                    config.validate()
                    if config.to_dict() != protocol.model_config.to_dict():
                        raise ValueError(
                            "Provided RandomForestBaselineConfig conflicts with "
                            "protocol.model_config."
                        )
                elif isinstance(config, dict):
                    parsed_cfg = RandomForestBaselineConfig.from_dict(config)
                    if parsed_cfg.to_dict() != protocol.model_config.to_dict():
                        raise ValueError(
                            "Provided config dictionary conflicts with protocol.model_config."
                        )
                else:
                    raise TypeError(f"Unsupported config type: {type(config)}")
            self.protocol: Optional[RandomForestBaselineProtocol] = protocol
            self.config: RandomForestBaselineConfig = protocol.model_config
            self.config.validate()
        elif isinstance(config, RandomForestBaselineProtocol):
            config.validate()
            self.protocol = config
            self.config = config.model_config
            self.config.validate()
        elif isinstance(config, RandomForestBaselineConfig):
            config.validate()
            self.protocol = None
            self.config = config
        elif isinstance(config, dict):
            self.protocol = None
            self.config = RandomForestBaselineConfig.from_dict(config)
        elif config is None:
            proto = create_rf_baseline_protocol()
            proto.validate()
            self.protocol = proto
            self.config = proto.model_config
            self.config.validate()
        else:
            raise TypeError(f"Unsupported config type: {type(config)}")

        if metadata is not None and not isinstance(metadata, dict):
            raise TypeError(f"metadata must be a dict or None, got {type(metadata).__name__}")
        self.metadata: Dict[str, Any] = dict(metadata) if metadata is not None else {}

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
        self.config.validate()
        if self.protocol is not None:
            self.protocol.validate()
        return RandomForestClassifier(**self.config.to_sklearn_params())

    @property
    def estimator(self) -> RandomForestClassifier:
        """Access the underlying scikit-learn estimator instance."""
        return self._estimator

    @property
    def is_fitted(self) -> bool:
        """Indicate whether the model has been fitted with real training data."""
        return self._is_fitted

    @property
    def classes_(self) -> Any:
        """Class labels known to the classifier."""
        return getattr(self._estimator, "classes_", None)

    def _validate_feature_input(self, X: Any) -> int:
        """Validate feature matrix schema, dimensions, and finite numeric values."""
        if X is None or isinstance(X, (str, bytes, dict)):
            raise ValueError(f"Expected 2D feature matrix X, got {type(X).__name__}")

        expected_width = len(self.feature_names)

        if hasattr(X, "columns"):
            cols = list(X.columns)
            if len(cols) != len(set(cols)):
                raise ValueError("feature selection contains duplicate columns")
            forbidden = sorted(set(cols) & set(TRACE_METADATA_COLUMNS + TARGET_COLUMNS))
            if forbidden:
                raise ValueError(f"feature selection contains forbidden columns: {forbidden}")
            if self.config.is_canonical_baseline:
                validate_feature_selection(cols, require_complete=True)
            if tuple(cols) != tuple(self.feature_names):
                raise ValueError(
                    f"Input DataFrame columns {cols} do not match model feature names "
                    f"{list(self.feature_names)}"
                )
            n_samples = len(X)
            if n_samples == 0:
                raise ValueError("Feature matrix X must not be empty (0 rows).")
            try:
                numeric_arr = np.asarray(X, dtype=np.float64)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Feature matrix X contains non-numeric values that cannot be cast to float: "
                    f"{exc}"
                ) from exc
            if not np.isfinite(numeric_arr).all():
                raise ValueError("Feature matrix X contains NaN or infinite values.")
            return n_samples

        # Array-like / sequence input
        try:
            raw_arr = np.asarray(X)
        except Exception as exc:
            raise ValueError(f"Cannot convert feature input X to array: {exc}") from exc

        if raw_arr.ndim != 2:
            raise ValueError(f"Expected 2D feature matrix X, got array with ndim={raw_arr.ndim}")
        if raw_arr.shape[0] == 0:
            raise ValueError("Feature matrix X must not be empty (0 rows).")
        if raw_arr.shape[1] != expected_width:
            raise ValueError(
                f"Expected {expected_width} feature columns, "
                f"got matrix with {raw_arr.shape[1]} columns"
            )
        if raw_arr.dtype == bool or np.issubdtype(raw_arr.dtype, np.bool_):
            raise ValueError("Feature matrix X cannot have boolean dtype.")

        try:
            numeric_arr = np.asarray(raw_arr, dtype=np.float64)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"Feature matrix X contains non-numeric values that cannot be cast to float: {exc}"
            ) from exc
        if not np.isfinite(numeric_arr).all():
            raise ValueError("Feature matrix X contains NaN or infinite values.")
        return int(raw_arr.shape[0])

    def _validate_target_input(self, y: Any, expected_samples: int) -> None:
        """Validate target label vector y for binary classification."""
        if y is None or isinstance(y, (str, bytes, dict)):
            raise ValueError(f"Invalid target vector y: {type(y).__name__}")
        try:
            y_arr = np.asarray(y, dtype=object)
        except Exception as exc:
            raise ValueError(f"Cannot convert target y to 1D array: {exc}") from exc

        if y_arr.ndim != 1:
            raise ValueError(f"Expected 1D target vector y, got array with ndim={y_arr.ndim}")
        if len(y_arr) == 0:
            raise ValueError("Target vector y must not be empty.")
        if len(y_arr) != expected_samples:
            raise ValueError(
                f"Target vector y length ({len(y_arr)}) does not match "
                f"feature matrix X row count ({expected_samples})."
            )

        valid_str_labels = {
            "0",
            "1",
            "benign",
            "normal",
            "attack",
            "anomaly",
            NEGATIVE_CLASS_NAME.lower(),
            POSITIVE_CLASS_NAME.lower(),
        }
        for idx, val in enumerate(y_arr):
            if val is None or isinstance(val, (bool, np.bool_)):
                raise ValueError(
                    f"Invalid target label at index {idx}: {val!r} (booleans/None not allowed)"
                )
            if isinstance(val, (int, np.integer)):
                if int(val) not in (NEGATIVE_CLASS_LABEL, POSITIVE_CLASS_LABEL):
                    raise ValueError(
                        f"Invalid numeric target label at index {idx}: {val!r}; "
                        f"expected {NEGATIVE_CLASS_LABEL} or {POSITIVE_CLASS_LABEL}"
                    )
            elif isinstance(val, (float, np.floating)):
                if not np.isfinite(val) or float(val) not in (
                    float(NEGATIVE_CLASS_LABEL),
                    float(POSITIVE_CLASS_LABEL),
                ):
                    raise ValueError(
                        f"Invalid float target label at index {idx}: {val!r}; "
                        f"expected {NEGATIVE_CLASS_LABEL} or {POSITIVE_CLASS_LABEL}"
                    )
            elif isinstance(val, str):
                if val.strip().lower() not in valid_str_labels:
                    raise ValueError(f"Invalid string target label at index {idx}: {val!r}")
            else:
                raise ValueError(f"Unsupported target label type at index {idx}: {type(val)}")

    def fit(self, X: Any, y: Any, **fit_params: Any) -> "RandomForestModel":
        """Fit interface on verified NF-UNSW-NB15-v3 feature data."""
        n_samples = self._validate_feature_input(X)
        self._validate_target_input(y, expected_samples=n_samples)

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
        self._validate_feature_input(X)
        return self._estimator.predict(X)

    def predict_proba(self, X: Any) -> Any:
        """Predict class probabilities for anomaly detection."""
        if not self._is_fitted:
            raise NotFittedError(
                "This RandomForestModel instance is not fitted yet. "
                "Call 'fit' with verified NF-UNSW-NB15-v3 training data "
                "before using 'predict_proba'."
            )
        self._validate_feature_input(X)
        return self._estimator.predict_proba(X)

    def save(
        self,
        path: Union[str, Path],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Save fitted model artifact using joblib and return file SHA-256."""
        if not self._is_fitted:
            raise NotFittedError("Cannot save an unfitted RandomForestModel.")
        if metadata is not None and not isinstance(metadata, dict):
            raise TypeError(f"metadata must be a dict or None, got {type(metadata).__name__}")
        merged_metadata: Dict[str, Any] = dict(self.metadata)
        if metadata:
            merged_metadata.update(metadata)
        self.metadata = dict(merged_metadata)

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model_type": self.model_type,
            "task": self.task,
            "target": self.target,
            "positive_class": self.positive_class,
            "is_fitted": self._is_fitted,
            "config": self.config.to_dict(),
            "protocol": self.protocol.to_dict() if self.protocol is not None else None,
            "classes": (
                list(self._estimator.classes_) if hasattr(self._estimator, "classes_") else None
            ),
            "configuration_id": getattr(
                self.config, "configuration_id", "rf-baseline-canonical-v1"
            ),
            "is_canonical_baseline": getattr(self.config, "is_canonical_baseline", True),
            "estimator": self._estimator,
            "feature_names": list(self.feature_names),
            "metadata": merged_metadata,
        }
        joblib.dump(payload, p, compress=3)
        return _sha256_file(p)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "RandomForestModel":
        """Load a fitted RandomForestModel from a joblib artifact."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Model artifact not found: {path}")
        payload = joblib.load(p)
        if not isinstance(payload, dict) or "estimator" not in payload:
            raise ValueError(f"Invalid model artifact payload at {path}")
        config_dict = payload.get("config", {})
        config = RandomForestBaselineConfig.from_dict(config_dict)
        protocol = None
        if "protocol" in payload and payload["protocol"] is not None:
            try:
                protocol = RandomForestBaselineProtocol.from_dict(payload["protocol"])
            except Exception as e:
                raise ValueError(
                    f"Failed to deserialize model protocol from artifact payload at {path}: {e}"
                ) from e
        raw_metadata = payload.get("metadata")
        loaded_metadata = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
        model = cls(config=config, protocol=protocol, metadata=loaded_metadata)
        model._estimator = payload["estimator"]
        is_fitted_flag = payload.get("is_fitted", True)
        est = payload["estimator"]
        has_estimators = hasattr(est, "estimators_") and len(getattr(est, "estimators_", [])) > 0
        model._is_fitted = bool(is_fitted_flag and has_estimators)
        if "feature_names" in payload:
            model.feature_names = tuple(payload["feature_names"])
        return model

    @classmethod
    def load_verified(
        cls,
        model_path: Union[str, Path],
        manifest_path: Union[str, Path],
        expected_dataset_sha256: Optional[str] = None,
        expected_split_manifest_sha256: Optional[str] = None,
        expected_preprocessor_artifact_sha256: Optional[str] = None,
    ) -> "RandomForestModel":
        """Load and strictly verify a Random Forest model artifact against its manifest."""
        m_path = Path(manifest_path)
        if not m_path.exists():
            raise FileNotFoundError(f"Model manifest not found: {manifest_path}")
        try:
            with m_path.open("r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception as e:
            raise ValueError(f"Malformed model manifest JSON at {manifest_path}: {e}")

        if not isinstance(manifest, dict):
            raise ValueError(f"Model manifest must be a JSON object, got {type(manifest).__name__}")

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
        if "model_artifact_sha256" not in manifest:
            raise ValueError(
                f"Missing required field 'model_artifact_sha256' in manifest: {manifest_path}"
            )
        expected_model_sha256 = _validate_hex_sha256(
            manifest["model_artifact_sha256"], "model_artifact_sha256"
        )

        # 2. Dataset SHA-256
        if "dataset_sha256" not in manifest:
            raise ValueError(
                f"Missing required field 'dataset_sha256' in manifest: {manifest_path}"
            )
        manifest_dataset_sha = _validate_hex_sha256(manifest["dataset_sha256"], "dataset_sha256")

        # 3. Split manifest SHA-256 (top-level canonical, with cross-check against split_provenance)
        manifest_sm_sha_raw = manifest.get("split_manifest_sha256")
        prov_sm_sha_raw = None
        if isinstance(manifest.get("split_provenance"), dict):
            prov_sm_sha_raw = manifest["split_provenance"].get("split_manifest_sha256")

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

        # Check model file existence and hash
        mod_path = Path(model_path)
        if not mod_path.exists():
            raise FileNotFoundError(f"Model artifact not found: {model_path}")
        actual_model_sha256 = _sha256_file(mod_path)
        if actual_model_sha256 != expected_model_sha256:
            raise ValueError(
                f"Model artifact SHA-256 mismatch: "
                f"expected {expected_model_sha256}, got {actual_model_sha256}"
            )

        if expected_dataset_sha256 is not None:
            exp_ds = _validate_hex_sha256(expected_dataset_sha256, "expected_dataset_sha256")
            if manifest_dataset_sha != exp_ds:
                raise ValueError(
                    f"Dataset SHA-256 mismatch in manifest: "
                    f"expected {exp_ds}, got {manifest_dataset_sha}"
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

        manifest_prep_sha_raw = manifest.get("preprocessor_artifact_sha256")
        prov_prep_sha_raw = None
        if isinstance(manifest.get("preprocessing_provenance"), dict):
            prov_prep_sha_raw = manifest["preprocessing_provenance"].get(
                "preprocessor_artifact_sha256"
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

        clean_man_prep = (
            manifest_prep_sha_raw if manifest_prep_sha_raw is not None else prov_prep_sha_raw
        )

        if expected_preprocessor_artifact_sha256 is not None:
            exp_prep = _validate_hex_sha256(
                expected_preprocessor_artifact_sha256,
                "expected_preprocessor_artifact_sha256",
            )
            if clean_man_prep is None:
                raise ValueError(
                    f"Missing required field 'preprocessor_artifact_sha256' "
                    f"in manifest: {manifest_path}"
                )
            if clean_man_prep != exp_prep:
                raise ValueError(
                    f"Preprocessor artifact SHA-256 mismatch in manifest: "
                    f"expected {exp_prep}, got {clean_man_prep}"
                )

        # Provenance completeness and environment.git_commit integrity checks
        if manifest.get("provenance_complete") is False or (
            manifest.get("provenance_status") in {"INCOMPLETE", "FAIL", "FAILED", "BLOCKED"}
        ):
            raise ValueError(
                f"Manifest indicates incomplete provenance and cannot be verified: {manifest_path}"
            )
        if "environment" not in manifest or not isinstance(manifest["environment"], dict):
            raise ValueError(
                f"Missing or invalid required 'environment' object in manifest: {manifest_path}"
            )
        env = manifest["environment"]
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

        model = cls.load(model_path)
        if model.protocol is None:
            raise ValueError(
                f"Model artifact at {model_path} lacks required protocol provenance "
                f"for verified loading."
            )
        if not model.is_fitted:
            raise ValueError(f"Model artifact at {model_path} is not fitted.")
        if not isinstance(model.estimator, RandomForestClassifier):
            raise ValueError(
                f"Underlying estimator in {model_path} must be RandomForestClassifier, "
                f"got {type(model.estimator).__name__}"
            )

        # Cross-check protocol and configuration between model payload and manifest
        if "protocol_version" in manifest:
            if manifest["protocol_version"] != model.protocol.protocol_version:
                raise ValueError(
                    f"Protocol version mismatch: manifest has '{manifest['protocol_version']}', "
                    f"model payload has '{model.protocol.protocol_version}'"
                )

        if "configuration_id" in manifest:
            if manifest["configuration_id"] != model.config.configuration_id:
                raise ValueError(
                    f"Configuration ID mismatch: manifest has '{manifest['configuration_id']}', "
                    f"model payload has '{model.config.configuration_id}'"
                )

        if "is_canonical_baseline" in manifest:
            if manifest["is_canonical_baseline"] != model.config.is_canonical_baseline:
                raise ValueError(
                    f"Canonical baseline flag mismatch: manifest has "
                    f"'{manifest['is_canonical_baseline']}', "
                    f"model payload has '{model.config.is_canonical_baseline}'"
                )

        if "feature_contract_version" in manifest:
            if manifest["feature_contract_version"] != model.protocol.feature_contract_version:
                raise ValueError(
                    f"Feature contract version mismatch: manifest has "
                    f"'{manifest['feature_contract_version']}', "
                    f"model payload has '{model.protocol.feature_contract_version}'"
                )

        if "selected_features" in manifest:
            if list(manifest["selected_features"]) != list(model.protocol.selected_features):
                raise ValueError("Selected features mismatch between manifest and model protocol.")

        if "hyperparameters" in manifest and isinstance(manifest["hyperparameters"], dict):
            m_hp = manifest["hyperparameters"]
            c_hp = model.config.to_dict()
            for hp_key in (
                "n_estimators",
                "max_depth",
                "min_samples_split",
                "min_samples_leaf",
                "criterion",
                "max_features",
                "random_state",
                "n_jobs",
                "bootstrap",
            ):
                if hp_key in m_hp and m_hp[hp_key] != c_hp.get(hp_key):
                    raise ValueError(
                        f"Hyperparameter '{hp_key}' mismatch: manifest has {m_hp[hp_key]!r}, "
                        f"model config has {c_hp.get(hp_key)!r}"
                    )

        n_feat_in = getattr(model.estimator, "n_features_in_", None)
        if n_feat_in is not None and n_feat_in != len(model.feature_names):
            raise ValueError(
                f"Estimator n_features_in_ ({n_feat_in}) does not match "
                f"model feature count ({len(model.feature_names)})"
            )

        feat_names_in = getattr(model.estimator, "feature_names_in_", None)
        if feat_names_in is not None:
            if list(feat_names_in) != list(model.feature_names):
                raise ValueError("Estimator feature_names_in_ does not match model feature names.")

        if model.estimator.n_estimators != model.config.n_estimators:
            raise ValueError(
                f"Estimator n_estimators ({model.estimator.n_estimators}) != "
                f"config n_estimators ({model.config.n_estimators})"
            )
        if model.estimator.max_depth != model.config.max_depth:
            raise ValueError(
                f"Estimator max_depth ({model.estimator.max_depth}) != "
                f"config max_depth ({model.config.max_depth})"
            )
        if model.estimator.random_state != model.config.random_state:
            raise ValueError(
                f"Estimator random_state ({model.estimator.random_state}) != "
                f"config random_state ({model.config.random_state})"
            )

        if manifest.get("is_canonical_baseline") is True:
            if not model.config.is_canonical_baseline:
                raise ValueError(
                    "Manifest claims is_canonical_baseline=True, but "
                    "model payload has is_canonical_baseline=False."
                )
            if model.config.configuration_id != "rf-baseline-canonical-v1":
                raise ValueError(
                    f"Canonical baseline configuration_id must be 'rf-baseline-canonical-v1', "
                    f"got {model.config.configuration_id!r}"
                )
            model.config.validate()
            model.protocol.validate()

        return model


def _sha256_file(path: Path, chunk_bytes: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_bytes), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_model(
    config: Optional[
        Union[Dict[str, Any], RandomForestBaselineConfig, RandomForestBaselineProtocol]
    ] = None,
) -> RandomForestClassifier:
    """Build a RandomForestClassifier instance from a configuration or protocol."""
    if config is None:
        cfg = RANDOM_FOREST_DEFAULTS.copy()
    elif isinstance(config, RandomForestBaselineProtocol):
        config.validate()
        config.model_config.validate()
        cfg = config.model_config.to_sklearn_params()
    elif isinstance(config, RandomForestBaselineConfig):
        config.validate()
        cfg = config.to_sklearn_params()
    elif isinstance(config, dict):
        cfg_obj = RandomForestBaselineConfig.from_dict(config)
        cfg = cfg_obj.to_sklearn_params()
    else:
        raise TypeError(f"Unsupported config type: {type(config)}")
    return RandomForestClassifier(**cfg)


__all__ = [
    "RandomForestModel",
    "build_model",
    "CANONICAL_BASELINE_PARAMS",
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
