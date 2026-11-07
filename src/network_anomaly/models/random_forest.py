"""Random Forest supervised model and baseline protocol integration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import NotFittedError

from network_anomaly.config import RANDOM_FOREST_DEFAULTS
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
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
            proto = create_rf_baseline_protocol()
            self.protocol = proto
            self.config = proto.model_config
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
                "Call 'fit' with verified NF-UNSW-NB15-v3 training data "
                "before using 'predict_proba'."
            )
        return self._estimator.predict_proba(X)

    def save(
        self,
        path: Union[str, Path],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Save fitted model artifact using joblib and return file SHA-256."""
        if not self._is_fitted:
            raise NotFittedError("Cannot save an unfitted RandomForestModel.")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model_type": self.model_type,
            "task": self.task,
            "target": self.target,
            "positive_class": self.positive_class,
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
            "metadata": metadata or {},
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
        model = cls(config=config, protocol=protocol)
        model._estimator = payload["estimator"]
        model._is_fitted = True
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

        # 0. Provenance completeness and git_commit integrity checks
        if manifest.get("provenance_complete") is False or (
            manifest.get("provenance_status") == "INCOMPLETE"
        ):
            raise ValueError(
                f"Manifest indicates incomplete provenance and cannot be verified: {manifest_path}"
            )
        env = manifest.get("environment")
        if isinstance(env, dict) and "git_commit" in env:
            git_commit = env.get("git_commit")
            if (
                not isinstance(git_commit, str)
                or not git_commit.strip()
                or git_commit.strip().upper() == "UNKNOWN"
            ):
                raise ValueError(
                    f"Invalid or unknown environment.git_commit in manifest: {git_commit!r}"
                )

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

        model = cls.load(model_path)
        if model.protocol is None:
            raise ValueError(
                f"Model artifact at {model_path} lacks required protocol provenance "
                f"for verified loading."
            )
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
