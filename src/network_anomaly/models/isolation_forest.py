"""Isolation Forest unsupervised anomaly detection.

Note: evaluation protocol differs from supervised Random Forest.
Score-based threshold selection must be documented separately.

Scope of this module (Issue #11, model component only):
- a factory that builds a validated, reproducible ``IsolationForest``;
- an explicit contract for score direction and for the numeric feature matrix
  the estimator accepts.

Not implemented here, and still tracked by #6 (EDA), #7 (split and leakage
audit), #8 (fitted preprocessing) and the remaining part of #11 (threshold
calibration on validation, unknown-attack holdout, detection rate, FPR and the
comparison with Autoencoder): this module never loads data, never materialises
a split, never fits a transformer and never picks a threshold. The caller must
pass a feature matrix that is already numeric, finite and ordered by the
feature contract.
"""

import hashlib
import json
import numbers
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

from network_anomaly.config import ISOLATION_FOREST_DEFAULTS

FEATURE_CONTRACT_VERSION = "nf-unsw-nb15-v3-baseline-47"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _valid_sha256(value: Any) -> bool:
    """Validate a non-placeholder SHA-256 hexadecimal string."""
    return isinstance(value, str) and bool(_SHA256_RE.match(value)) and value != "0" * 64


def _sha256_file(path: Union[str, Path]) -> str:
    """Compute hex SHA-256 digest of a file in 64 KiB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


# Parameters this factory accepts. Anything else is rejected instead of being
# forwarded to scikit-learn, so a typo cannot silently change the estimator.
SUPPORTED_PARAMS = (
    "n_estimators",
    "max_samples",
    "contamination",
    "max_features",
    "bootstrap",
    "random_state",
    "n_jobs",
)


def _is_int(value):
    """True for plain integers (numpy integers included), false for booleans."""
    return isinstance(value, numbers.Integral) and not isinstance(value, bool)


def _is_float(value):
    """True for real numbers (numpy floats included), false for booleans."""
    return isinstance(value, numbers.Real) and not isinstance(value, bool)


def _is_numeric_dtype(dtype):
    """True for real numeric dtypes (boolean, integer, unsigned, float).

    Complex dtypes (kind == 'c') are intentionally excluded: converting a
    complex array to float64 silently discards the imaginary component, which
    is incorrect.  Callers that hold complex features must convert to a real
    representation before calling this module.
    """
    return getattr(dtype, "kind", None) in ("b", "i", "u", "f")


def _check_n_estimators(value):
    if not _is_int(value) or value < 1:
        raise ValueError(f"n_estimators must be an integer >= 1, got {value!r}")


def _check_max_samples(value):
    if isinstance(value, str):
        if value != "auto":
            raise ValueError(
                f"max_samples must be 'auto', an integer >= 1 or a float in (0, 1], got {value!r}"
            )
        return
    if _is_int(value):
        if value < 1:
            raise ValueError(f"max_samples must be an integer >= 1, got {value!r}")
        return
    if _is_float(value):
        if not 0.0 < value <= 1.0:
            raise ValueError(f"max_samples must be a float in (0, 1], got {value!r}")
        return
    raise ValueError(
        f"max_samples must be 'auto', an integer >= 1 or a float in (0, 1], got {value!r}"
    )


def _check_contamination(value):
    if isinstance(value, str):
        if value != "auto":
            raise ValueError(f"contamination must be 'auto' or a float in (0, 0.5], got {value!r}")
        return
    if not _is_float(value) or not 0.0 < value <= 0.5:
        raise ValueError(f"contamination must be 'auto' or a float in (0, 0.5], got {value!r}")


def _check_max_features(value):
    """Validate max_features against the values accepted by IsolationForest.

    Accepted: a positive integer (>= 1) or a float in (0, 1].
    Rejected: None, booleans, strings, zero, negative values, and floats
    outside (0, 1].  None is explicitly rejected because scikit-learn maps it
    to 1.0 only by coincidence of internal defaults; an explicit 1.0 is the
    correct way to express "use all features".
    """
    if value is None:
        raise ValueError(
            "max_features must be an integer >= 1 or a float in (0, 1], got None. "
            "Use max_features=1.0 to select all features."
        )
    if _is_int(value):
        if value < 1:
            raise ValueError(f"max_features must be an integer >= 1, got {value!r}")
        return
    if _is_float(value):
        if not 0.0 < value <= 1.0:
            raise ValueError(f"max_features must be a float in (0, 1], got {value!r}")
        return
    raise ValueError(f"max_features must be an integer >= 1 or a float in (0, 1], got {value!r}")


def _check_bootstrap(value):
    if not isinstance(value, bool):
        raise ValueError(f"bootstrap must be a boolean, got {value!r}")


def _check_random_state(value):
    if not _is_int(value):
        raise ValueError(
            "random_state must be an explicit integer seed "
            f"(see network_anomaly.config.RANDOM_SEED), got {value!r}. "
            "None disables reproducibility and is rejected."
        )


def _check_n_jobs(value):
    if value is None:
        return
    if not _is_int(value) or value == 0:
        raise ValueError(f"n_jobs must be a non-zero integer or None, got {value!r}")


_CHECKS = {
    "n_estimators": _check_n_estimators,
    "max_samples": _check_max_samples,
    "contamination": _check_contamination,
    "max_features": _check_max_features,
    "bootstrap": _check_bootstrap,
    "random_state": _check_random_state,
    "n_jobs": _check_n_jobs,
}


def validate_config(params):
    """Validate Isolation Forest parameters and raise on invalid values.

    Only the keys present in ``params`` are checked, so a partial override can
    be validated on its own. Invalid values are reported, never silently
    corrected or dropped.
    """
    if not isinstance(params, Mapping):
        raise TypeError(
            f"Isolation Forest config must be a mapping of parameters, got {type(params).__name__}"
        )
    unknown = sorted(set(params) - set(SUPPORTED_PARAMS))
    if unknown:
        raise TypeError(
            f"Unsupported Isolation Forest parameter(s): {', '.join(unknown)}. "
            f"Supported: {', '.join(SUPPORTED_PARAMS)}"
        )
    for name, check in _CHECKS.items():
        if name in params:
            check(params[name])


def build_model(config=None, **overrides):
    """Build an ``IsolationForest`` estimator from validated parameters.

    ``config`` is a mapping merged over ``config.ISOLATION_FOREST_DEFAULTS`` and
    ``overrides`` are applied last, so a caller can change one parameter without
    restating the others. Every value is validated before the estimator is
    created; an invalid value raises instead of being adjusted.
    """
    params = dict(ISOLATION_FOREST_DEFAULTS)
    if config is not None:
        if not isinstance(config, Mapping):
            raise TypeError(
                "Isolation Forest config must be a mapping of parameters, got "
                f"{type(config).__name__}"
            )
        params.update(config)
    params.update(overrides)
    validate_config(params)
    return IsolationForest(**params)


def _to_float_array(X):
    if hasattr(X, "to_numpy"):
        return X.to_numpy(dtype="float64", na_value=np.nan)
    return np.asarray(X, dtype="float64")


def validate_features(X):
    """Ensure ``X`` is a finite 2-D numeric (real) feature matrix.

    The model never fits a transformer, so the caller owns the feature
    contract: which columns enter the matrix, in which order, and the
    exclusion of ``Label``, ``Attack`` and the metadata columns. This guard
    checks that what reaches the estimator is:

    * a two-dimensional array or DataFrame (not 1-D, not 0-row, not 0-column);
    * composed entirely of real numeric columns (complex is rejected because
      converting complex to float64 silently discards the imaginary part);
    * free of NaN and infinite values (preprocessing must have handled these).

    It does not hard-code a dataset column list; that contract belongs to the
    split and feature work of #7.
    """
    if X is None:
        raise TypeError("Feature matrix X is required, got None")
    if hasattr(X, "columns") and hasattr(X, "dtypes"):
        # --- pandas DataFrame path ---
        if X.ndim != 2:  # pragma: no cover — DataFrames are always 2-D
            raise ValueError(f"Feature matrix must be 2-D, got {X.ndim}-D DataFrame")
        if X.shape[0] == 0:
            raise ValueError(
                "Feature matrix must have at least one sample, got 0 rows. "
                "Check that the dataset is not empty after splitting."
            )
        if X.shape[1] == 0:
            raise ValueError(
                "Feature matrix must have at least one feature, got 0 columns. "
                "Check that the preprocessing pipeline has not dropped all columns."
            )
        complex_cols = [
            str(col)
            for col, dtype in zip(X.columns, X.dtypes)
            if getattr(dtype, "kind", None) == "c"
        ]
        if complex_cols:
            raise TypeError(
                "Feature matrix must not contain complex-valued columns; "
                "complex column(s): " + ", ".join(complex_cols) + ". "
                "Convert to a real representation before passing to the model."
            )
        non_numeric = [
            str(column)
            for column, dtype in zip(X.columns, X.dtypes)
            if not _is_numeric_dtype(dtype)
        ]
        if non_numeric:
            raise TypeError(
                "Feature matrix must contain numeric columns only; non-numeric column(s): "
                + ", ".join(non_numeric)
            )
    else:
        # --- NumPy / array-like path ---
        array = np.asarray(X)
        if array.ndim != 2:
            raise ValueError(
                f"Feature matrix must be 2-D, got {array.ndim}-D array (shape {array.shape}). "
                "Pass a matrix with shape (n_samples, n_features); a 1-D array is not accepted."
            )
        if array.shape[0] == 0:
            raise ValueError(
                "Feature matrix must have at least one sample, got 0 rows. "
                "Check that the dataset is not empty after splitting."
            )
        if array.shape[1] == 0:
            raise ValueError(
                "Feature matrix must have at least one feature, got 0 columns. "
                "Check that the preprocessing pipeline has not dropped all columns."
            )
        if getattr(array.dtype, "kind", None) == "c":
            raise TypeError(
                f"Feature matrix must not be complex-valued, got dtype {array.dtype}. "
                "Convert to a real representation before passing to the model."
            )
        if not _is_numeric_dtype(array.dtype):
            raise TypeError(f"Feature matrix must be numeric, got dtype {array.dtype}")
    values = _to_float_array(X)
    if not np.isfinite(values).all():
        raise ValueError(
            "Feature matrix contains NaN or infinite values. Missing and non-finite "
            "values must be handled by the fitted preprocessing pipeline before the "
            "model is fitted."
        )


def fit_model(model, X):
    """Fit the estimator on an unlabeled numeric feature matrix.

    Isolation Forest is unsupervised, so no target argument is accepted: a
    label column cannot be handed to the model by accident. The caller stays
    responsible for the training population (normal-only novelty detection or
    a mixed/unlabeled population) and must record which one was used.
    """
    validate_features(X)
    return model.fit(X)


def anomaly_scores(model, X):
    """Return anomaly scores where a larger value means more anomalous.

    scikit-learn's ``decision_function`` uses the opposite sign (lower means
    more anomalous). This helper fixes the direction once so the evaluation
    protocol cannot silently flip it. It applies no threshold.
    Supports raw IsolationForest estimators, IsolationForestModel wrapper instances,
    and serialized payload dictionaries containing an 'estimator' key.
    """
    validate_features(X)
    if isinstance(model, IsolationForestModel):
        return model.anomaly_scores(X)
    if isinstance(model, dict) and "estimator" in model:
        return anomaly_scores(model["estimator"], X)
    if hasattr(model, "_estimator") and hasattr(model._estimator, "decision_function"):
        return -np.asarray(model._estimator.decision_function(X), dtype=float)
    if hasattr(model, "decision_function"):
        return -np.asarray(model.decision_function(X), dtype=float)
    raise TypeError(f"Unsupported model type for anomaly_scores: {type(model).__name__}")


class IsolationForestModel:
    """Standardized Isolation Forest model component for network anomaly detection.

    Implements the standardized model wrapper for Issue #11 and Issue #54 (C4 / Track C).
    Provides consistent interfaces:
      - __init__(config=None, threshold=None, ...)
      - build_model()
      - fit(X, y=None, **fit_params)
      - anomaly_scores(X) -> returns float array where larger means more anomalous
      - decision_function(X) -> alias for anomaly_scores(X) for consistent scoring
      - predict(X, threshold=None) -> returns binary labels in {0, 1} (0: Benign, 1: Attack)
      - save(model_path, manifest_path=None, ...) -> saves artifact payload and manifest
      - load(model_path) -> loads IsolationForestModel instance
      - load_verified(model_path, manifest_path, ...) -> loads with fail-closed verification
    """

    def __init__(
        self,
        config: Optional[Union[Dict[str, Any], Mapping]] = None,
        threshold: Optional[float] = None,
        score_direction: str = "higher_is_more_anomalous",
        label_mapping: Optional[Dict[str, str]] = None,
        **overrides: Any,
    ) -> None:
        params = dict(ISOLATION_FOREST_DEFAULTS)
        if config is not None:
            if not isinstance(config, Mapping):
                raise TypeError(
                    "Isolation Forest config must be a mapping of parameters, "
                    f"got {type(config).__name__}"
                )
            params.update(config)
        params.update(overrides)
        validate_config(params)

        self.config: Dict[str, Any] = params
        self.threshold: Optional[float] = float(threshold) if threshold is not None else None
        if self.threshold is not None and not np.isfinite(self.threshold):
            raise ValueError("Calibrated threshold must be finite")
        self.score_direction: str = score_direction
        self.label_mapping: Dict[str, str] = (
            dict(label_mapping) if label_mapping is not None else {"0": "Benign", "1": "Attack"}
        )
        self.model_type: str = "IsolationForest"
        self.task: str = "unsupervised_anomaly_detection"
        self.target: str = "Label"
        self.positive_class: str = "Attack"
        self.classes_: np.ndarray = np.array([0, 1], dtype=int)
        self.feature_names: Optional[Tuple[str, ...]] = None
        self.feature_contract_version: str = FEATURE_CONTRACT_VERSION
        self._is_fitted: bool = False
        self._estimator: IsolationForest = IsolationForest(**self.config)

    @property
    def estimator(self) -> IsolationForest:
        """Return the underlying scikit-learn IsolationForest estimator."""
        return self._estimator

    def build_model(self) -> IsolationForest:
        """Re-instantiate the underlying IsolationForest estimator."""
        self._estimator = IsolationForest(**self.config)
        self._is_fitted = False
        return self._estimator

    def fit(self, X: Any, y: Any = None, **fit_params: Any) -> "IsolationForestModel":
        """Fit the estimator on an unlabeled numeric feature matrix.

        y is accepted for scikit-learn API compatibility but is not used in training.
        """
        validate_features(X)
        if hasattr(X, "columns"):
            self.feature_names = tuple(str(c) for c in X.columns)
        self._estimator.fit(X, **fit_params)
        self._is_fitted = True
        return self

    def anomaly_scores(self, X: Any) -> np.ndarray:
        """Return anomaly scores where higher means more anomalous."""
        if not self._is_fitted:
            raise NotFittedError(
                "This IsolationForestModel instance is not fitted yet. "
                "Call 'fit' before computing anomaly scores."
            )
        validate_features(X)
        return -np.asarray(self._estimator.decision_function(X), dtype=float)

    def decision_function(self, X: Any) -> np.ndarray:
        """Return anomaly scores with consistent direction (higher is more anomalous)."""
        return self.anomaly_scores(X)

    def predict(self, X: Any, threshold: Optional[float] = None) -> np.ndarray:
        """Predict binary anomaly labels in {0, 1} (0: Benign, 1: Attack).

        Applies the calibrated threshold:
          scores = anomaly_scores(estimator, X) = -estimator.decision_function(X)
          y_pred = (scores >= threshold).astype(int)
        """
        if not self._is_fitted:
            raise NotFittedError(
                "This IsolationForestModel instance is not fitted yet. "
                "Call 'fit' before calling 'predict'."
            )
        t = self.threshold if threshold is None else float(threshold)
        if t is None:
            raise ValueError(
                "Threshold is not set. A calibrated threshold is required for predict(). "
                "Specify threshold in __init__, set model.threshold, or pass threshold argument."
            )
        if np.isnan(t) or (threshold is None and not np.isfinite(t)):
            raise ValueError("Calibrated threshold must be finite")
        scores = self.anomaly_scores(X)
        return (scores >= t).astype(int)

    def save(
        self,
        model_path: Union[str, Path],
        manifest_path: Optional[Union[str, Path]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        extra_manifest_fields: Optional[Dict[str, Any]] = None,
        preprocessor_artifact_sha256: Optional[str] = None,
        split_manifest_sha256: Optional[str] = None,
        evaluation_summary: Optional[Dict[str, Any]] = None,
        feature_contract_version: Optional[str] = None,
    ) -> str:
        """Save fitted model artifact payload and companion manifest; return model SHA-256."""
        if not self._is_fitted:
            raise NotFittedError("Cannot save an unfitted IsolationForestModel.")
        if self.threshold is None:
            raise ValueError("Cannot save IsolationForestModel without a calibrated threshold.")
        if not np.isfinite(self.threshold):
            raise ValueError("Calibrated threshold must be finite")

        p = Path(model_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        fc_version = feature_contract_version or self.feature_contract_version
        payload = {
            "model_type": self.model_type,
            "task": self.task,
            "target": self.target,
            "positive_class": self.positive_class,
            "estimator": self._estimator,
            "config": dict(self.config),
            "threshold": float(self.threshold),
            "calibrated_threshold": float(self.threshold),
            "score_direction": self.score_direction,
            "label_mapping": dict(self.label_mapping),
            "feature_contract_version": fc_version,
            "feature_names": list(self.feature_names) if self.feature_names is not None else None,
            "classes": [0, 1],
            "is_fitted": self._is_fitted,
            "metadata": metadata or {},
        }
        joblib.dump(payload, p, compress=3)
        artifact_sha256 = _sha256_file(p)

        if manifest_path is not None:
            mp = Path(manifest_path)
            mp.parent.mkdir(parents=True, exist_ok=True)
            manifest_data: Dict[str, Any] = {
                "model_type": self.model_type,
                "task": self.task,
                "target": self.target,
                "positive_class": self.positive_class,
                "model_artifact_path": str(p.as_posix()),
                "model_artifact_sha256": artifact_sha256,
                "model_artifact_size_bytes": p.stat().st_size,
                "preprocessor_artifact_sha256": preprocessor_artifact_sha256,
                "split_manifest_sha256": split_manifest_sha256,
                "threshold": float(self.threshold),
                "calibrated_threshold": float(self.threshold),
                "score_direction": self.score_direction,
                "label_mapping": dict(self.label_mapping),
                "feature_contract_version": fc_version,
                "hyperparameters": dict(self.config),
                "evaluation_summary": evaluation_summary or {},
                "metadata": metadata or {},
            }
            if extra_manifest_fields:
                manifest_data.update(extra_manifest_fields)
            with mp.open("w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2, ensure_ascii=False)

        return artifact_sha256

    @classmethod
    def load(cls, model_path: Union[str, Path]) -> "IsolationForestModel":
        """Load an IsolationForestModel from a joblib artifact."""
        p = Path(model_path)
        if not p.exists():
            raise FileNotFoundError(f"Model artifact not found at {model_path}")
        payload = joblib.load(p)
        if isinstance(payload, dict) and "estimator" in payload:
            config = payload.get("config", {})
            threshold = payload.get("threshold")
            if "calibrated_threshold" in payload and payload["calibrated_threshold"] != threshold:
                raise ValueError("Artifact calibrated_threshold conflicts with threshold")
            score_dir = payload.get("score_direction", "higher_is_more_anomalous")
            label_map = payload.get("label_mapping", {"0": "Benign", "1": "Attack"})
            model = cls(
                config=config,
                threshold=threshold,
                score_direction=score_dir,
                label_mapping=label_map,
            )
            model._estimator = payload["estimator"]
            model._is_fitted = bool(payload.get("is_fitted", True))
            if payload.get("feature_names"):
                model.feature_names = tuple(payload["feature_names"])
            if payload.get("feature_contract_version"):
                model.feature_contract_version = payload["feature_contract_version"]
            return model
        elif hasattr(payload, "decision_function"):
            config = payload.get_params() if hasattr(payload, "get_params") else {}
            model = cls(config=config)
            model._estimator = payload
            model._is_fitted = (
                hasattr(payload, "estimators_") and len(getattr(payload, "estimators_", [])) > 0
            )
            return model
        else:
            raise ValueError(f"Invalid model artifact payload at {model_path}")

    @classmethod
    def load_verified(
        cls,
        model_path: Union[str, Path],
        manifest_path: Union[str, Path],
        expected_preprocessor_artifact_sha256: Optional[str] = None,
        expected_split_manifest_sha256: Optional[str] = None,
        expected_threshold: Optional[float] = None,
        expected_model_sha256: Optional[str] = None,
    ) -> "IsolationForestModel":
        """Load and strictly verify an Isolation Forest model artifact against manifest.

        Fail-closed verification:
        1. Manifest file must exist and be valid JSON object.
        2. model_type must be "IsolationForest".
        3. model_artifact_sha256 must match file SHA-256 byte-for-byte.
        4. threshold must exist, be a valid float, and match expected_threshold if provided.
        5. preprocessor_artifact_sha256 must exist, be valid 64-hex, and match expected.
        6. score_direction must be "higher_is_more_anomalous".
        7. label_mapping must map {"0": "Benign", "1": "Attack"}.
        8. Payload inside artifact must have matching threshold and score_direction.
        """
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

        # Check model_type
        model_type = manifest.get("model_type")
        if model_type != "IsolationForest":
            raise ValueError(
                "Model manifest model_type mismatch: expected 'IsolationForest', "
                f"got '{model_type}'"
            )

        # Check model_artifact_sha256
        if "model_artifact_sha256" not in manifest or manifest["model_artifact_sha256"] is None:
            raise ValueError(
                f"Missing required field 'model_artifact_sha256' in manifest: {manifest_path}"
            )
        manifest_model_sha = manifest["model_artifact_sha256"]
        if not _valid_sha256(manifest_model_sha):
            raise ValueError(
                "Invalid or malformed 64-character hexadecimal SHA-256 for "
                f"'model_artifact_sha256': {manifest_model_sha!r}"
            )
        manifest_model_sha = manifest_model_sha.lower()

        if expected_model_sha256 is not None:
            if (
                not _valid_sha256(expected_model_sha256)
                or expected_model_sha256.lower() != manifest_model_sha
            ):
                raise ValueError(
                    "Model artifact SHA-256 mismatch between caller "
                    f"({expected_model_sha256}) and manifest ({manifest_model_sha})"
                )

        p_model = Path(model_path)
        if not p_model.exists():
            raise FileNotFoundError(f"Model artifact not found: {model_path}")

        actual_model_sha = _sha256_file(p_model)
        if actual_model_sha != manifest_model_sha:
            raise ValueError(
                f"Integrity check failed for {model_path}: "
                f"expected SHA-256 {manifest_model_sha}, got {actual_model_sha}"
            )

        # Check threshold
        has_thresh = "threshold" in manifest and manifest["threshold"] is not None
        if not has_thresh or isinstance(manifest["threshold"], bool):
            raise ValueError(
                f"Missing or invalid required float field 'threshold' in manifest: {manifest_path}"
            )
        try:
            manifest_threshold = float(manifest["threshold"])
        except (ValueError, TypeError) as e:
            raise ValueError(
                f"Invalid float 'threshold' in manifest: {manifest['threshold']!r}"
            ) from e
        if not np.isfinite(manifest_threshold):
            raise ValueError("Calibrated threshold in manifest must be finite")
        calibrated_threshold = manifest.get("calibrated_threshold", manifest_threshold)
        if (
            isinstance(calibrated_threshold, bool)
            or not isinstance(calibrated_threshold, (int, float))
            or not np.isfinite(calibrated_threshold)
            or abs(float(calibrated_threshold) - manifest_threshold) > 1e-9
        ):
            raise ValueError("calibrated_threshold conflicts with manifest threshold")

        if expected_threshold is not None:
            if abs(manifest_threshold - float(expected_threshold)) > 1e-9:
                raise ValueError(
                    f"Threshold mismatch: expected {expected_threshold}, got {manifest_threshold}"
                )

        # Check preprocessor_artifact_sha256
        has_prep = (
            "preprocessor_artifact_sha256" in manifest
            and manifest["preprocessor_artifact_sha256"] is not None
        )
        if not has_prep:
            raise ValueError(
                "Missing required field 'preprocessor_artifact_sha256' in manifest: "
                f"{manifest_path}"
            )
        manifest_prep_sha = manifest["preprocessor_artifact_sha256"]
        if not _valid_sha256(manifest_prep_sha):
            raise ValueError(
                "Invalid or malformed 64-character hexadecimal SHA-256 for "
                f"'preprocessor_artifact_sha256': {manifest_prep_sha!r}"
            )
        manifest_prep_sha = manifest_prep_sha.lower()

        if expected_preprocessor_artifact_sha256 is not None:
            if (
                not _valid_sha256(expected_preprocessor_artifact_sha256)
                or expected_preprocessor_artifact_sha256.lower() != manifest_prep_sha
            ):
                raise ValueError(
                    "Preprocessor artifact SHA-256 mismatch: "
                    f"expected {expected_preprocessor_artifact_sha256}, got {manifest_prep_sha}"
                )

        # Check split_manifest_sha256 if expected
        if expected_split_manifest_sha256 is not None:
            manifest_sm_sha = manifest.get("split_manifest_sha256")
            if (
                not manifest_sm_sha
                or manifest_sm_sha.lower() != expected_split_manifest_sha256.lower()
            ):
                raise ValueError(
                    "Split manifest SHA-256 mismatch: "
                    f"expected {expected_split_manifest_sha256}, got {manifest_sm_sha}"
                )

        # Check score_direction
        score_dir = manifest.get("score_direction")
        if score_dir != "higher_is_more_anomalous":
            raise ValueError(
                "Invalid score_direction in manifest: "
                f"expected 'higher_is_more_anomalous', got {score_dir!r}"
            )

        # Check label_mapping
        label_map = manifest.get("label_mapping")
        if not isinstance(label_map, dict):
            raise ValueError(f"label_mapping must be a dictionary, got {type(label_map).__name__}")
        benign_val = label_map.get("0") or label_map.get(0)
        attack_val = label_map.get("1") or label_map.get(1)
        if benign_val != "Benign" or attack_val != "Attack":
            raise ValueError(
                "Invalid label_mapping in manifest: expected 0->Benign, 1->Attack, "
                f"got {label_map!r}"
            )

        # Load deserialized payload after cryptographic check passes
        model = cls.load(p_model)

        # Validate loaded model internal attributes against manifest
        if model.threshold is None or abs(model.threshold - manifest_threshold) > 1e-9:
            raise ValueError(
                f"Artifact internal threshold ({model.threshold}) does not match "
                f"manifest threshold ({manifest_threshold})"
            )
        if model.score_direction != score_dir:
            raise ValueError(
                f"Artifact internal score_direction ({model.score_direction}) does not "
                f"match manifest ({score_dir})"
            )
        if not model._is_fitted:
            raise ValueError("Loaded model estimator is not fitted.")

        return model
