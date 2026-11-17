"""Autoencoder unsupervised anomaly detection (C4 / Issue #29).

This module implements the model component for the Autoencoder reconstruction-error
anomaly detection branch:
- A factory that builds a validated, reproducible MLP Autoencoder;
- Strict validation of architecture, hyperparameters, random seeds, and input contracts;
- Explicit reconstruction-error and anomaly-score functions where larger values
  indicate greater anomaly (higher reconstruction error = more anomalous);
- Fit only on unlabeled numeric feature matrices (no target labels accepted).

Data loading, split materialization, preprocessor fitting, threshold calibration
on Validation, and unknown-attack evaluation are managed by the pipeline script
(scripts/train_autoencoder.py) and data/split modules.
"""

import hashlib
import json
import math
import numbers
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.neural_network import MLPRegressor

from network_anomaly.config import AUTOENCODER_DEFAULTS, PROJECT_ROOT
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.preprocessing import FEATURE_CONTRACT_VERSION

SUPPORTED_PARAMS = (
    "hidden_layer_sizes",
    "activation",
    "solver",
    "alpha",
    "batch_size",
    "learning_rate_init",
    "max_iter",
    "early_stopping",
    "validation_fraction",
    "n_iter_no_change",
    "tol",
    "random_state",
)

SUPPORTED_ACTIVATIONS = ("relu", "logistic", "tanh", "identity")
SUPPORTED_SOLVERS = ("adam", "sgd", "lbfgs")


def _is_int(value: Any) -> bool:
    """True for plain integers (numpy integers included), false for booleans."""
    return isinstance(value, numbers.Integral) and not isinstance(value, bool)


def _is_float(value: Any) -> bool:
    """True for real numbers (numpy floats included), false for booleans."""
    return isinstance(value, numbers.Real) and not isinstance(value, bool)


def _is_numeric_dtype(dtype: Any) -> bool:
    """True for real numeric dtypes (integer, unsigned, float).

    Boolean and complex dtypes are intentionally excluded.
    """
    return getattr(dtype, "kind", None) in ("i", "u", "f")


def _check_hidden_layer_sizes(value: Any) -> None:
    if isinstance(value, (list, tuple)):
        if len(value) == 0:
            raise ValueError(
                "hidden_layer_sizes must contain at least one layer, got empty sequence"
            )
        for idx, layer_size in enumerate(value):
            if not _is_int(layer_size) or layer_size < 1:
                raise ValueError(
                    f"hidden_layer_sizes[{idx}] must be an integer >= 1, got {layer_size!r}"
                )
        return
    if _is_int(value):
        if value < 1:
            raise ValueError(f"hidden_layer_sizes must be an integer >= 1, got {value!r}")
        return
    raise TypeError(
        "hidden_layer_sizes must be a tuple/list of positive integers "
        f"or a single positive integer, got {type(value).__name__}"
    )


def _check_activation(value: Any) -> None:
    if not isinstance(value, str) or value not in SUPPORTED_ACTIVATIONS:
        raise ValueError(f"activation must be one of {SUPPORTED_ACTIVATIONS}, got {value!r}")


def _check_solver(value: Any) -> None:
    if not isinstance(value, str) or value not in SUPPORTED_SOLVERS:
        raise ValueError(f"solver must be one of {SUPPORTED_SOLVERS}, got {value!r}")


def _check_alpha(value: Any) -> None:
    if not _is_float(value) and not _is_int(value):
        raise TypeError(f"alpha must be a non-negative float, got {type(value).__name__}")
    if value < 0.0:
        raise ValueError(f"alpha must be >= 0.0, got {value!r}")


def _check_batch_size(value: Any) -> None:
    if isinstance(value, str):
        if value != "auto":
            raise ValueError(f"batch_size must be 'auto' or a positive integer, got {value!r}")
        return
    if not _is_int(value) or value < 1:
        raise ValueError(f"batch_size must be 'auto' or a positive integer >= 1, got {value!r}")


def _check_learning_rate_init(value: Any) -> None:
    if not _is_float(value) and not _is_int(value):
        raise TypeError(f"learning_rate_init must be a positive float, got {type(value).__name__}")
    if value <= 0.0:
        raise ValueError(f"learning_rate_init must be > 0.0, got {value!r}")


def _check_max_iter(value: Any) -> None:
    if not _is_int(value) or value < 1:
        raise ValueError(f"max_iter must be an integer >= 1, got {value!r}")


def _check_early_stopping(value: Any) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"early_stopping must be a boolean, got {type(value).__name__}")


def _check_validation_fraction(value: Any) -> None:
    if not _is_float(value) or not (0.0 < value < 1.0):
        raise ValueError(f"validation_fraction must be a float in (0, 1), got {value!r}")


def _check_n_iter_no_change(value: Any) -> None:
    if not _is_int(value) or value < 1:
        raise ValueError(f"n_iter_no_change must be an integer >= 1, got {value!r}")


def _check_tol(value: Any) -> None:
    if not _is_float(value) and not _is_int(value):
        raise TypeError(f"tol must be a non-negative float, got {type(value).__name__}")
    if value < 0.0:
        raise ValueError(f"tol must be >= 0.0, got {value!r}")


def _check_random_state(value: Any) -> None:
    if not _is_int(value):
        raise ValueError(
            "random_state must be an explicit integer seed for reproducibility, "
            f"got {value!r}. None is rejected."
        )


_CHECKS = {
    "hidden_layer_sizes": _check_hidden_layer_sizes,
    "activation": _check_activation,
    "solver": _check_solver,
    "alpha": _check_alpha,
    "batch_size": _check_batch_size,
    "learning_rate_init": _check_learning_rate_init,
    "max_iter": _check_max_iter,
    "early_stopping": _check_early_stopping,
    "validation_fraction": _check_validation_fraction,
    "n_iter_no_change": _check_n_iter_no_change,
    "tol": _check_tol,
    "random_state": _check_random_state,
}


def validate_config(params: Mapping[str, Any]) -> None:
    """Validate Autoencoder hyperparameters and raise on any invalid setting.

    Only keys present in ``params`` are checked. Unsupported keys, incorrect
    types, and out-of-range values raise immediately.
    """
    if not isinstance(params, Mapping):
        raise TypeError(
            f"Autoencoder config must be a mapping of parameters, got {type(params).__name__}"
        )
    unknown = sorted(set(params) - set(SUPPORTED_PARAMS))
    if unknown:
        raise TypeError(
            f"Unsupported Autoencoder parameter(s): {', '.join(unknown)}. "
            f"Supported: {', '.join(SUPPORTED_PARAMS)}"
        )
    for name, check in _CHECKS.items():
        if name in params:
            check(params[name])


def build_model(config: Mapping[str, Any] | None = None, **overrides: Any) -> MLPRegressor:
    """Build an MLP Autoencoder model (MLPRegressor) from validated parameters.

    Default settings come from ``config.AUTOENCODER_DEFAULTS``. ``config`` and
    ``overrides`` are merged in order and strictly validated.
    """
    params = dict(AUTOENCODER_DEFAULTS)
    if config is not None:
        if not isinstance(config, Mapping):
            raise TypeError(
                f"Autoencoder config must be a mapping of parameters, got {type(config).__name__}"
            )
        params.update(config)
    params.update(overrides)

    # Normalize single integer hidden_layer_sizes to tuple
    if _is_int(params.get("hidden_layer_sizes")):
        params["hidden_layer_sizes"] = (params["hidden_layer_sizes"],)
    elif isinstance(params.get("hidden_layer_sizes"), list):
        params["hidden_layer_sizes"] = tuple(params["hidden_layer_sizes"])

    validate_config(params)
    return MLPRegressor(**params)


def _to_float_array(X: Any) -> np.ndarray:
    if hasattr(X, "to_numpy"):
        return X.to_numpy(dtype="float64", na_value=np.nan)
    return np.asarray(X, dtype="float64")


def validate_features(X: Any, expected_dim: int | None = None) -> None:
    """Validate that ``X`` is a 2-D numeric feature matrix suitable for Autoencoder.

    Guarantees:
    - 2-D array or DataFrame (shape (n_samples, n_features));
    - At least 1 sample and 1 feature;
    - Exactly ``expected_dim`` features if specified;
    - Real numeric dtypes only (no boolean, complex, string, object);
    - Strictly finite (no NaN, +Inf, -Inf).
    """
    if X is None:
        raise TypeError("Feature matrix X is required, got None")

    if hasattr(X, "columns") and hasattr(X, "dtypes"):
        # pandas DataFrame path
        if X.ndim != 2:
            raise ValueError(f"Feature matrix must be 2-D, got {X.ndim}-D DataFrame")
        if X.shape[0] == 0:
            raise ValueError("Feature matrix must have at least one sample, got 0 rows.")
        if X.shape[1] == 0:
            raise ValueError("Feature matrix must have at least one feature, got 0 columns.")
        if expected_dim is not None and X.shape[1] != expected_dim:
            raise ValueError(
                f"Feature matrix dimension mismatch: expected {expected_dim} features, "
                f"got {X.shape[1]}"
            )

        complex_cols = [
            str(col)
            for col, dtype in zip(X.columns, X.dtypes)
            if getattr(dtype, "kind", None) == "c"
        ]
        if complex_cols:
            raise TypeError(
                "Feature matrix must not contain complex-valued columns; "
                f"complex column(s): {', '.join(complex_cols)}."
            )
        non_numeric = [
            str(col) for col, dtype in zip(X.columns, X.dtypes) if not _is_numeric_dtype(dtype)
        ]
        if non_numeric:
            raise TypeError(
                "Feature matrix must contain numeric columns only; non-numeric column(s): "
                f"{', '.join(non_numeric)}"
            )
    else:
        # NumPy / array-like path
        array = np.asarray(X)
        if array.ndim != 2:
            raise ValueError(
                f"Feature matrix must be 2-D, got {array.ndim}-D array (shape {array.shape})."
            )
        if array.shape[0] == 0:
            raise ValueError("Feature matrix must have at least one sample, got 0 rows.")
        if array.shape[1] == 0:
            raise ValueError("Feature matrix must have at least one feature, got 0 columns.")
        if expected_dim is not None and array.shape[1] != expected_dim:
            raise ValueError(
                f"Feature matrix dimension mismatch: expected {expected_dim} features, "
                f"got {array.shape[1]}"
            )
        if getattr(array.dtype, "kind", None) == "c":
            raise TypeError(f"Feature matrix must not be complex-valued, got dtype {array.dtype}")
        if not _is_numeric_dtype(array.dtype):
            raise TypeError(f"Feature matrix must be numeric, got dtype {array.dtype}")

    values = _to_float_array(X)
    if not np.isfinite(values).all():
        raise ValueError(
            "Feature matrix contains NaN or infinite values. "
            "All features must be cleaned and finite before Autoencoder processing."
        )


def fit_model(model: MLPRegressor, X: Any) -> MLPRegressor:
    """Fit the Autoencoder to reconstruct its input distribution.

    Autoencoder training is strictly unsupervised: no target argument is accepted.
    The model is trained with reconstruction objective: target y is set to X.
    The caller is responsible for ensuring X contains only the authorized training
    population (e.g. benign-only from the Train partition) and that target/metadata
    columns are completely excluded.
    """
    validate_features(X)
    X_arr = _to_float_array(X)
    return model.fit(X_arr, X_arr)


def reconstruct(model: MLPRegressor, X: Any) -> np.ndarray:
    """Reconstruct the feature matrix X using the fitted Autoencoder."""
    validate_features(X)
    X_arr = _to_float_array(X)
    return model.predict(X_arr)


def reconstruction_errors(model: MLPRegressor, X: Any) -> np.ndarray:
    """Calculate per-sample Mean Squared Error (MSE) reconstruction errors.

    Score direction:
    - Higher reconstruction error = more anomalous.
    - Lower reconstruction error = more normal.

    Returns a 1-D numpy float64 array of shape (n_samples,).
    """
    validate_features(X)
    X_arr = _to_float_array(X)
    X_hat = model.predict(X_arr)
    # Per-sample mean squared error over features
    errors = np.mean((X_arr - X_hat) ** 2, axis=1)
    return np.asarray(errors, dtype=np.float64)


def anomaly_scores(model: MLPRegressor, X: Any) -> np.ndarray:
    """Return anomaly scores where a larger value means more anomalous.

    For the Autoencoder, the canonical anomaly score is the reconstruction error.
    """
    return reconstruction_errors(model, X)


def predict(model: MLPRegressor, X: Any, threshold: float) -> np.ndarray:
    """Predict binary anomaly decisions given a frozen threshold.

    Decision rule:
    - 1 (anomalous) if reconstruction_error >= threshold;
    - 0 (normal) if reconstruction_error < threshold.

    Returns a 1-D integer array of shape (n_samples,).
    """
    if not _is_float(threshold) and not _is_int(threshold):
        raise TypeError(f"threshold must be a real number, got {type(threshold).__name__}")
    if not np.isfinite(threshold):
        raise ValueError(f"threshold must be finite, got {threshold!r}")
    if threshold < 0.0:
        raise ValueError(
            f"threshold must be non-negative for reconstruction error, got {threshold!r}"
        )

    scores = reconstruction_errors(model, X)
    return (scores >= threshold).astype(np.int64)


class AutoencoderModel:
    """Verified-inference wrapper pairing a fitted MLPRegressor autoencoder with its threshold."""

    model_type = "Autoencoder"

    def __init__(self, estimator: MLPRegressor, threshold: float) -> None:
        if not isinstance(estimator, MLPRegressor):
            raise TypeError(
                f"AutoencoderModel requires an MLPRegressor estimator, got {type(estimator).__name__}"
            )
        if not _is_float(threshold) and not _is_int(threshold):
            raise TypeError(f"threshold must be a real number, got {type(threshold).__name__}")
        threshold_val = float(threshold)
        if not np.isfinite(threshold_val) or threshold_val < 0.0:
            raise ValueError(f"threshold must be non-negative and finite, got {threshold!r}")
        self._estimator = estimator
        self.threshold = threshold_val

    @property
    def estimator(self) -> MLPRegressor:
        """Return the underlying fitted MLPRegressor instance."""
        return self._estimator

    def anomaly_scores(self, X: Any) -> np.ndarray:
        """Compute per-sample MSE reconstruction errors (higher = more anomalous)."""
        return anomaly_scores(self._estimator, X)

    def score_samples(self, X: Any) -> np.ndarray:
        """Alias returning MSE reconstruction errors for uniform score extraction."""
        return anomaly_scores(self._estimator, X)

    def predict(self, X: Any) -> np.ndarray:
        """Predict binary anomaly labels {0, 1} using the frozen threshold."""
        return predict(self._estimator, X, threshold=self.threshold)

    @classmethod
    def load_verified(
        cls,
        model_path: str | Path,
        manifest_path: str | Path | None = None,
        expected_preprocessor_sha256: str | None = None,
    ) -> "AutoencoderModel":
        """Load and strictly verify an Autoencoder artifact against its manifest and sidecars."""
        model, _ = load_verified_autoencoder_bundle(
            model_artifact_path=model_path,
            manifest_path=manifest_path,
            expected_preprocessor_sha256=expected_preprocessor_sha256,
        )
        return model


_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file in streaming 64 KiB chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _is_valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_HEX_RE.fullmatch(value.strip()))


def _require_nonneg_finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Autoencoder {label} must be a real number, got {value!r}")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0.0:
        raise ValueError(f"Autoencoder {label} must be finite and >= 0, got {value!r}")
    return numeric


def _normalize_hidden_layers(value: Any) -> list[int]:
    if _is_int(value):
        return [int(value)]
    if isinstance(value, (list, tuple)):
        return [int(v) for v in value]
    return []


def _normalize_config_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(mapping)
    if "hidden_layer_sizes" in out:
        out["hidden_layer_sizes"] = _normalize_hidden_layers(out["hidden_layer_sizes"])
    return out


def _resolve_manifest_path(model_path: Path, manifest_path: str | Path | None) -> Path:
    if manifest_path is not None:
        man_p = Path(manifest_path)
        if not man_p.is_file():
            raise FileNotFoundError(f"Autoencoder companion manifest not found at '{man_p}'")
        return man_p

    candidates = [
        PROJECT_ROOT / "reports" / "models" / "autoencoder_manifest.json",
        model_path.parent / "autoencoder_manifest.json",
        model_path.with_suffix(".json"),
        model_path.parent / f"{model_path.stem}_manifest.json",
        model_path.parent / "manifest.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"Autoencoder companion manifest not found for '{model_path}'.")


def _load_verified_ae_sidecar(
    manifest_dir: Path,
    model_dir: Path,
    manifest: Mapping[str, Any],
    file_key: str,
    sha_key: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    """Verify safe bare filename, existence, and SHA-256 of a mandatory sidecar JSON."""
    sidecar_name = manifest.get(file_key)
    expected_sha = manifest.get(sha_key)
    if (
        not isinstance(sidecar_name, str)
        or not sidecar_name.strip()
        or Path(sidecar_name).name != sidecar_name
    ):
        raise ValueError(f"Autoencoder manifest missing or unsafe {file_key}: {sidecar_name!r}")
    if not _is_valid_sha256(expected_sha):
        raise ValueError(f"Autoencoder manifest missing valid {sha_key}")

    sidecar_path = manifest_dir / sidecar_name
    if not sidecar_path.is_file() and model_dir != manifest_dir:
        alt_path = model_dir / sidecar_name
        if alt_path.is_file():
            sidecar_path = alt_path
    if not sidecar_path.is_file():
        raise FileNotFoundError(
            f"Autoencoder {label} sidecar referenced by {file_key} not found: '{sidecar_path}'"
        )

    actual_sha = _sha256_file(sidecar_path).lower()
    if actual_sha != str(expected_sha).strip().lower():
        raise ValueError(
            f"Autoencoder sidecar SHA-256 mismatch for {file_key}: "
            f"expected {expected_sha}, got {actual_sha}"
        )

    try:
        payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Autoencoder {label} sidecar JSON unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Autoencoder {label} sidecar payload must be a JSON object.")
    return payload, actual_sha


def _validate_ae_contract_before_deserialize(
    model_path: Path,
    manifest_path: Path,
    manifest: Mapping[str, Any],
    expected_preprocessor_sha256: str | None,
) -> tuple[float, dict[str, Any], dict[str, Any], str, str, str, str]:
    """Enforce canonical manifest, hash, config, architecture, and frozen threshold contracts."""
    if manifest.get("artifact_type") != "autoencoder-anomaly-detector":
        raise ValueError(
            f"Autoencoder manifest at '{manifest_path}' missing canonical "
            "artifact_type='autoencoder-anomaly-detector'"
        )
    if manifest.get("schema_version") != "1.0":
        raise ValueError(
            f"Unsupported Autoencoder manifest schema_version: {manifest.get('schema_version')!r}"
        )
    if "model_type" in manifest and manifest["model_type"] is not None:
        raw_mt = str(manifest["model_type"]).strip().lower()
        if raw_mt not in {
            "autoencoder",
            "autoencodermodel",
            "mlpregressor",
            "autoencoder-anomaly-detector",
        }:
            raise ValueError(
                f"Autoencoder manifest declares mismatched model_type: {manifest['model_type']!r}"
            )

    feat_contract = manifest.get("feature_contract_version")
    if feat_contract != FEATURE_CONTRACT_VERSION:
        raise ValueError(
            f"Model feature contract version '{feat_contract}' does not match "
            f"expected '{FEATURE_CONTRACT_VERSION}'"
        )

    prep_sha = manifest.get("preprocessor_sha256")
    if not _is_valid_sha256(prep_sha):
        raise ValueError("Autoencoder manifest missing required field 'preprocessor_sha256'")
    prep_sha_norm = str(prep_sha).strip().lower()
    prep_alt = manifest.get("preprocessor_artifact_sha256")
    if prep_alt is not None and (
        not _is_valid_sha256(prep_alt) or str(prep_alt).strip().lower() != prep_sha_norm
    ):
        raise ValueError(
            "Autoencoder manifest preprocessor_artifact_sha256 disagrees with preprocessor_sha256"
        )
    if expected_preprocessor_sha256 is not None and (
        not _is_valid_sha256(expected_preprocessor_sha256)
        or prep_sha_norm != expected_preprocessor_sha256.strip().lower()
    ):
        raise ValueError(
            f"Model was trained with preprocessor SHA-256 '{prep_sha_norm}', "
            f"but current preprocessor artifact has SHA-256 '{expected_preprocessor_sha256}'."
        )

    model_file_decl = manifest.get("model_file")
    if (
        not isinstance(model_file_decl, str)
        or not model_file_decl.strip()
        or Path(model_file_decl).name != model_file_decl
        or model_file_decl != model_path.name
    ):
        raise ValueError(
            f"Autoencoder manifest model_file {model_file_decl!r} does not match {model_path.name!r}"
        )

    expected_model_sha = manifest.get("model_sha256")
    if not _is_valid_sha256(expected_model_sha):
        raise ValueError("Autoencoder manifest missing required field 'model_sha256'")
    model_sha_norm = str(expected_model_sha).strip().lower()
    model_alt = manifest.get("model_artifact_sha256")
    if model_alt is not None and (
        not _is_valid_sha256(model_alt) or str(model_alt).strip().lower() != model_sha_norm
    ):
        raise ValueError("Autoencoder manifest model_artifact_sha256 disagrees with model_sha256")

    actual_model_sha = _sha256_file(model_path).lower()
    if actual_model_sha != model_sha_norm:
        raise ValueError(
            f"Model artifact SHA-256 mismatch: expected {expected_model_sha}, got {actual_model_sha}"
        )

    config_payload, config_sha = _load_verified_ae_sidecar(
        manifest_path.parent, model_path.parent, manifest, "config_file", "config_sha256", "config"
    )
    threshold_payload, threshold_sha = _load_verified_ae_sidecar(
        manifest_path.parent,
        model_path.parent,
        manifest,
        "threshold_file",
        "threshold_sha256",
        "threshold",
    )

    if not config_payload or "hidden_layer_sizes" not in config_payload:
        raise ValueError("Autoencoder config sidecar missing required hyperparameters")
    try:
        validate_config(config_payload)
    except TypeError as exc:
        raise ValueError(f"Autoencoder config sidecar invalid: {exc}") from exc

    hparams = manifest.get("hyperparameters")
    if not isinstance(hparams, dict) or not hparams:
        raise ValueError("Autoencoder manifest missing required 'hyperparameters' object")
    if _normalize_config_mapping(hparams) != _normalize_config_mapping(config_payload):
        raise ValueError(
            "Autoencoder manifest 'hyperparameters' disagrees with verified model_config.json"
        )

    arch = manifest.get("model_architecture")
    expected_dim = len(ML_FEATURE_COLUMNS)
    if not isinstance(arch, dict):
        raise ValueError("Autoencoder manifest missing required 'model_architecture' object")
    if arch.get("class") != "MLPRegressor":
        raise ValueError(
            f"Autoencoder manifest model_architecture.class must be 'MLPRegressor', got {arch.get('class')!r}"
        )
    if (
        isinstance(arch.get("input_dimension"), bool)
        or arch.get("input_dimension") != expected_dim
        or isinstance(arch.get("output_dimension"), bool)
        or arch.get("output_dimension") != expected_dim
    ):
        raise ValueError(
            f"Autoencoder manifest model_architecture dimensions must equal {expected_dim} -> {expected_dim}"
        )
    if "hidden_layer_sizes" in arch:
        if _normalize_hidden_layers(arch["hidden_layer_sizes"]) != _normalize_hidden_layers(
            config_payload["hidden_layer_sizes"]
        ):
            raise ValueError(
                "Autoencoder manifest model_architecture.hidden_layer_sizes disagrees with config"
            )

    if threshold_payload.get("threshold_frozen") is not True:
        raise ValueError(
            "Autoencoder threshold sidecar must explicitly declare threshold_frozen=True"
        )
    sidecar_th = _require_nonneg_finite(
        threshold_payload.get("threshold"), "threshold.json threshold"
    )
    manifest_th = _require_nonneg_finite(manifest.get("threshold"), "manifest threshold")
    if not math.isclose(manifest_th, sidecar_th, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError(
            f"Autoencoder manifest threshold ({manifest_th}) disagrees with "
            f"threshold.json ({sidecar_th})"
        )

    th_cal = manifest.get("threshold_calibration")
    if not isinstance(th_cal, dict) or th_cal != threshold_payload:
        raise ValueError(
            "Autoencoder manifest 'threshold_calibration' does not match verified threshold.json"
        )

    manifest_unknown = manifest.get("unknown_attack_categories")
    cal_unknown = threshold_payload.get("unknown_categories_excluded")
    if manifest_unknown is not None and cal_unknown is not None:
        if sorted(map(str, manifest_unknown)) != sorted(map(str, cal_unknown)):
            raise ValueError(
                "Autoencoder manifest unknown_attack_categories disagrees with threshold_calibration"
            )

    provenance = manifest.get("provenance")
    if isinstance(provenance, dict):
        prov_model = provenance.get("model")
        prov_cal = provenance.get("calibration")
        prov_prep = provenance.get("preprocessor")
        if isinstance(prov_model, dict):
            if prov_model.get("sha256") and str(prov_model["sha256"]).lower() != actual_model_sha:
                raise ValueError("Autoencoder provenance.model.sha256 disagrees with model_sha256")
            if (
                prov_model.get("config_sha256")
                and str(prov_model["config_sha256"]).lower() != config_sha
            ):
                raise ValueError(
                    "Autoencoder provenance.model.config_sha256 disagrees with config_sha256"
                )
        if isinstance(prov_cal, dict):
            if (
                prov_cal.get("threshold_sha256")
                and str(prov_cal["threshold_sha256"]).lower() != threshold_sha
            ):
                raise ValueError(
                    "Autoencoder provenance.calibration.threshold_sha256 disagrees with threshold_sha256"
                )
            if prov_cal.get("threshold_frozen") is False:
                raise ValueError(
                    "Autoencoder provenance.calibration.threshold_frozen must not be False"
                )
        if isinstance(prov_prep, dict):
            if (
                prov_prep.get("artifact_sha256")
                and str(prov_prep["artifact_sha256"]).lower() != prep_sha_norm
            ):
                raise ValueError(
                    "Autoencoder provenance.preprocessor.artifact_sha256 disagrees with preprocessor_sha256"
                )

    return (
        sidecar_th,
        config_payload,
        threshold_payload,
        actual_model_sha,
        prep_sha_norm,
        config_sha,
        threshold_sha,
    )


def _validate_ae_estimator(
    loaded_obj: Any,
    expected_threshold: float,
    expected_config: Mapping[str, Any],
) -> AutoencoderModel:
    """Validate deserialized Autoencoder estimator, dimensions, parameters, and threshold."""
    if isinstance(loaded_obj, AutoencoderModel):
        if not math.isclose(loaded_obj.threshold, expected_threshold, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError(
                f"Autoencoder artifact threshold ({loaded_obj.threshold}) conflicts with "
                f"threshold.json ({expected_threshold})"
            )
        estimator = loaded_obj.estimator
    elif isinstance(loaded_obj, dict) and "estimator" in loaded_obj:
        if "threshold" in loaded_obj and loaded_obj["threshold"] is not None:
            art_th = _require_nonneg_finite(loaded_obj["threshold"], "artifact threshold")
            if not math.isclose(art_th, expected_threshold, rel_tol=0.0, abs_tol=1e-12):
                raise ValueError("Autoencoder payload threshold disagrees with threshold.json")
        if "config" in loaded_obj and isinstance(loaded_obj["config"], Mapping):
            if _normalize_config_mapping(loaded_obj["config"]) != _normalize_config_mapping(
                expected_config
            ):
                raise ValueError("Autoencoder payload config disagrees with model_config.json")
        estimator = loaded_obj["estimator"]
    else:
        estimator = loaded_obj

    if not isinstance(estimator, MLPRegressor):
        raise ValueError(
            f"Autoencoder artifact must deserialize to MLPRegressor or AutoencoderModel, "
            f"got '{type(loaded_obj).__name__}'"
        )

    coefs = getattr(estimator, "coefs_", None)
    if not coefs:
        raise ValueError("Autoencoder MLPRegressor estimator is not fitted")

    expected_dim = len(ML_FEATURE_COLUMNS)
    n_in = getattr(estimator, "n_features_in_", coefs[0].shape[0])
    n_out = coefs[-1].shape[1]
    if n_in != expected_dim or coefs[0].shape[0] != expected_dim or n_out != expected_dim:
        raise ValueError(
            f"Autoencoder architecture mismatch: expected {expected_dim} -> {expected_dim}, "
            f"got {n_in} -> {n_out}"
        )

    est_params = estimator.get_params()
    for key, expected_val in expected_config.items():
        if key not in est_params:
            continue
        actual_val = est_params[key]
        if key == "hidden_layer_sizes":
            if _normalize_hidden_layers(actual_val) != _normalize_hidden_layers(expected_val):
                raise ValueError(
                    f"Autoencoder estimator hidden_layer_sizes {actual_val!r} disagrees with "
                    f"model_config.json {expected_val!r}"
                )
        elif (
            isinstance(actual_val, (int, float))
            and not isinstance(actual_val, bool)
            and isinstance(expected_val, (int, float))
            and not isinstance(expected_val, bool)
        ):
            if not math.isclose(
                float(actual_val), float(expected_val), rel_tol=1e-9, abs_tol=1e-12
            ):
                raise ValueError(
                    f"Autoencoder estimator parameter {key}={actual_val!r} disagrees with "
                    f"model_config.json {expected_val!r}"
                )
        elif actual_val != expected_val:
            raise ValueError(
                f"Autoencoder estimator parameter {key}={actual_val!r} disagrees with "
                f"model_config.json {expected_val!r}"
            )

    return AutoencoderModel(estimator, threshold=expected_threshold)


def load_verified_autoencoder_bundle(
    model_artifact_path: str | Path,
    manifest_path: str | Path | None = None,
    expected_preprocessor_sha256: str | None = None,
) -> tuple[AutoencoderModel, dict[str, Any]]:
    """Verify Autoencoder manifest, cryptographic sidecars, and deserialize frozen model."""
    model_path = Path(model_artifact_path)
    if not model_path.is_file():
        raise FileNotFoundError(f"Model artifact not found at '{model_path}'")

    man_p = _resolve_manifest_path(model_path, manifest_path)
    try:
        manifest_data = json.loads(man_p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to parse model manifest JSON at '{man_p}': {exc}") from exc
    if not isinstance(manifest_data, dict):
        raise ValueError(
            f"Model manifest JSON must be a dict/object at '{man_p}', got {type(manifest_data).__name__}"
        )

    (
        ae_threshold,
        config_payload,
        threshold_payload,
        model_sha,
        prep_sha,
        config_sha,
        threshold_sha,
    ) = _validate_ae_contract_before_deserialize(
        model_path=model_path,
        manifest_path=man_p,
        manifest=manifest_data,
        expected_preprocessor_sha256=expected_preprocessor_sha256,
    )

    try:
        loaded_obj = joblib.load(model_path)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to deserialize model artifact from '{model_path}': {exc}"
        ) from exc

    ae_model = _validate_ae_estimator(
        loaded_obj=loaded_obj,
        expected_threshold=ae_threshold,
        expected_config=config_payload,
    )

    man_sha = _sha256_file(man_p)
    model_metadata: dict[str, Any] = {
        "model_artifact_path": str(model_path),
        "model_artifact_sha256": model_sha,
        "model_manifest_path": str(man_p),
        "model_manifest_sha256": man_sha,
        "model_type": "Autoencoder",
        "run_id": manifest_data.get("run_id", "untracked"),
        "feature_contract_version": manifest_data.get("feature_contract_version"),
        "preprocessor_sha256": prep_sha,
        "class_mapping": manifest_data.get("class_mapping"),
        "hyperparameters": config_payload,
        "config_sha256": config_sha,
        "threshold": ae_threshold,
        "threshold_sha256": threshold_sha,
        "threshold_calibration": threshold_payload,
        "raw_manifest": manifest_data,
    }
    return ae_model, model_metadata
