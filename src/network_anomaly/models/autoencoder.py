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

import numbers
from collections.abc import Mapping
from typing import Any

import numpy as np
from sklearn.neural_network import MLPRegressor

from network_anomaly.config import AUTOENCODER_DEFAULTS

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

    scores = reconstruction_errors(model, X)
    return (scores >= threshold).astype(np.int64)
