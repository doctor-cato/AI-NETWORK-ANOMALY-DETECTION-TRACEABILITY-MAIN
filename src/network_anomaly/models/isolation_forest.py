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
import numbers
from collections.abc import Mapping

import numpy as np
from sklearn.ensemble import IsolationForest

from network_anomaly.config import ISOLATION_FOREST_DEFAULTS

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
            raise ValueError(
                f"contamination must be 'auto' or a float in (0, 0.5], got {value!r}"
            )
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
    raise ValueError(
        f"max_features must be an integer >= 1 or a float in (0, 1], got {value!r}"
    )


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
            raise ValueError(
                f"Feature matrix must be 2-D, got {X.ndim}-D DataFrame"
            )
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
            raise TypeError(
                f"Feature matrix must be numeric, got dtype {array.dtype}"
            )
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
    """
    validate_features(X)
    return -np.asarray(model.decision_function(X))
