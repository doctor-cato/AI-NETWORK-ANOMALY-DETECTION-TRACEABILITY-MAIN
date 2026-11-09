#!/usr/bin/env python3
"""Unit tests — Autoencoder model component (Issue #29 / C4).

Synthetic fixtures only. These tests verify hyperparameters, validation logic,
input guards, score directions, deterministic execution, and the unsupervised
contract of the Autoencoder.
"""

import numpy as np
import pandas as pd
import pytest
from sklearn.neural_network import MLPRegressor

from network_anomaly import config
from network_anomaly.models.autoencoder import (
    anomaly_scores,
    build_model,
    fit_model,
    predict,
    reconstruct,
    reconstruction_errors,
    validate_config,
    validate_features,
)


@pytest.fixture
def synthetic_matrix():
    """Small deterministic fixture: normal cluster + 1 extreme anomaly."""
    rng = np.random.default_rng(42)
    normal = rng.normal(loc=0.0, scale=0.1, size=(200, 5))
    outlier = np.array([[15.0, -15.0, 15.0, -15.0, 15.0]])
    return np.vstack([normal, outlier]), len(normal)


# --- Construction & Defaults ---------------------------------------------------


def test_build_model_returns_mlp_regressor():
    model = build_model()
    assert isinstance(model, MLPRegressor)


def test_build_model_uses_documented_defaults():
    model = build_model()
    for name, expected in config.AUTOENCODER_DEFAULTS.items():
        assert getattr(model, name) == expected


def test_build_model_sets_random_state_explicitly():
    model = build_model()
    assert model.random_state == config.RANDOM_SEED
    assert model.random_state is not None


def test_build_model_merges_partial_config_over_defaults():
    model = build_model({"max_iter": 10, "alpha": 0.01})
    assert model.max_iter == 10
    assert model.alpha == 0.01
    assert model.random_state == config.RANDOM_SEED
    assert model.hidden_layer_sizes == config.AUTOENCODER_DEFAULTS["hidden_layer_sizes"]


def test_build_model_accepts_overrides():
    model = build_model(max_iter=15, learning_rate_init=0.005)
    assert model.max_iter == 15
    assert model.learning_rate_init == 0.005


def test_build_model_normalizes_hidden_layers():
    model = build_model(hidden_layer_sizes=64)
    assert model.hidden_layer_sizes == (64,)

    model2 = build_model(hidden_layer_sizes=[32, 16, 32])
    assert model2.hidden_layer_sizes == (32, 16, 32)


# --- Hyperparameter Validation -------------------------------------------------


def test_validate_config_rejects_non_mapping():
    with pytest.raises(TypeError, match="must be a mapping"):
        validate_config(["not", "a", "mapping"])  # type: ignore


def test_validate_config_rejects_unknown_param():
    with pytest.raises(TypeError, match="Unsupported Autoencoder parameter"):
        validate_config({"invalid_param": 123})


def test_validate_config_rejects_invalid_hidden_layers():
    with pytest.raises(ValueError, match="at least one layer"):
        validate_config({"hidden_layer_sizes": ()})
    with pytest.raises(ValueError, match="must be an integer >= 1"):
        validate_config({"hidden_layer_sizes": (32, 0, 16)})
    with pytest.raises(TypeError, match="must be a tuple/list"):
        validate_config({"hidden_layer_sizes": "32,16"})


def test_validate_config_rejects_invalid_activation():
    with pytest.raises(ValueError, match="activation must be one of"):
        validate_config({"activation": "sigmoid_custom"})


def test_validate_config_rejects_invalid_solver():
    with pytest.raises(ValueError, match="solver must be one of"):
        validate_config({"solver": "custom_solver"})


def test_validate_config_rejects_invalid_alpha():
    with pytest.raises(ValueError, match="alpha must be >= 0.0"):
        validate_config({"alpha": -0.5})
    with pytest.raises(TypeError, match="alpha must be a non-negative float"):
        validate_config({"alpha": "low"})


def test_validate_config_rejects_invalid_batch_size():
    with pytest.raises(ValueError, match="batch_size must be 'auto' or a positive integer"):
        validate_config({"batch_size": 0})
    with pytest.raises(ValueError, match="batch_size must be 'auto' or a positive integer"):
        validate_config({"batch_size": "all"})


def test_validate_config_rejects_invalid_learning_rate():
    with pytest.raises(ValueError, match="learning_rate_init must be > 0.0"):
        validate_config({"learning_rate_init": 0.0})
    with pytest.raises(ValueError, match="learning_rate_init must be > 0.0"):
        validate_config({"learning_rate_init": -0.01})


def test_validate_config_rejects_invalid_max_iter():
    with pytest.raises(ValueError, match="max_iter must be an integer >= 1"):
        validate_config({"max_iter": 0})


def test_validate_config_rejects_invalid_random_state():
    with pytest.raises(ValueError, match="explicit integer seed"):
        validate_config({"random_state": None})
    with pytest.raises(ValueError, match="explicit integer seed"):
        validate_config({"random_state": "seed_42"})


# --- Input Feature Validation --------------------------------------------------


def test_validate_features_rejects_none():
    with pytest.raises(TypeError, match="Feature matrix X is required"):
        validate_features(None)


def test_validate_features_rejects_1d():
    with pytest.raises(ValueError, match="Feature matrix must be 2-D"):
        validate_features(np.array([1.0, 2.0, 3.0]))


def test_validate_features_rejects_empty():
    with pytest.raises(ValueError, match="at least one sample"):
        validate_features(np.empty((0, 5)))
    with pytest.raises(ValueError, match="at least one feature"):
        validate_features(np.empty((5, 0)))


def test_validate_features_rejects_expected_dim_mismatch():
    with pytest.raises(ValueError, match="dimension mismatch"):
        validate_features(np.ones((10, 5)), expected_dim=47)


def test_validate_features_rejects_nan_and_inf():
    nan_arr = np.array([[1.0, 2.0], [np.nan, 4.0]])
    with pytest.raises(ValueError, match="contains NaN or infinite values"):
        validate_features(nan_arr)

    inf_arr = np.array([[1.0, np.inf], [3.0, 4.0]])
    with pytest.raises(ValueError, match="contains NaN or infinite values"):
        validate_features(inf_arr)


def test_validate_features_rejects_complex():
    complex_arr = np.array([[1.0 + 1.0j, 2.0]])
    with pytest.raises(TypeError, match="must not be complex-valued"):
        validate_features(complex_arr)

    df_complex = pd.DataFrame({"a": [1.0 + 2.0j], "b": [3.0]})
    with pytest.raises(TypeError, match="complex-valued columns"):
        validate_features(df_complex)


def test_validate_features_rejects_non_numeric_dataframe():
    df_str = pd.DataFrame({"a": [1.0, 2.0], "b": ["normal", "attack"]})
    with pytest.raises(TypeError, match="numeric columns only"):
        validate_features(df_str)

    df_bool = pd.DataFrame({"a": [True, False], "b": [1.0, 2.0]})
    with pytest.raises(TypeError, match="numeric columns only"):
        validate_features(df_bool)


# --- Fitting and Anomaly Scoring ------------------------------------------------


def test_fit_and_reconstruct_shape(synthetic_matrix):
    X, _ = synthetic_matrix
    model = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=20, random_state=42)
    fit_model(model, X)

    X_hat = reconstruct(model, X)
    assert X_hat.shape == X.shape


def test_reconstruction_errors_shape_and_type(synthetic_matrix):
    X, _ = synthetic_matrix
    model = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=20, random_state=42)
    fit_model(model, X)

    errors = reconstruction_errors(model, X)
    assert isinstance(errors, np.ndarray)
    assert errors.shape == (len(X),)
    assert errors.dtype == np.float64
    assert np.all(errors >= 0.0)


def test_anomaly_score_direction(synthetic_matrix):
    """An outlier should have significantly higher reconstruction error than normal data."""
    X, normal_count = synthetic_matrix
    normal_data = X[:normal_count]
    outlier = X[normal_count:]

    # Train only on normal data
    model = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=30, random_state=42)
    fit_model(model, normal_data)

    normal_scores = anomaly_scores(model, normal_data)
    outlier_score = anomaly_scores(model, outlier)[0]

    # Outlier error must be substantially higher than average normal error
    assert outlier_score > np.mean(normal_scores) * 5.0
    assert outlier_score > np.max(normal_scores)


def test_predict_binary_decisions(synthetic_matrix):
    X, normal_count = synthetic_matrix
    normal_data = X[:normal_count]
    model = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=30, random_state=42)
    fit_model(model, normal_data)

    errors = reconstruction_errors(model, normal_data)
    threshold = float(np.percentile(errors, 95))

    preds = predict(model, X, threshold=threshold)
    assert preds.shape == (len(X),)
    assert set(np.unique(preds)).issubset({0, 1})
    # The extreme outlier must be predicted as 1 (anomaly)
    assert preds[-1] == 1


def test_predict_rejects_invalid_threshold(synthetic_matrix):
    X, _ = synthetic_matrix
    model = build_model(max_iter=5)
    fit_model(model, X)

    with pytest.raises(TypeError, match="threshold must be a real number"):
        predict(model, X, threshold="high")  # type: ignore

    with pytest.raises(ValueError, match="threshold must be finite"):
        predict(model, X, threshold=np.nan)

    with pytest.raises(ValueError, match="threshold must be non-negative"):
        predict(model, X, threshold=-0.01)


def test_deterministic_execution_with_seed(synthetic_matrix):
    X, _ = synthetic_matrix
    model1 = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=20, random_state=42)
    model2 = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=20, random_state=42)

    fit_model(model1, X)
    fit_model(model2, X)

    err1 = reconstruction_errors(model1, X)
    err2 = reconstruction_errors(model2, X)

    np.testing.assert_allclose(err1, err2, rtol=1e-5, atol=1e-5)
