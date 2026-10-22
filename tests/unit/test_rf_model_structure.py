"""Unit tests for Random Forest model component structure (Issue #10).

Verifies model construction, configuration integration, interface signatures, and unfitted
error guards strictly without generating synthetic datasets, mock flows, or executing fake training.
"""

import inspect

import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import NotFittedError

from network_anomaly.config import RANDOM_SEED
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.models.random_forest import (
    RandomForestBaselineConfig,
    RandomForestBaselineProtocol,
    RandomForestModel,
    build_model,
    create_rf_baseline_protocol,
)


def test_rf_model_default_initialization():
    """Verify RandomForestModel structure and configuration when initialized with defaults."""
    model = RandomForestModel()

    # Metadata and task specification
    assert model.model_type == "RandomForest"
    assert model.task == "binary_classification"
    assert model.target == "Label"
    assert model.positive_class == "Attack"
    assert model.random_state == RANDOM_SEED

    # Feature names default to the 47-feature baseline
    assert model.feature_names == ML_FEATURE_COLUMNS
    assert len(model.feature_names) == 47

    # Fitted state starts as False
    assert model.is_fitted is False

    # Underlying estimator construction
    assert isinstance(model.estimator, RandomForestClassifier)
    assert model.estimator.n_estimators == 200
    assert model.estimator.max_depth == 16
    assert model.estimator.criterion == "gini"
    assert model.estimator.random_state == RANDOM_SEED
    assert model.estimator.n_jobs == -1


def test_rf_model_initialization_with_config():
    """Verify RandomForestModel accepts custom RandomForestBaselineConfig."""
    cfg = RandomForestBaselineConfig(
        n_estimators=100,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=99,
    )
    model = RandomForestModel(config=cfg)

    assert model.config.n_estimators == 100
    assert model.config.max_depth == 12
    assert model.random_state == 99
    assert model.estimator.n_estimators == 100
    assert model.estimator.max_depth == 12
    assert model.estimator.random_state == 99


def test_rf_model_initialization_with_protocol():
    """Verify RandomForestModel attaches to Issue #9 protocol."""
    protocol = create_rf_baseline_protocol(
        split_id="nf-unsw-nb15-v3-temporal-group-v1",
        random_seed=123,
        n_estimators=150,
        max_depth=10,
    )
    model = RandomForestModel(protocol=protocol)

    assert model.protocol is protocol
    assert model.config == protocol.model_config
    assert model.feature_names == protocol.selected_features
    assert model.estimator.n_estimators == 150
    assert model.estimator.max_depth == 10
    assert model.estimator.random_state == 123


def test_rf_model_initialization_with_dict():
    """Verify RandomForestModel accepts a dictionary config."""
    cfg_dict = {"n_estimators": 50, "max_depth": 6, "random_state": 77}
    model = RandomForestModel(config=cfg_dict)

    assert model.config.n_estimators == 50
    assert model.config.max_depth == 6
    assert model.estimator.n_estimators == 50
    assert model.estimator.max_depth == 6


def test_rf_model_rejection_of_invalid_config_type():
    """Verify error on unsupported configuration type."""
    with pytest.raises(TypeError, match="Unsupported config type"):
        RandomForestModel(config="invalid_config_string")


def test_rf_model_unfitted_guard():
    """Verify NotFittedError is raised when predicting before fit.

    Does NOT use mock training data. Confirms safety guards when unfitted.
    """
    model = RandomForestModel()
    assert model.is_fitted is False

    with pytest.raises(NotFittedError, match="not fitted yet"):
        model.predict([[0] * 47])

    with pytest.raises(NotFittedError, match="not fitted yet"):
        model.predict_proba([[0] * 47])


def test_rf_model_interface_signatures():
    """Verify standard interfaces exist with correct method signatures.

    Confirms interfaces are ready for Issue #10 training pipeline without executing fit().
    """
    model = RandomForestModel()

    # Check callability
    assert callable(model.build_model)
    assert callable(model.fit)
    assert callable(model.predict)
    assert callable(model.predict_proba)

    # Inspect fit signature: must accept (X, y, **fit_params)
    fit_sig = inspect.signature(model.fit)
    params = list(fit_sig.parameters.keys())
    assert "X" in params
    assert "y" in params

    # Inspect predict signature: must accept (X)
    predict_sig = inspect.signature(model.predict)
    assert "X" in list(predict_sig.parameters.keys())

    # Inspect predict_proba signature: must accept (X)
    predict_proba_sig = inspect.signature(model.predict_proba)
    assert "X" in list(predict_proba_sig.parameters.keys())
