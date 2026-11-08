"""Unit tests for XGBoost model component structure (Issue #31 / C3).

Verifies model construction, configuration integration, interface signatures, and unfitted
error guards strictly without generating synthetic datasets, mock flows, or executing fake training.
"""

import pytest
from xgboost import XGBClassifier
from sklearn.exceptions import NotFittedError

from network_anomaly.config import RANDOM_SEED
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.models.xgboost_model import (
    XGBoostModel,
    build_model,
)
from network_anomaly.models.xgboost_protocol import (
    XGBoostBaselineConfig,
    XGBoostBaselineProtocol,
    create_xgb_baseline_protocol,
)
from network_anomaly.models.random_forest import RandomForestModel


def test_xgb_model_default_initialization():
    """Verify XGBoostModel structure and configuration when initialized with defaults."""
    model = XGBoostModel()

    assert model.model_type == "XGBoost"
    assert model.task == "binary_classification"
    assert model.target == "Label"
    assert model.positive_class == "Attack"
    assert model.random_state == RANDOM_SEED

    assert model.feature_names == ML_FEATURE_COLUMNS
    assert len(model.feature_names) == 47

    assert model.is_fitted is False
    assert isinstance(model.estimator, XGBClassifier)
    assert model.estimator.n_estimators == 200
    assert model.estimator.max_depth == 6
    assert model.estimator.random_state == RANDOM_SEED


def test_xgb_model_initialization_with_config():
    """Verify XGBoostModel accepts custom XGBoostBaselineConfig."""
    cfg = XGBoostBaselineConfig(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.05,
        random_state=99,
        is_canonical_baseline=False,
        configuration_id="xgb-custom-test",
    )
    model = XGBoostModel(config=cfg)

    assert model.config.n_estimators == 100
    assert model.config.max_depth == 4
    assert model.random_state == 99
    assert model.estimator.n_estimators == 100
    assert model.estimator.max_depth == 4


def test_xgb_model_initialization_with_protocol():
    """Verify XGBoostModel attaches to protocol correctly."""
    protocol = create_xgb_baseline_protocol(
        random_seed=123,
        n_estimators=150,
        max_depth=5,
        is_canonical=False,
        configuration_id="xgb-custom-proto",
    )
    model = XGBoostModel(protocol=protocol)

    assert model.protocol is protocol
    assert model.config == protocol.model_config
    assert model.feature_names == tuple(protocol.selected_features)


def test_xgb_model_unfitted_guards():
    """Verify predict and predict_proba raise NotFittedError before fitting."""
    model = XGBoostModel()
    dummy_input = [[0.0] * 47]

    with pytest.raises(NotFittedError, match="not fitted yet"):
        model.predict(dummy_input)

    with pytest.raises(NotFittedError, match="not fitted yet"):
        model.predict_proba(dummy_input)

    with pytest.raises(NotFittedError, match="Cannot save an unfitted"):
        model.save("non_existent_path.joblib")


def test_xgb_model_shares_interface_with_rf_model():
    """Verify XGBoostModel and RandomForestModel expose the same public methods and properties."""
    rf_model = RandomForestModel()
    xgb_model = XGBoostModel()

    expected_attrs = [
        "model_type",
        "task",
        "target",
        "positive_class",
        "random_state",
        "feature_names",
        "is_fitted",
        "build_model",
        "fit",
        "predict",
        "predict_proba",
        "save",
        "load",
        "load_verified",
    ]

    for attr in expected_attrs:
        assert hasattr(rf_model, attr), f"RandomForestModel missing {attr}"
        assert hasattr(xgb_model, attr), f"XGBoostModel missing {attr}"
