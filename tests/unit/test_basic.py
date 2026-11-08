#!/usr/bin/env python3
"""Basic unit test — import, config, and model instantiation error guards."""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import NotFittedError

from network_anomaly import config
from network_anomaly.models.isolation_forest import build_model as build_if
from network_anomaly.models.random_forest import (
    RandomForestModel,
)
from network_anomaly.models.random_forest import (
    build_model as build_rf,
)


def test_config_exists():
    """Verify global config default random seed."""
    assert config.RANDOM_SEED == 42


def test_build_rf():
    """Verify Random Forest model initialization and unfitted error guards."""
    estimator = build_rf()
    assert isinstance(estimator, RandomForestClassifier)

    wrapper = RandomForestModel()
    assert wrapper.is_fitted is False
    assert len(wrapper.feature_names) == 47

    # Verify that an unfitted model rejects inference calls fail-closed
    X_dummy = np.zeros((5, 47))
    with pytest.raises(NotFittedError):
        estimator.predict(X_dummy)
    with pytest.raises(NotFittedError, match="not fitted yet"):
        wrapper.predict(X_dummy)
    with pytest.raises(NotFittedError, match="not fitted yet"):
        wrapper.predict_proba(X_dummy)


def test_build_isolation_forest():
    """Verify Isolation Forest model initialization and unfitted state."""
    model = build_if()
    assert model is not None
    X_dummy = np.zeros((5, 47))
    with pytest.raises(NotFittedError):
        model.predict(X_dummy)
