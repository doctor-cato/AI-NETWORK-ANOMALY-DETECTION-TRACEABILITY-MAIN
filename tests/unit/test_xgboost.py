#!/usr/bin/env python3
"""Unit tests for XGBoost model — Issue #31 / C3.

Tests in this file are data-free: they verify import, config, and constructor
behaviour only.  No training or inference is performed, and no synthetic records
are generated.

Training/evaluation tests are BLOCKED until:
  - UNSW-NB15 CSV files are present in data/raw/ (verified via MANIFEST sha256).
  - C1 leakage audit and C2 preprocessing pipeline are complete and verified.

Status progression expected:
  IMPLEMENTED  →  TESTED (this file)  →  EXPERIMENTALLY VALIDATED (after real data run).
"""

import copy

import pytest


# ---------------------------------------------------------------------------
# Import and dependency tests
# ---------------------------------------------------------------------------


def test_xgboost_package_importable():
    """xgboost must be installed and importable (dependency check)."""
    import xgboost  # noqa: F401


def test_xgboost_classifier_importable():
    """XGBClassifier must be importable from xgboost."""
    from xgboost import XGBClassifier  # noqa: F401


def test_xgboost_model_module_importable():
    """The project module must import without error."""
    import network_anomaly.models.xgboost_model  # noqa: F401


def test_build_model_importable():
    """build_model function must be importable from the module."""
    from network_anomaly.models.xgboost_model import build_model  # noqa: F401


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------


def test_xgboost_defaults_in_config():
    """XGBOOST_DEFAULTS must be present in config and be a non-empty dict."""
    from network_anomaly.config import XGBOOST_DEFAULTS

    assert isinstance(XGBOOST_DEFAULTS, dict), "XGBOOST_DEFAULTS must be a dict"
    assert len(XGBOOST_DEFAULTS) > 0, "XGBOOST_DEFAULTS must not be empty"


def test_xgboost_defaults_required_keys():
    """XGBOOST_DEFAULTS must contain the required hyperparameter keys."""
    from network_anomaly.config import XGBOOST_DEFAULTS

    required_keys = {
        "n_estimators",
        "max_depth",
        "learning_rate",
        "random_state",
        "objective",
        "eval_metric",
    }
    missing = required_keys - set(XGBOOST_DEFAULTS.keys())
    assert not missing, f"XGBOOST_DEFAULTS is missing keys: {missing}"


def test_xgboost_defaults_random_seed_matches_project():
    """XGBOOST_DEFAULTS['random_state'] must equal config.RANDOM_SEED."""
    from network_anomaly.config import RANDOM_SEED, XGBOOST_DEFAULTS

    assert XGBOOST_DEFAULTS["random_state"] == RANDOM_SEED


def test_xgboost_defaults_default_objective_binary():
    """Default objective must be binary:logistic (binary classification)."""
    from network_anomaly.config import XGBOOST_DEFAULTS

    assert XGBOOST_DEFAULTS["objective"] == "binary:logistic"


# ---------------------------------------------------------------------------
# Constructor tests
# ---------------------------------------------------------------------------


def test_build_model_returns_non_none():
    """build_model() must return a non-None object."""
    from network_anomaly.models.xgboost_model import build_model

    model = build_model()
    assert model is not None


def test_build_model_returns_xgb_classifier():
    """build_model() must return an XGBClassifier instance."""
    from xgboost import XGBClassifier

    from network_anomaly.models.xgboost_model import build_model

    model = build_model()
    assert isinstance(model, XGBClassifier)


def test_build_model_default_config_applied():
    """build_model() with no arguments must apply XGBOOST_DEFAULTS."""
    from network_anomaly.config import XGBOOST_DEFAULTS
    from network_anomaly.models.xgboost_model import build_model

    model = build_model()
    params = model.get_params()
    assert params["n_estimators"] == XGBOOST_DEFAULTS["n_estimators"]
    assert params["max_depth"] == XGBOOST_DEFAULTS["max_depth"]
    assert params["learning_rate"] == XGBOOST_DEFAULTS["learning_rate"]


def test_build_model_custom_config():
    """build_model() must apply a custom config dict correctly."""
    from network_anomaly.models.xgboost_model import build_model

    custom = {
        "n_estimators": 50,
        "max_depth": 3,
        "learning_rate": 0.05,
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "random_state": 42,
        "n_jobs": 1,
    }
    model = build_model(config=custom)
    params = model.get_params()
    assert params["n_estimators"] == 50
    assert params["max_depth"] == 3


def test_build_model_does_not_mutate_defaults():
    """build_model() must not mutate XGBOOST_DEFAULTS."""
    from network_anomaly.config import XGBOOST_DEFAULTS
    from network_anomaly.models.xgboost_model import build_model

    original = copy.deepcopy(XGBOOST_DEFAULTS)
    build_model()
    assert XGBOOST_DEFAULTS == original, "build_model() must not mutate XGBOOST_DEFAULTS"


def test_build_model_does_not_mutate_caller_config():
    """build_model() must not mutate the caller-supplied config dict."""
    from network_anomaly.models.xgboost_model import build_model

    cfg = {
        "n_estimators": 10,
        "max_depth": 2,
        "learning_rate": 0.1,
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "random_state": 42,
        "n_jobs": 1,
    }
    original = copy.deepcopy(cfg)
    build_model(config=cfg)
    assert cfg == original, "build_model() must not mutate the caller-supplied config dict"


def test_build_model_independent_instances():
    """Two calls to build_model() must return independent objects."""
    from network_anomaly.models.xgboost_model import build_model

    m1 = build_model()
    m2 = build_model()
    assert m1 is not m2


# ---------------------------------------------------------------------------
# Schema contract tests
# ---------------------------------------------------------------------------


def test_xgboost_and_random_forest_share_build_model_interface():
    """Both xgboost_model and random_forest must expose a callable build_model(config=None)."""
    import inspect

    from network_anomaly.models import random_forest, xgboost_model

    for module in (random_forest, xgboost_model):
        assert hasattr(module, "build_model"), f"{module.__name__} missing build_model"
        sig = inspect.signature(module.build_model)
        params = list(sig.parameters)
        assert "config" in params, f"{module.__name__}.build_model must accept 'config'"


def test_xgboost_model_not_fit_at_construction():
    """A freshly built XGBClassifier must not be fitted (no booster_ attribute)."""
    from network_anomaly.models.xgboost_model import build_model

    model = build_model()
    # XGBoost sets internal booster after fit(); should not exist on fresh instance
    assert not hasattr(model, "get_booster") or _booster_not_fitted(model)


def _booster_not_fitted(model):
    """Return True if the model has not been fitted yet."""
    try:
        model.get_booster()
        return False  # booster exists — model was fitted
    except Exception:
        return True  # expected: no booster before fit


# ---------------------------------------------------------------------------
# Training/evaluation: BLOCKED
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason=(
        "BLOCKED — training requires UNSW-NB15 CSV in data/raw/ (verified by MANIFEST sha256), "
        "C1 leakage audit passed, and C2 preprocessing pipeline implemented. "
        "Do not run until all preconditions are met."
    )
)
def test_xgboost_train_and_evaluate_on_real_data():
    """Placeholder: train XGBoost and compute metrics on real UNSW-NB15 split.

    Preconditions (all must be met before un-skipping):
      1. data/raw/UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv present.
      2. SHA-256 verified against data/UNSW_NB15_MANIFEST.json.
      3. C1 leakage audit complete (group/near-duplicate overlap reviewed).
      4. C2 preprocessing pipeline implemented and fit boundary confirmed.
      5. Split performed BEFORE any preprocessing fit.
      6. Target column confirmed: 'label' (binary) or 'attack_cat' (multiclass).

    When unblocked, this test must record:
      - run_id, issue, commit/worktree, dataset sha256, split seed, feature schema,
        target/label mapping, preprocessing config, model config, dependency versions,
        command, artifact hash, and real metrics (Precision/Recall/F1/Macro-F1/FPR).
    """
    raise NotImplementedError("BLOCKED — see skip reason above.")
