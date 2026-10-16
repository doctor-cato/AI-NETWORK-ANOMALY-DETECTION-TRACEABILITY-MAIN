#!/usr/bin/env python3
"""Basic unit test — import and config."""
from network_anomaly import config
from network_anomaly.models.random_forest import build_model


def test_config_exists():
    assert config.RANDOM_SEED == 42


def test_build_rf():
    model = build_model()
    assert model is not None
