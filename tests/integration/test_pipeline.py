#!/usr/bin/env python3
"""Integration test — inference pipeline components load together (constructor-only smoke check)."""
from network_anomaly.inference.pipeline import ARTIFACTS, predict_from_artifact
from network_anomaly.models.isolation_forest import build_model


def test_isolation_forest_load():
    m = build_model()
    assert m is not None


def test_inference_module_resolves_artifact_location():
    assert ARTIFACTS.name == "artifacts"
    assert callable(predict_from_artifact)
