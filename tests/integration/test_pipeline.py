#!/usr/bin/env python3
"""Integration test — pipeline components load together."""
from network_anomaly.config import DATA_RAW
from network_anomaly.models.isolation_forest import build_model

def test_isolation_forest_load():
    m = build_model()
    assert m is not None
