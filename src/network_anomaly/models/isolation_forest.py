"""Isolation Forest unsupervised anomaly detection.

Note: evaluation protocol differs from supervised Random Forest.
Score-based threshold selection must be documented separately.
"""
from sklearn.ensemble import IsolationForest
from network_anomaly.config import ISOLATION_FOREST_DEFAULTS


def build_model(config=None):
    cfg = config or ISOLATION_FOREST_DEFAULTS.copy()
    return IsolationForest(**cfg)
