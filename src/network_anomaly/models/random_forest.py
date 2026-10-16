"""Random Forest supervised model."""
from sklearn.ensemble import RandomForestClassifier
from network_anomaly.config import RANDOM_FOREST_DEFAULTS


def build_model(config=None):
    cfg = config or RANDOM_FOREST_DEFAULTS.copy()
    return RandomForestClassifier(**cfg)
