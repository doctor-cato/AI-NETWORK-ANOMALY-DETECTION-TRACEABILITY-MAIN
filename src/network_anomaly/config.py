"""Configuration for network anomaly detection project."""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_RAW = PROJECT_ROOT / "data" / "raw"
DATA_PROCESSED = PROJECT_ROOT / "data" / "processed"
ARTIFACTS = PROJECT_ROOT / "artifacts"

RANDOM_SEED = 42

# Hyperparameters (defaults — update with experiment tracking)
RANDOM_FOREST_DEFAULTS = {
    "n_estimators": 200,
    "max_depth": 16,
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
}

ISOLATION_FOREST_DEFAULTS = {
    "n_estimators": 100,
    "contamination": 0.1,
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
}
