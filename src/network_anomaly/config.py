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

# Isolation Forest is unsupervised; the explicit parameter set below is the
# effective config recorded with every run so the estimator is reproducible.
ISOLATION_FOREST_DEFAULTS = {
    "n_estimators": 100,
    "max_samples": "auto",
    "contamination": 0.1,
    "max_features": 1.0,
    "bootstrap": False,
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
}

# Autoencoder is unsupervised representation learning (C4 / Issue #29);
# the explicit parameter set below is recorded with every run for reproducibility.
AUTOENCODER_DEFAULTS = {
    "hidden_layer_sizes": (32, 16, 32),
    "activation": "relu",
    "solver": "adam",
    "alpha": 0.0001,
    "batch_size": 256,
    "learning_rate_init": 0.001,
    "max_iter": 50,
    "early_stopping": True,
    "validation_fraction": 0.1,
    "n_iter_no_change": 5,
    "tol": 1e-4,
    "random_state": RANDOM_SEED,
}
