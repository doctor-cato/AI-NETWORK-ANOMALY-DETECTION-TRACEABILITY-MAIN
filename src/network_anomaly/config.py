"""Configuration for network anomaly detection project."""

import os
import sys
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent.parent


def _is_valid_project_root(candidate: Path) -> bool:
    """Return True if `candidate` is a source repo root or standalone resource root."""
    if (candidate / "src" / "network_anomaly").is_dir():
        return True
    return (candidate / "reports" / "models").is_dir() and (
        (candidate / "artifacts").is_dir() or (candidate / "data").is_dir()
    )


def resolve_project_root() -> Path:
    """Resolve code/manifest root, honoring env overrides and PyInstaller frozen bundles."""
    for env_key in ("NETWORK_ANOMALY_REPO_ROOT", "NETWORK_ANOMALY_RESOURCE_DIR"):
        explicit = os.environ.get(env_key, "").strip()
        if explicit:
            candidate = Path(explicit).expanduser().resolve()
            if _is_valid_project_root(candidate):
                return candidate

    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates = [exe_dir, exe_dir / "_up_" / "_up_"]
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass).resolve())
        for candidate in candidates:
            if _is_valid_project_root(candidate):
                return candidate
        return exe_dir

    return _PACKAGE_ROOT


PROJECT_ROOT = resolve_project_root()
DATA_RAW = PROJECT_ROOT / "data" / "raw"
DATA_PROCESSED = PROJECT_ROOT / "data" / "processed"
ARTIFACTS = PROJECT_ROOT / "artifacts"


def _has_populated_artifacts(artifacts_dir: Path) -> bool:
    """Return True when an artifacts directory contains preprocessor or model binaries."""
    prep_file = artifacts_dir / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    legacy_prep = artifacts_dir / "preprocessor.joblib"
    if prep_file.is_file() or legacy_prep.is_file():
        return True
    models_dir = artifacts_dir / "models"
    return models_dir.is_dir() and any(models_dir.rglob("*.joblib"))


def get_runtime_root() -> Path:
    """Return writable per-user runtime root for SQLite DB, logs, and user exports."""
    explicit = os.environ.get("NETWORK_ANOMALY_RUNTIME_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app_data and (getattr(sys, "frozen", False) or not (PROJECT_ROOT / ".git").exists()):
        return Path(local_app_data).expanduser().resolve() / "NetFlowSentinel"
    return PROJECT_ROOT


def resolve_artifacts_dir() -> Path:
    """Resolve the active artifacts directory (env override -> bundled/repo artifacts -> runtime dir)."""
    explicit = os.environ.get("NETWORK_ANOMALY_ARTIFACTS_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    repo_artifacts = PROJECT_ROOT / "artifacts"
    if _has_populated_artifacts(repo_artifacts):
        return repo_artifacts
    runtime_artifacts = get_runtime_root() / "artifacts"
    if _has_populated_artifacts(runtime_artifacts) or not (PROJECT_ROOT / ".git").exists():
        return runtime_artifacts
    return repo_artifacts


def resolve_demo_dir() -> Path:
    """Resolve the active demo CSV directory (env override -> bundled/repo data/demo -> runtime dir)."""
    explicit = os.environ.get("NETWORK_ANOMALY_DEMO_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    repo_demo = PROJECT_ROOT / "data" / "demo"
    if (repo_demo / "demo_flows.csv").is_file():
        return repo_demo
    runtime_demo = get_runtime_root() / "data" / "demo"
    if (runtime_demo / "demo_flows.csv").is_file() or not (PROJECT_ROOT / ".git").exists():
        return runtime_demo
    return repo_demo


def resolve_default_db_path() -> Path:
    """Resolve default SQLite DB path in writable runtime root (or repo data/ in git checkout)."""
    runtime_root = get_runtime_root()
    if runtime_root != PROJECT_ROOT:
        return runtime_root / "network_anomaly.db"
    return PROJECT_ROOT / "data" / "network_anomaly.db"


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

# XGBoost defaults — consistent with Random Forest supervised protocol (Issue #31 / C3).
# use_label_encoder=False: suppressed since XGBoost >= 1.6 deprecates this param.
# eval_metric set explicitly to avoid warning; binary classification uses 'logloss'.
# tree_method='hist' is the recommended default for CPU training (XGBoost >= 2.0).
# n_jobs=-1 mirrors Random Forest convention.
# Multiclass target: override objective to 'multi:softprob' and set num_class accordingly.
XGBOOST_DEFAULTS = {
    "n_estimators": 200,
    "max_depth": 6,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "tree_method": "hist",
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
