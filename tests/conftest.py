"""Shared test fixtures for live telemetry and v2 inference tests.

The baseline row is a heterogeneous 18-feature canonical-flow-v2-18 fixture built
directly from observed base telemetry fields via ``compute_flow_features_from_base``.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS, compute_flow_features_from_base

BASELINE_FEATURES: Dict[str, float] = compute_flow_features_from_base(
    duration_ms=34.0,
    bytes_in=1580.0,
    bytes_out=2260.0,
    pkts_in=16.0,
    pkts_out=18.0,
    protocol_num=6,
)

assert set(BASELINE_FEATURES) == set(
    ML_FEATURE_COLUMNS
), "baseline fixture must cover exactly the 18 contract features"


@pytest.fixture
def baseline_features():
    """Return a factory producing a full 18-feature row with optional overrides."""

    def _make(**overrides: Any) -> Dict[str, float]:
        row = dict(BASELINE_FEATURES)
        row.update({name: float(value) for name, value in overrides.items()})
        return row

    return _make


@pytest.fixture
def real_artifacts_available() -> bool:
    """True when the v2 preprocessor and all four model artifacts exist locally."""
    from pathlib import Path

    from network_anomaly.config import resolve_artifacts_dir

    artifacts = resolve_artifacts_dir()
    required = [
        artifacts / "preprocessing" / "v2_flow_preprocessor.joblib",
        artifacts / "models" / "random_forest" / "random_forest_baseline.joblib",
        artifacts / "models" / "xgboost" / "xgboost_baseline.joblib",
        artifacts / "models" / "isolation_forest" / "isolation_forest.joblib",
        artifacts / "models" / "autoencoder" / "autoencoder_model.joblib",
    ]
    return all(Path(path).is_file() for path in required)
