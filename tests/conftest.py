"""Shared test fixtures for live telemetry and inference tests.

The baseline row is a synthetic but *heterogeneous* 47-feature fixture built from
column medians of a 200k-row sample of NF-UNSW-NB15-v3. It exists so tests never
fill all 47 model features with one repeated value, which would silently defeat
the feature contract.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS

BASELINE_FEATURES: Dict[str, float] = {
    "PROTOCOL": 6.0,
    "L7_PROTO": 36.0,
    "IN_BYTES": 1580.0,
    "IN_PKTS": 16.0,
    "OUT_BYTES": 2260.0,
    "OUT_PKTS": 18.0,
    "TCP_FLAGS": 27.0,
    "CLIENT_TCP_FLAGS": 24.0,
    "SERVER_TCP_FLAGS": 24.0,
    "FLOW_DURATION_MILLISECONDS": 34.0,
    "DURATION_IN": 31.0,
    "DURATION_OUT": 31.0,
    "MIN_TTL": 31.0,
    "MAX_TTL": 32.0,
    "LONGEST_FLOW_PKT": 362.0,
    "SHORTEST_FLOW_PKT": 52.0,
    "MIN_IP_PKT_LEN": 52.0,
    "MAX_IP_PKT_LEN": 362.0,
    "SRC_TO_DST_SECOND_BYTES": 162.0,
    "DST_TO_SRC_SECOND_BYTES": 81.35,
    "RETRANSMITTED_IN_BYTES": 436.0,
    "RETRANSMITTED_IN_PKTS": 4.0,
    "RETRANSMITTED_OUT_BYTES": 793.0,
    "RETRANSMITTED_OUT_PKTS": 4.0,
    "SRC_TO_DST_AVG_THROUGHPUT": 520000.0,
    "DST_TO_SRC_AVG_THROUGHPUT": 656000.0,
    "NUM_PKTS_UP_TO_128_BYTES": 30.0,
    "NUM_PKTS_128_TO_256_BYTES": 0.0,
    "NUM_PKTS_256_TO_512_BYTES": 0.0,
    "NUM_PKTS_512_TO_1024_BYTES": 0.0,
    "NUM_PKTS_1024_TO_1514_BYTES": 0.0,
    "TCP_WIN_MAX_IN": 14480.0,
    "TCP_WIN_MAX_OUT": 13032.0,
    "ICMP_TYPE": 21248.0,
    "ICMP_IPV4_TYPE": 83.0,
    "DNS_QUERY_ID": 0.0,
    "DNS_QUERY_TYPE": 0.0,
    "DNS_TTL_ANSWER": 0.0,
    "FTP_COMMAND_RET_CODE": 0.0,
    "SRC_TO_DST_IAT_MIN": 0.0,
    "SRC_TO_DST_IAT_MAX": 6.0,
    "SRC_TO_DST_IAT_AVG": 0.0,
    "SRC_TO_DST_IAT_STDDEV": 1.0,
    "DST_TO_SRC_IAT_MIN": 0.0,
    "DST_TO_SRC_IAT_MAX": 6.0,
    "DST_TO_SRC_IAT_AVG": 0.0,
    "DST_TO_SRC_IAT_STDDEV": 1.0,
}

assert set(BASELINE_FEATURES) == set(
    ML_FEATURE_COLUMNS
), "baseline fixture must cover exactly the 47 contract features"


@pytest.fixture
def baseline_features():
    """Return a factory producing a full 47-feature row with optional overrides."""

    def _make(**overrides: Any) -> Dict[str, float]:
        row = dict(BASELINE_FEATURES)
        row.update({name: float(value) for name, value in overrides.items()})
        return row

    return _make


@pytest.fixture
def real_artifacts_available() -> bool:
    """True when the four model artifacts and the preprocessor exist locally."""
    from pathlib import Path

    from network_anomaly.config import resolve_artifacts_dir

    artifacts = resolve_artifacts_dir()
    required = [
        artifacts / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib",
        artifacts / "models" / "random_forest" / "random_forest_baseline.joblib",
        artifacts / "models" / "xgboost" / "xgboost_baseline.joblib",
        artifacts / "models" / "isolation_forest" / "isolation_forest.joblib",
        artifacts / "models" / "autoencoder" / "autoencoder_model.joblib",
    ]
    return all(Path(path).is_file() for path in required)
