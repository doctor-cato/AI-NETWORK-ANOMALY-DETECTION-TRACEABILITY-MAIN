"""Regression tests for cross-dataset isolation, anti-leakage, and Test Lock (Issue #57, #58)."""

from __future__ import annotations

import importlib
from pathlib import Path

import pandas as pd
import pytest

from network_anomaly.models.robust_experiment import (
    FEATURES_E1,
    compute_fingerprint_disjoint_split,
)
from scripts.fetch_external_dataset import (
    UNSW_CANONICAL_TRAIN_END,
    UNSW_TEST_LOCK_START,
    UNSW_VALIDATION_START,
    validate_slice_sampling_parameters,
)
from scripts.run_cross_dataset_experiments import (
    DEFAULT_SPLIT_MANIFEST,
    verify_split_manifest_and_test_lock,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_main_components_zero_regression():
    """Verify that current main components (XGBoost, Isolation Forest) remain intact."""
    # 1. XGBoost model and protocol
    xgb_model_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "xgboost_model.py"
    xgb_proto_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "xgboost_protocol.py"
    xgb_train_path = PROJECT_ROOT / "scripts" / "train_xgboost.py"

    assert xgb_model_path.exists(), "xgboost_model.py must be preserved on main"
    assert xgb_proto_path.exists(), "xgboost_protocol.py must be preserved on main"
    assert xgb_train_path.exists(), "train_xgboost.py must be preserved on main"

    xgb_mod = importlib.import_module("network_anomaly.models.xgboost_model")
    assert hasattr(xgb_mod, "XGBoostModel"), "XGBoostModel class must be intact"

    # 2. Isolation Forest model
    if_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "isolation_forest.py"
    assert if_path.exists(), "isolation_forest.py must be preserved on main"

    # Verify isolation_forest.py is the full implementation, not the 12-line PR #47 stub
    line_count = len(if_path.read_text(encoding="utf-8").splitlines())
    assert (
        line_count >= 50
    ), f"isolation_forest.py must not be overwritten by stub ({line_count} lines)"

    if_mod = importlib.import_module("network_anomaly.models.isolation_forest")
    assert hasattr(if_mod, "anomaly_scores"), "anomaly_scores function must be intact"


def test_fetch_external_dataset_anti_leakage_guardrail():
    """First-50k slice on NF-UNSW-NB15-v3 (rows 0-50k) is strictly rejected as train-set leakage."""
    # Attempting to slice row 0 (start of training partition)
    with pytest.raises(ValueError) as excinfo:
        validate_slice_sampling_parameters("NF-UNSW-NB15-v3", skip_rows=0, sample_rows=50000)
    assert "chronological integrity violation" in str(excinfo.value).lower()
    assert f"{UNSW_CANONICAL_TRAIN_END:,}" in str(excinfo.value) or str(
        UNSW_CANONICAL_TRAIN_END
    ) in str(excinfo.value)

    # Attempting to slice inside training partition (< 1,665,240)
    with pytest.raises(ValueError) as excinfo_mid:
        validate_slice_sampling_parameters("NF-UNSW-NB15-v3", skip_rows=100000, sample_rows=10000)
    assert "chronological integrity violation" in str(excinfo_mid.value).lower()

    # Slicing at official validation start (>= 1,665,240) is permitted
    val_skip = validate_slice_sampling_parameters(
        "NF-UNSW-NB15-v3", skip_rows=UNSW_VALIDATION_START, sample_rows=50000
    )
    assert val_skip == UNSW_VALIDATION_START


def test_fetch_external_dataset_test_lock_guardrail():
    """Held-out Test split (rows >= 2,019,471) is strictly BLOCKED under Test Lock."""
    with pytest.raises(PermissionError) as excinfo:
        validate_slice_sampling_parameters(
            "NF-UNSW-NB15-v3", skip_rows=UNSW_TEST_LOCK_START, sample_rows=10000
        )
    assert "test lock enforced" in str(excinfo.value).lower()
    assert "blocked" in str(excinfo.value).lower()


def test_split_manifest_verification_and_test_lock():
    """Official split manifest must define validation, test lock, and 300s purge gap."""
    audit = verify_split_manifest_and_test_lock(DEFAULT_SPLIT_MANIFEST)
    assert audit["status"] == "VERIFIED"
    assert audit["validation_rows"] == 345371
    exp_val_sha = "a3e4470c2731870deaf57ce9a865e2491107d8e7f72383cdd0f99de0dd485cd4"
    assert audit["validation_index_sha256"] == exp_val_sha
    assert "BLOCKED" in audit["test_lock_status"]
    assert audit["purge_gap_milliseconds"] == 300000


def test_fingerprint_disjointness_in_cross_dataset_partitioning():
    """Partitioning must ensure 0 5-tuple flow overlap between train and test subsets."""
    # Synthetic dataset with repeated 5-tuples simulating multi-packet flows
    df = pd.DataFrame(
        {
            "IPV4_SRC_ADDR": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.3"],
            "L4_SRC_PORT": [1000, 1000, 2000, 2000, 3000],
            "IPV4_DST_ADDR": ["10.0.0.5", "10.0.0.5", "10.0.0.6", "10.0.0.6", "10.0.0.7"],
            "L4_DST_PORT": [80, 80, 443, 443, 8080],
            "PROTOCOL": [6, 6, 6, 6, 17],
            "Label": [0, 0, 1, 1, 0],
            "Attack": ["Benign", "Benign", "DoS", "DoS", "Benign"],
        }
    )
    for col in FEATURES_E1:
        if col not in df.columns:
            df[col] = 1.0

    df_train, df_test, audit = compute_fingerprint_disjoint_split(
        df, train_size=0.40, random_state=42, feature_cols=FEATURES_E1
    )
    assert audit["overlap_5tuple_fingerprints"] == 0
    assert audit["fingerprint_disjoint_verified"] is True
    assert len(df_train) > 0
    assert len(df_test) > 0
