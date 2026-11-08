"""Unit tests for XGBoost baseline protocol (Issue #31 / C3).

Verifies protocol invariants, configuration validation, feature exclusion, test-set lock,
tuning boundaries, serialization roundtrip, and model builder integration without requiring
model training or fake ML data.
"""

import json
from pathlib import Path

import pytest
from xgboost import XGBClassifier

from network_anomaly.config import RANDOM_SEED
from network_anomaly.data.nf_unsw_nb15_v3 import (
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.models.xgboost_model import (
    XGBoostModel,
    build_model,
)
from network_anomaly.models.xgboost_protocol import (
    CANONICAL_BASELINE_PARAMS,
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_CONTRACT_ID,
    PROTOCOL_IDENTIFIER,
    SPLIT_PROTOCOL_ID,
    EvaluationMetricProtocol,
    PreprocessingReference,
    SplitReference,
    TestLockPolicy,
    TuningConfig,
    XGBoostBaselineConfig,
    XGBoostBaselineProtocol,
    create_xgb_baseline_protocol,
)


def test_default_xgb_baseline_protocol_invariants():
    """Verify all default baseline invariants for Issue #31."""
    protocol = create_xgb_baseline_protocol()

    assert protocol.protocol_version == PROTOCOL_IDENTIFIER
    assert protocol.feature_contract_version == FEATURE_CONTRACT_VERSION
    assert len(protocol.selected_features) == 47
    assert protocol.selected_features == ML_FEATURE_COLUMNS

    assert protocol.evaluation_protocol.target_column == "Label"
    assert protocol.evaluation_protocol.stratification_column == "Attack"
    assert protocol.evaluation_protocol.positive_class_name == "Attack"
    assert protocol.evaluation_protocol.positive_class_label == 1
    assert protocol.evaluation_protocol.negative_class_name == "Benign"
    assert protocol.evaluation_protocol.negative_class_label == 0


def test_xgb_baseline_config_locking():
    """Verify that canonical baseline hyperparameter changes are rejected fail-closed."""
    # Custom parameter with is_canonical_baseline=True must fail
    cfg = XGBoostBaselineConfig(n_estimators=100, is_canonical_baseline=True)
    with pytest.raises(ValueError, match="Canonical baseline configuration mismatch"):
        cfg.validate()


def test_xgb_baseline_config_custom_allowed():
    """Verify that custom configuration is valid when is_canonical_baseline=False."""
    cfg = XGBoostBaselineConfig(
        n_estimators=100,
        max_depth=4,
        is_canonical_baseline=False,
        configuration_id="xgb-exp-100",
    )
    cfg.validate()
    assert cfg.n_estimators == 100
    assert cfg.is_canonical_baseline is False
    assert cfg.configuration_id == "xgb-exp-100"


def test_xgb_test_lock_policy_cannot_be_unlocked():
    """Verify that TestLockPolicy strictly enforces locked=True."""
    with pytest.raises(ValueError, match="locked must be True"):
        TestLockPolicy(locked=False).validate()


def test_xgb_tuning_policy_excludes_test_partition():
    """Verify that tuning policy strictly prohibits 'test' partition."""
    with pytest.raises(ValueError, match="Violation of tuning isolation"):
        TuningConfig(allowed_partitions=("train", "test")).validate()


def test_xgb_protocol_serialization_roundtrip():
    """Verify protocol dictionary and JSON roundtrip serialization."""
    protocol = create_xgb_baseline_protocol()
    p_dict = protocol.to_dict()
    assert isinstance(p_dict, dict)
    assert p_dict["protocol_version"] == PROTOCOL_IDENTIFIER
    assert p_dict["feature_contract_version"] == FEATURE_CONTRACT_VERSION
    assert len(p_dict["selected_features"]) == 47

    p_json = protocol.to_json()
    assert isinstance(p_json, str)
    loaded = json.loads(p_json)
    assert loaded["protocol_version"] == PROTOCOL_IDENTIFIER


def test_build_model_with_protocol():
    """Verify build_model returns an untracked estimator conforming to protocol."""
    protocol = create_xgb_baseline_protocol()
    estimator = build_model(protocol)
    assert isinstance(estimator, XGBClassifier)
    assert estimator.n_estimators == 200
    assert estimator.max_depth == 6
