"""Unit tests for XGBoost baseline protocol (Issue #31 / C3).

Verifies protocol invariants, configuration validation, feature exclusion, test-set lock,
tuning boundaries, serialization roundtrip, and model builder integration without requiring
model training or fake ML data.
"""

import json

import pytest
from xgboost import XGBClassifier

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
)
from network_anomaly.models.xgboost_model import (
    XGBoostModel,
    build_model,
)
from network_anomaly.models.xgboost_protocol import (
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


def test_xgb_protocol_from_dict_full_roundtrip():
    """Finding F02: protocol_before.to_dict() == protocol_after.to_dict() through from_dict."""
    protocol_before = create_xgb_baseline_protocol()
    d = protocol_before.to_dict()
    protocol_after = XGBoostBaselineProtocol.from_dict(d)
    assert protocol_before.to_dict() == protocol_after.to_dict()
    assert (
        protocol_after.split_reference.manifest_sha256
        == protocol_before.split_reference.manifest_sha256
    )
    assert (
        protocol_after.preprocessing_reference.artifact_sha256
        == protocol_before.preprocessing_reference.artifact_sha256
    )
    assert (
        protocol_after.tuning_policy.allowed_partitions
        == protocol_before.tuning_policy.allowed_partitions
    )
    assert protocol_after.test_lock_policy.locked == protocol_before.test_lock_policy.locked
    assert (
        protocol_after.evaluation_protocol.primary_metrics
        == protocol_before.evaluation_protocol.primary_metrics
    )


def test_xgb_protocol_custom_nested_components_roundtrip():
    """Finding F02: Custom nested components are fully preserved without reverting to defaults."""
    custom_split = SplitReference(
        protocol_id=SPLIT_PROTOCOL_ID,
        manifest_path="custom/splits/manifest.json",
        manifest_sha256="c" * 64,
        status="PASS",
    )
    custom_prep = PreprocessingReference(
        contract_id=PREPROCESSING_CONTRACT_ID,
        artifact_path="custom/prep.joblib",
        artifact_sha256="d" * 64,
        manifest_path="custom/prep_manifest.json",
        manifest_sha256="e" * 64,
        status="PASS",
    )
    custom_tuning = TuningConfig(
        enabled=True,
        search_space_version="custom-search-v2",
        search_space={"max_depth": [3, 5, 7]},
        tuning_budget={"max_evals": 10},
        allowed_partitions=("train",),
        scoring_metric="f1",
        random_state=123,
    )
    custom_test_lock = TestLockPolicy(
        locked=True,
        purpose="final_evaluation_only",
        forbidden_uses=(
            "feature_selection",
            "hyperparameter_tuning",
            "threshold_selection",
            "preprocessing_fitting",
            "model_selection",
            "model_iteration",
            "extra_forbidden_use",
        ),
        max_evaluation_count=1,
    )
    custom_eval = EvaluationMetricProtocol(
        task="binary_classification",
        target_column="Label",
        stratification_column="Attack",
        positive_class_name="Attack",
        positive_class_label=1,
        negative_class_name="Benign",
        negative_class_label=0,
        primary_metrics=(
            "precision",
            "recall",
            "f1",
            "macro_f1",
            "false_positive_rate",
            "confusion_matrix",
        ),
        confusion_matrix_labels=(0, 1),
        error_analysis_breakdown_column="Attack",
        expected_attack_categories=("Analysis", "Backdoor", "DoS"),
    )
    custom_cfg = XGBoostBaselineConfig(
        n_estimators=100,
        max_depth=4,
        is_canonical_baseline=False,
        configuration_id="xgb-custom-roundtrip-test",
    )

    proto_before = XGBoostBaselineProtocol(
        split_reference=custom_split,
        preprocessing_reference=custom_prep,
        tuning_policy=custom_tuning,
        test_lock_policy=custom_test_lock,
        evaluation_protocol=custom_eval,
        model_config=custom_cfg,
    )

    proto_after = XGBoostBaselineProtocol.from_dict(proto_before.to_dict())
    assert proto_before.to_dict() == proto_after.to_dict()
    assert proto_after.split_reference.manifest_sha256 == "c" * 64
    assert proto_after.preprocessing_reference.artifact_sha256 == "d" * 64
    assert proto_after.tuning_policy.enabled is True
    assert proto_after.tuning_policy.search_space_version == "custom-search-v2"
    assert "extra_forbidden_use" in proto_after.test_lock_policy.forbidden_uses
    assert proto_after.evaluation_protocol.expected_attack_categories == (
        "Analysis",
        "Backdoor",
        "DoS",
    )


def test_xgb_model_save_load_roundtrip_preserves_protocol(tmp_path):
    """Finding F02: XGBoostModel.save() -> load() preserves full protocol provenance."""
    import numpy as np
    import pandas as pd

    X = pd.DataFrame(np.ones((20, 47)), columns=list(ML_FEATURE_COLUMNS))
    y = np.array([0] * 10 + [1] * 10)

    proto = create_xgb_baseline_protocol()
    model = XGBoostModel(protocol=proto).fit(X, y)

    model_path = tmp_path / "model.joblib"
    model.save(model_path)

    reloaded = XGBoostModel.load(model_path)
    assert reloaded.protocol is not None
    assert reloaded.protocol.to_dict() == proto.to_dict()


def test_xgb_protocol_from_dict_rejects_corrupted_payloads():
    """Finding F02: Corrupted protocol dictionary fail-closed validation."""
    with pytest.raises(ValueError, match="Expected dict for protocol payload"):
        XGBoostBaselineProtocol.from_dict("not-a-dict")  # type: ignore

    proto = create_xgb_baseline_protocol()
    d = proto.to_dict()
    d["tuning_policy"] = "invalid_tuning_policy"
    with pytest.raises(ValueError, match="Invalid tuning_policy"):
        XGBoostBaselineProtocol.from_dict(d)

    d2 = proto.to_dict()
    d2["split_reference"] = "invalid_split"
    with pytest.raises(ValueError, match="Invalid split_reference"):
        XGBoostBaselineProtocol.from_dict(d2)

    d3 = proto.to_dict()
    d3["selected_features"] = list(ML_FEATURE_COLUMNS)[:40]
    with pytest.raises(ValueError, match="Expected 47 ML features"):
        XGBoostBaselineProtocol.from_dict(d3)
