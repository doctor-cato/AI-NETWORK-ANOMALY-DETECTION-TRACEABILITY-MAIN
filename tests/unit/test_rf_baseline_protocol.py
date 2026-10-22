"""Unit tests for Random Forest baseline protocol (Issue #9).

Verifies protocol invariants, configuration validation, feature exclusion, test-set lock,
tuning boundaries, serialization roundtrip, and model builder integration without requiring
model training or fake ML data.
"""

import json
from pathlib import Path

import pytest
from sklearn.ensemble import RandomForestClassifier

from network_anomaly.config import RANDOM_SEED
from network_anomaly.data.nf_unsw_nb15_v3 import (
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.evaluation.metrics import (
    compute_attack_category_breakdown,
    compute_metrics,
)
from network_anomaly.models.random_forest import (
    RandomForestBaselineConfig,
    RandomForestBaselineProtocol,
    build_model,
    create_rf_baseline_protocol,
)
from network_anomaly.models.random_forest_protocol import (
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_CONTRACT_ID,
    PROTOCOL_IDENTIFIER,
    SPLIT_PROTOCOL_ID,
    EvaluationMetricProtocol,
    PreprocessingReference,
    SplitReference,
    TestLockPolicy,
    TuningConfig,
)


def test_default_rf_baseline_protocol_invariants():
    """Verify all default baseline invariants required for Issue #9."""
    protocol = create_rf_baseline_protocol()

    assert protocol.protocol_version == PROTOCOL_IDENTIFIER
    assert protocol.feature_contract_version == FEATURE_CONTRACT_VERSION
    assert len(protocol.selected_features) == 47
    assert protocol.selected_features == ML_FEATURE_COLUMNS

    # Target & positive class
    assert protocol.evaluation_protocol.target_column == "Label"
    assert protocol.evaluation_protocol.stratification_column == "Attack"
    assert protocol.evaluation_protocol.positive_class_name == "Attack"
    assert protocol.evaluation_protocol.positive_class_label == 1
    assert protocol.evaluation_protocol.negative_class_name == "Benign"
    assert protocol.evaluation_protocol.negative_class_label == 0

    # Strict exclusions
    assert "Label" not in protocol.selected_features
    assert "Attack" not in protocol.selected_features
    for meta_col in TRACE_METADATA_COLUMNS:
        assert meta_col not in protocol.selected_features
    assert set(protocol.selected_features).isdisjoint(TRACE_METADATA_COLUMNS + TARGET_COLUMNS)

    # Split reference & status
    assert protocol.split_reference.dataset_name == DATASET_NAME
    assert protocol.split_reference.split_protocol_id == SPLIT_PROTOCOL_ID
    assert protocol.split_reference.split_id is not None
    assert protocol.split_reference.split_status == "PLANNED / NOT VERIFIED"
    assert protocol.split_reference.ml_ready is False

    # Preprocessing reference
    assert protocol.preprocessing_reference.preprocessing_contract_id == PREPROCESSING_CONTRACT_ID
    assert protocol.preprocessing_reference.fit_boundary == "train_only"
    assert protocol.preprocessing_reference.preprocessing_status == "PLANNED / NOT VERIFIED"

    # Test lock policy
    assert protocol.test_lock.locked is True
    assert protocol.test_lock.purpose == "final_evaluation_only"
    assert "feature_selection" in protocol.test_lock.forbidden_uses
    assert "hyperparameter_tuning" in protocol.test_lock.forbidden_uses
    assert "threshold_selection" in protocol.test_lock.forbidden_uses
    assert "preprocessing_fitting" in protocol.test_lock.forbidden_uses
    assert "model_selection" in protocol.test_lock.forbidden_uses
    assert "model_iteration" in protocol.test_lock.forbidden_uses
    assert protocol.test_lock.max_evaluation_count == 1

    # Tuning policy
    assert protocol.tuning_policy.enabled is False
    assert "test" not in protocol.tuning_policy.allowed_partitions
    assert set(protocol.tuning_policy.allowed_partitions).issubset({"train", "validation"})
    assert protocol.tuning_policy.random_state == RANDOM_SEED

    # Hyperparameters
    assert protocol.model_config.n_estimators == 200
    assert protocol.model_config.max_depth == 16
    assert protocol.model_config.random_state == RANDOM_SEED
    assert protocol.model_config.criterion == "gini"
    assert protocol.model_config.min_samples_split == 2
    assert protocol.model_config.min_samples_leaf == 1
    assert protocol.model_config.n_jobs == -1


def test_rejection_of_target_in_features():
    """Enforce rejection when Label or Attack is included in feature selection."""
    with pytest.raises(ValueError, match="Target leakage violation|forbidden"):
        RandomForestBaselineProtocol(
            selected_features=ML_FEATURE_COLUMNS[:46] + ("Label",),
        ).validate()

    with pytest.raises(ValueError, match="Target leakage violation|forbidden"):
        RandomForestBaselineProtocol(
            selected_features=ML_FEATURE_COLUMNS[:46] + ("Attack",),
        ).validate()


@pytest.mark.parametrize("meta_col", TRACE_METADATA_COLUMNS)
def test_rejection_of_trace_metadata_in_features(meta_col):
    """Enforce rejection when any trace metadata (IP, port, timestamp) enters X."""
    with pytest.raises(ValueError, match="forbidden|Metadata leakage violation"):
        RandomForestBaselineProtocol(
            selected_features=ML_FEATURE_COLUMNS[:46] + (meta_col,),
        ).validate()


def test_rejection_of_feature_count_or_ordering_mismatch():
    """Enforce exact 47-feature baseline ordering contract."""
    # Truncated features
    with pytest.raises(ValueError, match="does not match"):
        RandomForestBaselineProtocol(
            selected_features=ML_FEATURE_COLUMNS[:46],
        ).validate()

    # Reordered features
    reordered = list(ML_FEATURE_COLUMNS)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(ValueError, match="does not match"):
        RandomForestBaselineProtocol(
            selected_features=tuple(reordered),
        ).validate()


def test_rejection_of_test_partition_in_tuning():
    """Enforce strict isolation of test partition from hyperparameter tuning."""
    with pytest.raises(ValueError, match="Violation of tuning isolation"):
        TuningConfig(allowed_partitions=("train", "test")).validate()

    with pytest.raises(ValueError, match="Violation of tuning isolation"):
        TuningConfig(allowed_partitions=("validation", "test")).validate()

    with pytest.raises(ValueError, match="Violation of tuning isolation"):
        protocol = RandomForestBaselineProtocol(
            tuning_policy=TuningConfig(allowed_partitions=("train", "validation", "test"))
        )
        protocol.validate()


def test_rejection_of_test_unlocking():
    """Enforce that test_lock cannot be disabled or stripped of forbidden uses."""
    with pytest.raises(ValueError, match="TestLockPolicy violation: locked must be True"):
        TestLockPolicy(locked=False).validate()

    with pytest.raises(ValueError, match="missing required forbidden uses"):
        TestLockPolicy(forbidden_uses=("feature_selection",)).validate()

    with pytest.raises(ValueError, match="evaluation count must be exactly 1"):
        TestLockPolicy(max_evaluation_count=5).validate()


def test_rejection_of_preprocessing_fit_leakage():
    """Enforce that preprocessing fit boundary must be strictly 'train_only'."""
    with pytest.raises(ValueError, match="Fit boundary violation"):
        PreprocessingReference(fit_boundary="train_and_validation").validate()

    with pytest.raises(ValueError, match="Fit boundary violation"):
        PreprocessingReference(fit_boundary="all_data").validate()


def test_rejection_of_invalid_hyperparameters():
    """Enforce hyperparameter validation rules."""
    with pytest.raises(ValueError, match="n_estimators must be positive"):
        RandomForestBaselineConfig(n_estimators=0).validate()

    with pytest.raises(ValueError, match="max_depth must be positive"):
        RandomForestBaselineConfig(max_depth=0).validate()

    with pytest.raises(ValueError, match="min_samples_split must be >= 2"):
        RandomForestBaselineConfig(min_samples_split=1).validate()

    with pytest.raises(ValueError, match="min_samples_leaf must be >= 1"):
        RandomForestBaselineConfig(min_samples_leaf=0).validate()

    with pytest.raises(ValueError, match="Unsupported criterion"):
        RandomForestBaselineConfig(criterion="unknown_crit").validate()


def test_rejection_of_invalid_target_or_positive_class():
    """Enforce binary target and positive class definitions."""
    with pytest.raises(ValueError, match="Target column must be 'Label'"):
        EvaluationMetricProtocol(target_column="Attack").validate()

    with pytest.raises(ValueError, match="Positive class must be 'Attack'"):
        EvaluationMetricProtocol(positive_class_name="Malicious").validate()

    with pytest.raises(ValueError, match="Positive class must be 'Attack' with integer label 1"):
        EvaluationMetricProtocol(positive_class_label=0).validate()

    with pytest.raises(ValueError, match="confusion_matrix_labels must be ordered"):
        EvaluationMetricProtocol(confusion_matrix_labels=(1, 0)).validate()


def test_rejection_of_empty_split_id():
    """Enforce that split_id must be non-empty."""
    with pytest.raises(ValueError, match="split_id must be a non-empty string"):
        SplitReference(split_id="").validate()

    with pytest.raises(ValueError, match="split_id must be a non-empty string"):
        SplitReference(split_id="   ").validate()


def test_serialization_and_deserialization_roundtrip(tmp_path):
    """Test full lossless roundtrip serialization through dict and JSON."""
    original = create_rf_baseline_protocol(
        split_id="nf-v3-test-split-01",
        random_seed=123,
        n_estimators=150,
        max_depth=20,
    )

    # 1. Dictionary roundtrip
    as_dict = original.to_dict()
    reconstructed_from_dict = RandomForestBaselineProtocol.from_dict(as_dict)
    assert reconstructed_from_dict == original
    assert reconstructed_from_dict.model_config.n_estimators == 150
    assert reconstructed_from_dict.model_config.random_state == 123
    assert reconstructed_from_dict.split_reference.split_id == "nf-v3-test-split-01"

    # 2. JSON string roundtrip
    as_json = original.to_json()
    reconstructed_from_json = RandomForestBaselineProtocol.from_json(as_json)
    assert reconstructed_from_json == original

    # 3. File save and load roundtrip
    filepath = tmp_path / "rf_protocol.json"
    original.save(filepath)
    loaded_from_file = RandomForestBaselineProtocol.load(filepath)
    assert loaded_from_file == original


def test_build_rf_model_integration():
    """Test that build_model builds RandomForestClassifier correctly from config and protocol."""
    protocol = create_rf_baseline_protocol(n_estimators=75, max_depth=8, random_seed=999)

    # Build from protocol
    model_from_protocol = build_model(protocol)
    assert isinstance(model_from_protocol, RandomForestClassifier)
    assert model_from_protocol.n_estimators == 75
    assert model_from_protocol.max_depth == 8
    assert model_from_protocol.random_state == 999

    # Build from config object
    model_from_config = build_model(protocol.model_config)
    assert isinstance(model_from_config, RandomForestClassifier)
    assert model_from_config.n_estimators == 75
    assert model_from_config.max_depth == 8

    # Build default
    default_model = build_model()
    assert isinstance(default_model, RandomForestClassifier)
    assert default_model.n_estimators == 200
    assert default_model.max_depth == 16


def test_metric_computation_and_fpr():
    """Test compute_metrics with synthetic binary predictions (strictly mathematical verification)."""
    # 4 samples: TN, FP, FN, TP
    # y_true: [0, 0, 1, 1]
    # y_pred: [0, 1, 0, 1]
    # TN=1, FP=1, FN=1, TP=1
    y_true = [0, 0, 1, 1]
    y_pred = [0, 1, 0, 1]

    metrics = compute_metrics(y_true, y_pred, labels=[0, 1])

    # Precision = TP / (TP + FP) = 1 / 2 = 0.5
    assert metrics["precision"] == 0.5
    # Recall = TP / (TP + FN) = 1 / 2 = 0.5
    assert metrics["recall"] == 0.5
    # F1 = 2 * (0.5 * 0.5) / (0.5 + 0.5) = 0.5
    assert metrics["f1"] == 0.5
    # FPR = FP / (FP + TN) = 1 / 2 = 0.5
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["fpr"] == 0.5
    # Confusion matrix: [[1, 1], [1, 1]]
    assert metrics["confusion_matrix"] == [[1, 1], [1, 1]]


def test_attack_category_breakdown():
    """Test error analysis breakdown by attack category without fake datasets."""
    y_true = [1, 1, 1, 0, 0]
    y_pred = [1, 0, 1, 0, 1]
    attack_cats = ["Exploits", "Exploits", "DoS", "Benign", "Benign"]

    breakdown = compute_attack_category_breakdown(y_true, y_pred, attack_cats)

    assert "Exploits" in breakdown
    assert breakdown["Exploits"]["total"] == 2
    assert breakdown["Exploits"]["detected"] == 1
    assert breakdown["Exploits"]["missed"] == 1
    assert breakdown["Exploits"]["detection_rate"] == 0.5

    assert "DoS" in breakdown
    assert breakdown["DoS"]["total"] == 1
    assert breakdown["DoS"]["detected"] == 1
    assert breakdown["DoS"]["missed"] == 0
    assert breakdown["DoS"]["detection_rate"] == 1.0

    assert "Benign" in breakdown
    assert breakdown["Benign"]["total"] == 2
    assert breakdown["Benign"]["false_positive"] == 1
    assert breakdown["Benign"]["true_negative"] == 1
    assert breakdown["Benign"]["false_positive_rate"] == 0.5
    assert "detected" not in breakdown["Benign"]


def test_attack_category_breakdown_benign_false_positive():
    """Test 1: True Benign incorrectly predicted as Attack is counted as false_positive."""
    y_true = [0]
    y_pred = [1]
    attack_cats = ["Benign"]

    breakdown = compute_attack_category_breakdown(y_true, y_pred, attack_cats)

    assert "Benign" in breakdown
    assert breakdown["Benign"]["total"] == 1
    assert breakdown["Benign"]["false_positive"] == 1
    assert breakdown["Benign"]["true_negative"] == 0
    assert breakdown["Benign"]["false_positive_rate"] == 1.0
    assert "detected" not in breakdown["Benign"]


def test_attack_category_breakdown_attack_missed():
    """Test 2: True Attack incorrectly predicted as Benign is counted as missed."""
    y_true = [1]
    y_pred = [0]
    attack_cats = ["Exploits"]

    breakdown = compute_attack_category_breakdown(y_true, y_pred, attack_cats)

    assert "Exploits" in breakdown
    assert breakdown["Exploits"]["total"] == 1
    assert breakdown["Exploits"]["detected"] == 0
    assert breakdown["Exploits"]["missed"] == 1
    assert breakdown["Exploits"]["detection_rate"] == 0.0


def test_attack_category_breakdown_all_confusion_cases():
    """Verify all four quadrant outcomes (TP, FN, TN, FP) in category breakdown."""
    # TP: Exploits predicted as Attack (1)
    # FN: Exploits predicted as Benign (0)
    # TN: Benign predicted as Benign (0)
    # FP: Benign predicted as Attack (1)
    y_true = [1, 1, 0, 0]
    y_pred = [1, 0, 0, 1]
    attack_cats = ["Exploits", "Exploits", "Benign", "Benign"]

    breakdown = compute_attack_category_breakdown(y_true, y_pred, attack_cats)

    # Attack category assertions (TP & FN)
    assert breakdown["Exploits"]["total"] == 2
    assert breakdown["Exploits"]["detected"] == 1
    assert breakdown["Exploits"]["missed"] == 1
    assert breakdown["Exploits"]["detection_rate"] == 0.5

    # Benign assertions (TN & FP)
    assert breakdown["Benign"]["total"] == 2
    assert breakdown["Benign"]["true_negative"] == 1
    assert breakdown["Benign"]["false_positive"] == 1
    assert breakdown["Benign"]["false_positive_rate"] == 0.5
    assert "detected" not in breakdown["Benign"]


def test_metadata_and_traceability():
    """Verify protocol metadata traceability and truthful non-claim of ML benchmark."""
    protocol = create_rf_baseline_protocol()

    assert protocol.metadata["issue"] == 9
    assert protocol.metadata["status"] == "IMPLEMENTED / TESTED"
    assert protocol.metadata["dependencies"] == "#7 -> #8 -> #9 -> #10 -> #12"
    assert protocol.metadata["training_status"] == "PLANNED (Issue #10)"
    assert protocol.metadata["evaluation_status"] == "PLANNED (Issue #12)"
    assert protocol.metadata["benchmark_claim"] == "NOT_AVAILABLE_YET"
    assert protocol.metadata["synthetic_data_used"] is False
