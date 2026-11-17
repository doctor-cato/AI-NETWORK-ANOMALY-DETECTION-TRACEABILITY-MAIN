"""Unit tests for OOD Rejection Gate and Independent Threshold Calibration.

Validates Issues #99 and #100 for NetFlow Sentinel v2.0.
"""

import numpy as np
import pytest

from network_anomaly.ml.ood_gate import OODAction, OODRejectionGate
from network_anomaly.ml.threshold_calibration import (
    CalibrationPolicy,
    ThresholdCalibrator,
)


class TestOODRejectionGate:
    def test_in_distribution_sample_proceeds(self):
        # 100 samples, 4 features
        np.random.seed(42)
        X_train = np.random.normal(loc=10.0, scale=2.0, size=(100, 4))
        feat_names = ["feat_a", "feat_b", "feat_c", "feat_d"]

        gate = OODRejectionGate(std_margin=4.0, statistical_threshold=4.0)
        gate.fit(X_train, feat_names)

        # In-distribution sample
        sample_in = {"feat_a": 10.2, "feat_b": 9.8, "feat_c": 10.5, "feat_d": 11.0}
        dec = gate.evaluate_sample(sample_in)
        assert dec.action == OODAction.PROCEED
        assert dec.is_ood is False
        assert dec.reason is None

    def test_extreme_bounds_breach_abstains(self):
        np.random.seed(42)
        X_train = np.random.normal(loc=10.0, scale=1.0, size=(100, 4))
        feat_names = ["feat_a", "feat_b", "feat_c", "feat_d"]

        gate = OODRejectionGate(std_margin=3.0)
        gate.fit(X_train, feat_names)

        # Radical breach in 3 features (> 100 vs ~10)
        sample_ood = {"feat_a": 999.0, "feat_b": 500.0, "feat_c": 800.0, "feat_d": 10.0}
        dec = gate.evaluate_sample(sample_ood)
        assert dec.action == OODAction.ABSTAIN
        assert dec.is_ood is True
        assert dec.reason == "FEATURE_BOUNDS_EXTREME_BREACH"
        assert len(dec.offending_features) >= 3

    def test_missing_features_abstains(self):
        np.random.seed(42)
        X_train = np.random.normal(loc=10.0, scale=1.0, size=(100, 4))
        gate = OODRejectionGate()
        gate.fit(X_train, ["feat_a", "feat_b", "feat_c", "feat_d"])

        sample_missing = {"feat_a": 10.0}
        dec = gate.evaluate_sample(sample_missing)
        assert dec.action == OODAction.ABSTAIN
        assert dec.is_ood is True
        assert dec.reason == "MISSING_MANDATORY_FEATURES"


class TestThresholdCalibration:
    def test_calibration_guard_blocks_test_partition(self):
        # Must raise ValueError if 'test' is passed
        with pytest.raises(ValueError, match="LEAKAGE GUARD VIOLATION"):
            ThresholdCalibrator(partition_name="heldout_test_set")

    def test_calibration_max_f1_policy(self):
        calibrator = ThresholdCalibrator(partition_name="validation")
        # Synthetic ground truth and scores
        y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
        y_scores = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95])

        manifest = calibrator.calibrate(
            y_true=y_true,
            y_scores=y_scores,
            model_family="RandomForest",
            policy=CalibrationPolicy.MAX_F1,
        )

        assert manifest.model_family == "RandomForest"
        assert manifest.calibration_policy == "MAX_F1"
        assert 0.5 <= manifest.optimal_threshold <= 0.65
        assert manifest.validation_metrics["f1_score"] == 1.0
        assert manifest.guard_test_partition_excluded is True

    def test_calibration_budget_fpr_policy(self):
        calibrator = ThresholdCalibrator(partition_name="validation_split")
        y_true = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
        y_scores = np.array(
            [0.05, 0.1, 0.12, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.45, 0.6, 0.7, 0.8, 0.9]
        )

        manifest = calibrator.calibrate(
            y_true=y_true,
            y_scores=y_scores,
            model_family="Autoencoder",
            policy=CalibrationPolicy.BUDGET_FPR,
            max_fpr=0.05,
        )

        assert manifest.validation_metrics["fpr"] <= 0.05
