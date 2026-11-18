"""Unit tests for OOD Rejection Gate and Independent Threshold Calibration.

Validates Issues #99 and #100 for NetFlow Sentinel v2.0.
"""

import json
from pathlib import Path

import numpy as np
import pytest

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.ml.ood_gate import (
    DEFAULT_OOD_GATE_PATH,
    OODAction,
    OODRejectionGate,
    load_persisted_ood_gate,
    verify_ood_gate_artifact,
)
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

        # Non-finite values (NaN / Inf) must abstain fail-closed
        nan_sample = {col: 0.0 for col in feat_names}
        nan_sample["feat_a"] = float("nan")
        nan_dec = gate.evaluate_sample(nan_sample)
        assert nan_dec.action == OODAction.ABSTAIN
        assert nan_dec.is_ood is True
        assert nan_dec.reason == "NON_FINITE_FEATURE_VALUE"

        inf_sample = {col: 0.0 for col in feat_names}
        inf_sample["feat_b"] = float("inf")
        inf_dec = gate.evaluate_sample(inf_sample)
        assert inf_dec.action == OODAction.ABSTAIN
        assert inf_dec.is_ood is True
        assert inf_dec.reason == "NON_FINITE_FEATURE_VALUE"

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

    def test_verify_ood_gate_artifact_rejects_corruption_and_hash_mismatch(self, tmp_path):
        rng = np.random.default_rng(7)
        gate = OODRejectionGate()
        gate.fit(rng.normal(size=(50, len(ML_FEATURE_COLUMNS))), list(ML_FEATURE_COLUMNS))
        payload = gate.to_artifact(
            {
                "dataset_name": "AIT-NDS-v2",
                "partition": "train",
                "fit_rows": 50,
                "preprocessor_artifact_sha256": "a" * 64,
            }
        )
        gate_path = tmp_path / "ood_reference_gate.json"
        gate_path.write_text(json.dumps(payload), encoding="utf-8")

        loaded, meta = verify_ood_gate_artifact(
            gate_path,
            expected_preprocessor_sha256="a" * 64,
        )
        assert loaded.is_fitted is True
        assert meta["status"] == "FITTED"
        assert meta["fit_rows"] == 50

        # Mismatched preprocessor SHA fails closed
        with pytest.raises(ValueError, match="preprocessor_artifact_sha256 mismatch"):
            verify_ood_gate_artifact(gate_path, expected_preprocessor_sha256="b" * 64)

        # Wrong schema_version, inverted bounds, zero stds, or missing provenance fail closed
        bad_schema = json.loads(json.dumps(payload))
        bad_schema["schema_version"] = 99
        bad_schema_path = tmp_path / "bad_schema.json"
        bad_schema_path.write_text(json.dumps(bad_schema), encoding="utf-8")
        with pytest.raises(ValueError, match="schema_version"):
            verify_ood_gate_artifact(bad_schema_path)

        bad_stds = json.loads(json.dumps(payload))
        bad_stds["stds"][0] = 0.0
        bad_stds_path = tmp_path / "bad_stds.json"
        bad_stds_path.write_text(json.dumps(bad_stds), encoding="utf-8")
        with pytest.raises(ValueError, match="non-positive standard deviations"):
            verify_ood_gate_artifact(bad_stds_path)

        no_prov = json.loads(json.dumps(payload))
        no_prov.pop("provenance", None)
        no_prov_path = tmp_path / "no_prov.json"
        no_prov_path.write_text(json.dumps(no_prov), encoding="utf-8")
        with pytest.raises(ValueError, match="provenance"):
            verify_ood_gate_artifact(no_prov_path)

        bad_bounds = json.loads(json.dumps(payload))
        bad_bounds["min_bounds"][0] = bad_bounds["max_bounds"][0] + 10.0
        bad_path = tmp_path / "bad_bounds.json"
        bad_path.write_text(json.dumps(bad_bounds), encoding="utf-8")
        with pytest.raises(ValueError, match="min_bounds > max_bounds"):
            verify_ood_gate_artifact(bad_path)
        assert load_persisted_ood_gate(bad_path) is None
        with pytest.raises(ValueError, match="Failed to verify OOD gate artifact"):
            load_persisted_ood_gate(bad_path, strict=True)

        # Real artifact on disk (if present) verifies cleanly against preprocessor manifest
        if DEFAULT_OOD_GATE_PATH.is_file():
            prep_man = Path("reports/preprocessing/v2_flow_preprocessing_manifest.json")
            prep_sha = json.loads(prep_man.read_text(encoding="utf-8"))["artifact_sha256"]
            real_gate, real_meta = verify_ood_gate_artifact(
                DEFAULT_OOD_GATE_PATH,
                expected_preprocessor_sha256=prep_sha,
            )
            assert real_gate.is_fitted is True
            assert real_meta["fit_rows"] > 0
            assert real_meta["feature_count"] == len(ML_FEATURE_COLUMNS)


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
