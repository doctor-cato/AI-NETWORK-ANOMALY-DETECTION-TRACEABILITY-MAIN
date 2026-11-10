#!/usr/bin/env python3
"""Regression tests for Track C: Isolation Forest Artifact & Calibration Parity (Issue #54).

Covers:
- Strict binary label {0, 1} parity between evaluation and inference predict.
- 100% prediction agreement across threshold sweeps.
- Round-trip save and load_verified parity and fail-closed integrity.
- Score direction monotonicity and semantic label mapping (0: Benign, 1: Attack).
"""

from pathlib import Path

import numpy as np
import pytest

from network_anomaly.models.isolation_forest import (
    IsolationForestModel,
    anomaly_scores,
    build_model,
)


@pytest.fixture
def synthetic_flow_data():
    """Create reproducible synthetic dataset representing normal flows and anomalies."""
    rng = np.random.default_rng(42)
    # 300 normal flows in tight cluster around origin
    normal_flows = rng.normal(loc=0.0, scale=0.5, size=(300, 5))
    # 20 anomalous flows scattered far from origin
    anomalous_flows = rng.uniform(low=8.0, high=15.0, size=(20, 5))
    X = np.vstack([normal_flows, anomalous_flows])
    return X, len(normal_flows), len(anomalous_flows)


class TestEvaluationInferenceParity:
    """Verify exact element-by-element equivalence between evaluation and inference."""

    def test_evaluation_and_inference_binary_parity_100_percent(self, synthetic_flow_data):
        """Under identical input matrix and threshold, evaluation and predict match 100%."""
        X, n_normal, n_anomaly = synthetic_flow_data

        model = IsolationForestModel(config={"n_estimators": 50, "random_state": 42})
        model.fit(X)

        # Calibrate a threshold (e.g. 90th percentile of anomaly scores on normal cluster)
        normal_scores = model.anomaly_scores(X[:n_normal])
        calibrated_threshold = float(np.percentile(normal_scores, 90))
        model.threshold = calibrated_threshold

        # 1. Evaluation logic (as executed in scripts/train_isolation_forest.py)
        scores_eval = anomaly_scores(model.estimator, X)
        y_eval = (scores_eval >= calibrated_threshold).astype(int)

        # 2. Inference logic (as executed in predict())
        y_inf = model.predict(X)

        # Parity assertions
        assert np.array_equal(y_eval, y_inf), "Evaluation and inference predictions diverged!"
        assert (y_eval == y_inf).mean() == 1.0
        assert set(np.unique(y_inf)).issubset({0, 1})
        assert y_inf.dtype == int

        # Ensure outliers are marked as Attack (1) and normal mostly Benign (0)
        assert np.all(y_inf[n_normal:] == 1), "Extreme outliers must be classified as Attack (1)"
        assert float(np.mean(y_inf[:n_normal] == 0)) >= 0.85

    def test_parity_across_threshold_sweep(self, synthetic_flow_data):
        """Verify 100% agreement holds across multiple threshold values."""
        X, _, _ = synthetic_flow_data

        model = IsolationForestModel(config={"n_estimators": 50, "random_state": 42})
        model.fit(X)

        all_scores = model.anomaly_scores(X)
        thresholds = [
            float(np.min(all_scores) - 0.5),
            float(np.percentile(all_scores, 5)),
            float(np.percentile(all_scores, 25)),
            float(np.median(all_scores)),
            float(np.percentile(all_scores, 75)),
            float(np.percentile(all_scores, 95)),
            float(np.max(all_scores) + 0.5),
        ]

        for tau in thresholds:
            y_eval = (all_scores >= tau).astype(int)
            y_inf = model.predict(X, threshold=tau)

            assert np.array_equal(y_eval, y_inf), f"Parity mismatch at threshold tau={tau}"
            assert set(np.unique(y_inf)).issubset({0, 1})

    def test_parity_preserved_across_save_and_load_verified(
        self, synthetic_flow_data, tmp_path: Path
    ):
        """Predictions remain identical after round-trip save and verified loading."""
        X, _, _ = synthetic_flow_data

        model = IsolationForestModel(config={"n_estimators": 50, "random_state": 42})
        model.fit(X)

        scores = model.anomaly_scores(X)
        tau = float(np.percentile(scores, 90))
        model.threshold = tau

        model_path = tmp_path / "isolation_forest.joblib"
        manifest_path = tmp_path / "isolation_forest_manifest.json"
        valid_prep_sha = "a" * 64
        valid_sm_sha = "b" * 64

        model.save(
            model_path=model_path,
            manifest_path=manifest_path,
            preprocessor_artifact_sha256=valid_prep_sha,
            split_manifest_sha256=valid_sm_sha,
        )

        loaded = IsolationForestModel.load_verified(
            model_path=model_path,
            manifest_path=manifest_path,
            expected_preprocessor_artifact_sha256=valid_prep_sha,
            expected_split_manifest_sha256=valid_sm_sha,
            expected_threshold=tau,
        )

        # Baseline evaluation prediction
        y_eval = (scores >= tau).astype(int)
        # Prediction from loaded verified model
        y_loaded = loaded.predict(X)

        assert np.array_equal(y_eval, y_loaded)
        assert np.array_equal(model.predict(X), y_loaded)


class TestScoreDirectionAndSemantics:
    """Validate score monotonicity, score direction, and label mapping semantics."""

    def test_score_direction_monotonically_increases_with_distance(self):
        """Anomaly score increases as points deviate from normal distribution."""
        rng = np.random.default_rng(123)
        # Train on normal samples centered at 0 with standard variance
        train_normal = rng.normal(loc=0.0, scale=1.0, size=(1000, 3))
        model = IsolationForestModel(config={"n_estimators": 100, "random_state": 42})
        model.fit(train_normal)

        probe_points = np.array(
            [
                [0.0, 0.0, 0.0],  # Inlier center
                [2.0, 2.0, 2.0],  # Moderate boundary anomaly
                [10.0, 10.0, 10.0],  # Extreme outlier
            ]
        )

        scores = model.anomaly_scores(probe_points)
        assert (
            scores[0] < scores[1] < scores[2]
        ), f"Expected monotonic score increase, got: {scores}"
        assert scores[2] > model.anomaly_scores(train_normal).mean()
        assert model.score_direction == "higher_is_more_anomalous"

    def test_label_mapping_and_sklearn_prediction_disparity_resolution(self):
        """Raw sklearn outputs {-1, 1} where 1 is inlier; IsolationForestModel maps 1 to Attack."""
        rng = np.random.default_rng(999)
        normal = rng.normal(loc=0.0, scale=0.1, size=(200, 2))
        extreme_outlier = np.array([[50.0, 50.0]])
        X = np.vstack([normal, extreme_outlier])

        # Raw sklearn estimator
        raw_model = build_model({"n_estimators": 30, "random_state": 42})
        raw_model.fit(X)
        raw_preds = raw_model.predict(X)
        # Raw sklearn outputs: 1 = inlier, -1 = outlier
        assert raw_preds[-1] == -1
        assert raw_preds[0] == 1

        # Standardized IsolationForestModel wrapper
        model = IsolationForestModel(config={"n_estimators": 30, "random_state": 42}, threshold=0.0)
        model.fit(X)
        std_preds = model.predict(X)

        # Standardized model outputs: 0 = Benign, 1 = Attack
        assert set(np.unique(std_preds)).issubset({0, 1})
        assert std_preds[-1] == 1, "Extreme outlier must be classified as Attack (1)"
        assert std_preds[0] == 0, "Normal cluster point must be classified as Benign (0)"
        assert model.label_mapping == {"0": "Benign", "1": "Attack"}


class TestFailClosedIntegrity:
    """Verify that tampering or mismatches trigger fail-closed ValueError."""

    def test_tampered_model_binary_rejected(self, synthetic_flow_data, tmp_path: Path):
        X, _, _ = synthetic_flow_data
        model = IsolationForestModel(threshold=0.05)
        model.fit(X)

        m_path = tmp_path / "model.joblib"
        man_path = tmp_path / "manifest.json"
        model.save(m_path, man_path, preprocessor_artifact_sha256="c" * 64)

        # Alter binary by appending arbitrary bytes
        with open(m_path, "ab") as fh:
            fh.write(b"\x00\xffCORRUPT")

        with pytest.raises(ValueError, match="Integrity check failed"):
            IsolationForestModel.load_verified(m_path, man_path)

    def test_tampered_threshold_rejected(self, synthetic_flow_data, tmp_path: Path):
        X, _, _ = synthetic_flow_data
        model = IsolationForestModel(threshold=0.05)
        model.fit(X)

        m_path = tmp_path / "model.joblib"
        man_path = tmp_path / "manifest.json"
        model.save(m_path, man_path, preprocessor_artifact_sha256="c" * 64)

        with pytest.raises(ValueError, match="Threshold mismatch"):
            IsolationForestModel.load_verified(m_path, man_path, expected_threshold=0.55)

    def test_tampered_preprocessor_sha_rejected(self, synthetic_flow_data, tmp_path: Path):
        X, _, _ = synthetic_flow_data
        model = IsolationForestModel(threshold=0.05)
        model.fit(X)

        m_path = tmp_path / "model.joblib"
        man_path = tmp_path / "manifest.json"
        model.save(m_path, man_path, preprocessor_artifact_sha256="c" * 64)

        with pytest.raises(ValueError, match="Preprocessor artifact SHA-256 mismatch"):
            IsolationForestModel.load_verified(
                m_path, man_path, expected_preprocessor_artifact_sha256="d" * 64
            )
