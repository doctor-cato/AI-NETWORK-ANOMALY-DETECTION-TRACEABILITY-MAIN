"""Unit tests for Robust Random Forest Cross-Dataset Experiments (Issue #48)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.models.robust_experiment import (
    ENVIRONMENT_SPECIFIC_FEATURES,
    FEATURES_E0,
    FEATURES_E1,
    FEATURES_E2,
    SHORTCUT_TTL_FEATURES,
    ExperimentMetrics,
    RobustModelExperiment,
)


def test_feature_contracts_ablation() -> None:
    """Verify exact feature contract lengths and strict exclusions."""
    # Full baseline: 47 features
    assert len(FEATURES_E0) == 47
    assert FEATURES_E0 == list(ML_FEATURE_COLUMNS)

    # E1: 45 features (excludes MIN_TTL, MAX_TTL)
    assert len(FEATURES_E1) == 45
    assert "MIN_TTL" not in FEATURES_E1
    assert "MAX_TTL" not in FEATURES_E1
    assert set(FEATURES_E0) - set(FEATURES_E1) == SHORTCUT_TTL_FEATURES

    # E2: 41 features (excludes TTL and environment-specific artifacts)
    assert len(FEATURES_E2) == 41
    assert set(FEATURES_E0) - set(FEATURES_E2) == ENVIRONMENT_SPECIFIC_FEATURES
    for feat in ENVIRONMENT_SPECIFIC_FEATURES:
        assert feat not in FEATURES_E2


def test_model_not_fitted_error() -> None:
    """Verify calling predict or evaluate before fit raises RuntimeError."""
    exp = RobustModelExperiment("E1_test", FEATURES_E1)
    df_dummy = pd.DataFrame(np.zeros((5, 45)), columns=FEATURES_E1)

    with pytest.raises(RuntimeError, match="is not fitted"):
        exp.predict(df_dummy)

    with pytest.raises(RuntimeError, match="is not fitted"):
        exp.predict_proba(df_dummy)

    with pytest.raises(RuntimeError, match="is not fitted"):
        exp.evaluate(df_dummy, np.zeros(5))


def test_fit_and_evaluate_lifecycle() -> None:
    """Verify fit, predict, evaluate, and metrics calculation."""
    rng = np.random.RandomState(42)
    n_samples = 100

    # Create dummy DataFrame with 47 columns
    data = {col: rng.randn(n_samples) for col in ML_FEATURE_COLUMNS}
    df = pd.DataFrame(data)
    y = rng.choice([0, 1], size=n_samples)
    attacks = ["Benign" if yi == 0 else "Exploits" for yi in y]

    exp = RobustModelExperiment(
        experiment_id="E1_test",
        feature_set=FEATURES_E1,
        n_estimators=10,
        max_depth=4,
        random_state=42,
    )

    exp.fit(df, y, train_provenance={"test_run": True})
    assert exp.is_fitted
    assert exp.fitted_at_utc is not None
    assert exp.training_duration_seconds is not None

    preds = exp.predict(df)
    assert len(preds) == n_samples
    assert set(preds).issubset({0, 1})

    metrics = exp.evaluate(df, y, attack_names=attacks)
    assert isinstance(metrics, ExperimentMetrics)
    assert 0.0 <= metrics.accuracy <= 1.0
    assert 0.0 <= metrics.false_positive_rate <= 1.0
    assert metrics.total_evaluated_rows == n_samples
    assert "Benign_Specificity" in metrics.per_attack_recall
    assert "Exploits" in metrics.per_attack_recall

    # Manifest generation
    manifest = exp.generate_manifest(metrics, eval_dataset_name="synthetic_test")
    assert manifest["experiment_id"] == "E1_test"
    assert manifest["feature_contract"]["features_count"] == 45
    assert set(manifest["feature_contract"]["excluded_shortcuts"]) == SHORTCUT_TTL_FEATURES
    assert manifest["evaluation"]["metrics"]["accuracy"] == round(metrics.accuracy, 6)


def test_compute_metrics_edge_cases() -> None:
    """Verify compute_metrics handles edge cases such as zero divisions cleanly."""
    y_true = np.array([0, 0, 0, 0])
    y_pred = np.array([0, 0, 0, 0])

    metrics = RobustModelExperiment.compute_metrics(
        y_true=y_true,
        preds=y_pred,
        probs=np.array([0.1, 0.2, 0.1, 0.0]),
        attack_names=["Benign", "Benign", "Benign", "Benign"],
    )

    assert metrics.accuracy == 1.0
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.confusion_matrix["tn"] == 4
    assert metrics.confusion_matrix["fp"] == 0
    assert metrics.confusion_matrix["fn"] == 0
    assert metrics.confusion_matrix["tp"] == 0
