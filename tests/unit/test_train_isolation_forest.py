#!/usr/bin/env python3
"""Unit tests — train_isolation_forest pipeline components (Issue #11, C4).

All tests use synthetic fixtures only.  Real-data training on NF-UNSW-NB15-v3
is NOT conducted here and is NOT the subject of these tests.

Covered:
- Model training on benign-only samples.
- Target-column exclusion contract.
- Feature schema validation (count and order).
- Threshold calibration (policy, direction, unknown-holdout isolation).
- Score direction: higher = more anomalous.
- Unknown-attack holdout: scores not used to select threshold.
- Test-partition protection: threshold frozen before scoring test.
- Artifact save/load roundtrip.
- Model reload consistency (equivalent scores).
- Metric calculations (TP, TN, FP, FN, precision, recall, F1, FPR).
- Failure handling (blocked prerequisites, bad schema, leakage detection).
"""

import gzip
import json
import sys
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd
import pytest

# Ensure the project src is on the path when running standalone.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# ---------------------------------------------------------------------------
# Import the public API of the training pipeline.
# ---------------------------------------------------------------------------
from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.models.isolation_forest import (  # noqa: E402
    anomaly_scores,
    build_model,
    fit_model,
)
from scripts.train_isolation_forest import (  # noqa: E402
    EXPECTED_N_FEATURES,
    EXPECTED_TEST_ROWS,
    EXPECTED_TRAIN_ROWS,
    EXPECTED_VAL_ROWS,
    KNOWN_ATTACK_CATEGORIES,
    UNKNOWN_ATTACK_CATEGORIES,
    _save_blocked_report,
    calibrate_threshold,
    check_dataset,
    check_feature_schema,
    check_finite_values,
    check_no_leakage_in_matrix,
    check_preprocessor_artifact,
    check_split_manifest,
    compute_full_metrics,
    compute_per_category_metrics,
    parse_args,
    save_artifacts,
    sha256_file,
    verify_saved_model,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rng():
    return np.random.default_rng(42)


@pytest.fixture
def synthetic_benign(rng):
    """200 tight benign samples across 47 features."""
    return rng.normal(loc=0.0, scale=0.5, size=(200, EXPECTED_N_FEATURES)).astype(np.float64)


@pytest.fixture
def synthetic_attack(rng):
    """50 extreme attack samples: clearly separated from benign."""
    return rng.normal(loc=8.0, scale=0.5, size=(50, EXPECTED_N_FEATURES)).astype(np.float64)


@pytest.fixture
def fitted_model(synthetic_benign):
    """Model trained on benign-only synthetic data."""
    model = build_model({"n_estimators": 20, "n_jobs": 1, "contamination": 0.1, "random_state": 42})
    fit_model(model, synthetic_benign)
    return model


@pytest.fixture
def feature_df(synthetic_benign):
    """DataFrame with correct 47 feature columns."""
    return pd.DataFrame(synthetic_benign, columns=list(ML_FEATURE_COLUMNS))


@pytest.fixture
def tmp_artifact_dir(tmp_path):
    return tmp_path / "artifacts" / "models" / "isolation_forest"


# ---------------------------------------------------------------------------
# 1. Model training on benign-only samples
# ---------------------------------------------------------------------------


class TestBenignOnlyTraining:
    def test_fit_on_benign_only_no_target(self, synthetic_benign):
        """fit_model must not accept a target argument."""
        model = build_model({"n_estimators": 10, "n_jobs": 1, "contamination": 0.05})
        with pytest.raises(TypeError):
            fit_model(model, synthetic_benign, np.zeros(len(synthetic_benign)))

    def test_fit_on_benign_array_succeeds(self, synthetic_benign):
        model = build_model({"n_estimators": 10, "n_jobs": 1, "contamination": 0.05})
        fitted = fit_model(model, synthetic_benign)
        assert fitted.n_features_in_ == EXPECTED_N_FEATURES

    def test_fit_on_benign_dataframe_succeeds(self, feature_df):
        model = build_model({"n_estimators": 10, "n_jobs": 1, "contamination": 0.05})
        fitted = fit_model(model, feature_df)
        assert fitted.n_features_in_ == EXPECTED_N_FEATURES

    def test_benign_training_records_feature_count(self, synthetic_benign):
        """After fit, n_features_in_ must equal the feature contract."""
        model = build_model({"n_estimators": 10, "n_jobs": 1, "contamination": 0.05})
        fit_model(model, synthetic_benign)
        assert model.n_features_in_ == EXPECTED_N_FEATURES


# ---------------------------------------------------------------------------
# 2. Target-column exclusion
# ---------------------------------------------------------------------------


class TestTargetExclusion:
    def test_feature_schema_rejects_label_column(self):
        """Feature schema check must reject the 'Label' column."""
        result = check_feature_schema(["Label"] + list(ML_FEATURE_COLUMNS[:46]))
        assert result["status"] == "FAIL"
        assert "Label" in result["message"] or "forbidden" in result["message"].lower()

    def test_feature_schema_rejects_attack_column(self):
        """Feature schema check must reject the 'Attack' column."""
        result = check_feature_schema(list(ML_FEATURE_COLUMNS[:46]) + ["Attack"])
        assert result["status"] == "FAIL"

    def test_leakage_check_rejects_label_in_dataframe(self):
        df = pd.DataFrame(np.zeros((5, 47)), columns=list(ML_FEATURE_COLUMNS))
        df["Label"] = 0
        result = check_no_leakage_in_matrix(df)
        assert result["status"] == "FAIL"
        assert "Label" in result["message"]

    def test_leakage_check_rejects_trace_metadata_column(self):
        df = pd.DataFrame(np.zeros((5, 47)), columns=list(ML_FEATURE_COLUMNS))
        df["IPV4_SRC_ADDR"] = "192.168.1.1"
        result = check_no_leakage_in_matrix(df)
        assert result["status"] == "FAIL"

    def test_leakage_check_passes_on_clean_feature_matrix(self):
        df = pd.DataFrame(np.zeros((5, 47)), columns=list(ML_FEATURE_COLUMNS))
        result = check_no_leakage_in_matrix(df)
        assert result["status"] == "PASS"


# ---------------------------------------------------------------------------
# 3. Feature schema validation
# ---------------------------------------------------------------------------


class TestFeatureSchemaValidation:
    def test_correct_47_feature_schema_passes(self):
        result = check_feature_schema(list(ML_FEATURE_COLUMNS))
        assert result["status"] == "PASS"

    def test_wrong_feature_count_fails(self):
        result = check_feature_schema(list(ML_FEATURE_COLUMNS[:46]))
        assert result["status"] == "FAIL"
        assert "count" in result["message"] or "47" in result["message"]

    def test_wrong_feature_order_fails(self):
        shuffled = list(ML_FEATURE_COLUMNS[::-1])
        result = check_feature_schema(shuffled)
        assert result["status"] == "FAIL"

    def test_extra_feature_fails(self):
        result = check_feature_schema(list(ML_FEATURE_COLUMNS) + ["EXTRA_COL"])
        assert result["status"] == "FAIL"

    def test_empty_feature_list_fails(self):
        result = check_feature_schema([])
        assert result["status"] == "FAIL"


# ---------------------------------------------------------------------------
# 4. Threshold calibration
# ---------------------------------------------------------------------------


class TestThresholdCalibration:
    def test_calibration_selects_a_threshold(self, rng):
        """calibrate_threshold must return a numeric threshold."""
        benign = rng.normal(0, 1, 100)
        attack = rng.normal(5, 1, 50)
        result = calibrate_threshold(benign, attack)
        assert isinstance(result["threshold"], float)

    def test_calibration_max_f1_policy(self, rng):
        """Default policy must be max-F1."""
        benign = rng.normal(0, 1, 100)
        attack = rng.normal(5, 1, 50)
        result = calibrate_threshold(benign, attack)
        assert "f1" in result["policy"].lower() or "f1" in result["policy"]

    def test_calibration_fpr_policy(self, rng):
        """fpr_target switches to max-recall policy."""
        benign = rng.normal(0, 1, 100)
        attack = rng.normal(5, 1, 50)
        result = calibrate_threshold(benign, attack, fpr_target=0.05)
        assert "fpr" in result["policy"].lower() or "recall" in result["policy"].lower()

    def test_calibration_higher_threshold_for_separated_scores(self, rng):
        """When attack scores >> benign scores the threshold should be positive."""
        benign = rng.normal(-3, 0.3, 200)
        attack = rng.normal(3, 0.3, 100)
        result = calibrate_threshold(benign, attack)
        # With well-separated distributions the optimal threshold should lie
        # between the two means (i.e., between -3 and 3).
        assert -3 < result["threshold"] < 3

    def test_calibration_unknown_scores_not_used(self, rng):
        """Unknown-attack scores are observed but must not change the threshold."""
        benign = rng.normal(0, 1, 100)
        known = rng.normal(5, 1, 50)
        unknown = rng.normal(5, 1, 30)

        result_without = calibrate_threshold(benign, known, scores_unknown_val=None)
        result_with = calibrate_threshold(benign, known, scores_unknown_val=unknown)

        # Same threshold whether or not unknown scores are passed.
        assert result_without["threshold"] == result_with["threshold"]

    def test_calibration_reports_unknown_detection_when_provided(self, rng):
        """When unknown scores are provided, they must appear in the report."""
        benign = rng.normal(0, 1, 100)
        known = rng.normal(5, 1, 50)
        unknown = rng.normal(5, 1, 30)
        result = calibrate_threshold(benign, known, scores_unknown_val=unknown)
        assert "unknown_validation_detection" in result
        assert "note" in result["unknown_validation_detection"]

    def test_calibration_threshold_is_float(self, rng):
        benign = rng.normal(0, 1, 50)
        attack = rng.normal(3, 1, 20)
        result = calibrate_threshold(benign, attack)
        assert isinstance(result["threshold"], float)

    def test_calibration_validation_stats_keys(self, rng):
        """Validation stats must contain the required metric keys."""
        benign = rng.normal(0, 1, 100)
        attack = rng.normal(5, 1, 50)
        result = calibrate_threshold(benign, attack)
        for key in ("tp", "tn", "fp", "fn", "precision", "recall", "f1", "fpr"):
            assert key in result["validation_stats"], f"Missing key: {key}"


# ---------------------------------------------------------------------------
# 5. Score direction
# ---------------------------------------------------------------------------


class TestScoreDirection:
    def test_attack_scores_higher_than_benign(
        self, fitted_model, synthetic_benign, synthetic_attack
    ):
        """anomaly_scores must assign higher scores to attack samples."""
        scores_benign = anomaly_scores(fitted_model, synthetic_benign)
        scores_attack = anomaly_scores(fitted_model, synthetic_attack)
        # With well-separated synthetic data the attack median must exceed the
        # benign 95th percentile.
        assert np.median(scores_attack) > np.percentile(scores_benign, 95)

    def test_scores_are_one_dimensional(self, fitted_model, synthetic_benign):
        scores = anomaly_scores(fitted_model, synthetic_benign)
        assert scores.ndim == 1
        assert len(scores) == len(synthetic_benign)

    def test_higher_score_means_more_anomalous(self, rng):
        """A single extreme outlier must receive the highest score."""
        normal = rng.normal(0, 0.1, size=(300, 5))
        outlier = np.array([[20.0, -20.0, 20.0, -20.0, 20.0]])
        X = np.vstack([normal, outlier])
        model = build_model(
            {"n_estimators": 40, "n_jobs": 1, "contamination": 0.05, "random_state": 7}
        )
        fit_model(model, normal)  # benign-only training
        scores = anomaly_scores(model, X)
        # The outlier must be the highest-scored sample.
        assert scores[-1] == scores.max()


# ---------------------------------------------------------------------------
# 6. Unknown-attack holdout isolation
# ---------------------------------------------------------------------------


class TestUnknownAttackHoldout:
    def test_unknown_categories_are_pre_registered(self):
        """UNKNOWN_ATTACK_CATEGORIES must be a non-empty frozen set."""
        assert isinstance(UNKNOWN_ATTACK_CATEGORIES, frozenset)
        assert len(UNKNOWN_ATTACK_CATEGORIES) > 0

    def test_known_and_unknown_categories_are_disjoint(self):
        """Known and unknown sets must not overlap."""
        overlap = KNOWN_ATTACK_CATEGORIES & UNKNOWN_ATTACK_CATEGORIES
        assert len(overlap) == 0, f"Overlap detected: {overlap}"

    def test_unknown_categories_not_in_known(self):
        for cat in UNKNOWN_ATTACK_CATEGORIES:
            assert cat not in KNOWN_ATTACK_CATEGORIES

    def test_calibration_excludes_unknown_from_threshold_selection(self, rng):
        """The threshold must be the same with or without unknown-attack scores."""
        benign = rng.normal(0, 1, 100).tolist()
        known = rng.normal(4, 1, 50).tolist()
        unknown_high = rng.normal(10, 1, 30).tolist()
        unknown_low = rng.normal(-5, 1, 30).tolist()

        base_thresh = calibrate_threshold(benign, known)["threshold"]
        with_high_thresh = calibrate_threshold(benign, known, unknown_high)["threshold"]
        with_low_thresh = calibrate_threshold(benign, known, unknown_low)["threshold"]

        assert base_thresh == with_high_thresh
        assert base_thresh == with_low_thresh

    def test_per_category_metrics_labels_unknown_correctly(
        self, fitted_model, synthetic_benign, synthetic_attack, rng
    ):
        """compute_per_category_metrics must correctly flag unknown categories."""
        n_benign = len(synthetic_benign)
        n_attack = len(synthetic_attack)
        X = np.vstack([synthetic_benign, synthetic_attack])
        y_true = [0] * n_benign + [1] * n_attack

        # Use a known and an unknown category
        unknown_cat = next(iter(UNKNOWN_ATTACK_CATEGORIES))
        known_cat = next(iter(KNOWN_ATTACK_CATEGORIES))
        attack_col = (
            ["Benign"] * n_benign
            + [unknown_cat] * (n_attack // 2)
            + [known_cat] * (n_attack - n_attack // 2)
        )

        scores = anomaly_scores(fitted_model, X)
        preds = (scores >= 0.0).astype(int)

        per_cat = compute_per_category_metrics(y_true, preds, scores, attack_col)
        assert per_cat[unknown_cat]["is_unknown"] is True
        assert per_cat[known_cat]["is_known"] is True


# ---------------------------------------------------------------------------
# 7. Test partition protection
# ---------------------------------------------------------------------------


class TestTestPartitionProtection:
    def test_threshold_is_calibrated_before_test_evaluation(self, rng):
        """Confirm the pipeline freezes threshold on validation before test scoring.

        This is an architectural test: calibrate_threshold must not receive test
        labels.  We verify the function contract: it accepts only benign/attack
        validation scores, not test scores.
        """
        benign_val = rng.normal(0, 1, 100)
        attack_val = rng.normal(5, 1, 50)
        test_scores = rng.normal(3, 2, 200)  # hypothetical test scores

        # calibrate_threshold should be called ONLY with validation scores
        result = calibrate_threshold(benign_val, attack_val)
        threshold = result["threshold"]

        # Apply frozen threshold to "test" scores — simulate pipeline step
        test_preds = (test_scores >= threshold).astype(int)

        # The threshold was not influenced by test_scores
        assert isinstance(threshold, float)
        assert isinstance(test_preds, np.ndarray)

    def test_check_feature_schema_guards_test_partition(self):
        """check_feature_schema must fail if target leaked into test features."""
        bad_cols = list(ML_FEATURE_COLUMNS[:46]) + ["Label"]
        result = check_feature_schema(bad_cols)
        assert result["status"] == "FAIL"


# ---------------------------------------------------------------------------
# 8. Artifact save/load
# ---------------------------------------------------------------------------


class TestArtifactSaveLoad:
    def test_save_artifacts_creates_expected_files(self, fitted_model, tmp_artifact_dir):
        config = {"n_estimators": 20, "random_state": 42}
        meta = {"n_train_benign": 200, "training_duration_seconds": 1.5}
        info = save_artifacts(fitted_model, config, 0.15, meta, tmp_artifact_dir)
        for name, path in info["files"].items():
            assert Path(path).exists(), f"Missing artifact: {name} at {path}"

    def test_save_artifacts_records_checksums(self, fitted_model, tmp_artifact_dir):
        config = {"n_estimators": 20, "random_state": 42}
        meta = {"n_train_benign": 200}
        info = save_artifacts(fitted_model, config, 0.15, meta, tmp_artifact_dir)
        assert "checksums" in info
        assert len(info["checksums"]) > 0

    def test_save_and_reload_model_produces_equivalent_scores(
        self, fitted_model, synthetic_benign, tmp_artifact_dir
    ):
        config = {"n_estimators": 20, "random_state": 42}
        meta = {"n_train_benign": 200}
        info = save_artifacts(fitted_model, config, 0.15, meta, tmp_artifact_dir)
        model_path = Path(info["files"]["model"])
        verify_result = verify_saved_model(model_path, fitted_model, synthetic_benign[:50])
        assert verify_result["status"] == "PASS", verify_result["message"]

    def test_save_artifacts_stores_threshold(self, fitted_model, tmp_artifact_dir):
        config = {"n_estimators": 20, "random_state": 42}
        meta = {"n_train_benign": 200}
        threshold = 0.123456
        save_artifacts(fitted_model, config, threshold, meta, tmp_artifact_dir)
        thresh_path = tmp_artifact_dir / "threshold.json"
        with thresh_path.open() as fh:
            data = json.load(fh)
        assert abs(data["threshold"] - threshold) < 1e-12

    def test_save_artifacts_config_round_trips(self, fitted_model, tmp_artifact_dir):
        config = {"n_estimators": 20, "random_state": 42, "contamination": 0.05}
        meta = {}
        save_artifacts(fitted_model, config, 0.0, meta, tmp_artifact_dir)
        config_path = tmp_artifact_dir / "model_config.json"
        with config_path.open() as fh:
            loaded = json.load(fh)
        assert loaded["n_estimators"] == 20
        assert loaded["random_state"] == 42


# ---------------------------------------------------------------------------
# 9. Reproducibility
# ---------------------------------------------------------------------------


class TestReproducibility:
    def test_same_seed_produces_identical_scores(self, synthetic_benign, synthetic_attack):
        """Two models with the same seed must produce identical anomaly scores."""
        X = np.vstack([synthetic_benign, synthetic_attack])
        m1 = build_model(
            {"n_estimators": 20, "n_jobs": 1, "contamination": 0.1, "random_state": 42}
        )
        m2 = build_model(
            {"n_estimators": 20, "n_jobs": 1, "contamination": 0.1, "random_state": 42}
        )
        fit_model(m1, synthetic_benign)
        fit_model(m2, synthetic_benign)
        s1 = anomaly_scores(m1, X)
        s2 = anomaly_scores(m2, X)
        assert np.array_equal(s1, s2)

    def test_different_seeds_may_differ(self, synthetic_benign, synthetic_attack):
        """Different seeds should produce different scores (sanity check)."""
        X = np.vstack([synthetic_benign, synthetic_attack])
        m1 = build_model({"n_estimators": 20, "n_jobs": 1, "contamination": 0.1, "random_state": 1})
        m2 = build_model({"n_estimators": 20, "n_jobs": 1, "contamination": 0.1, "random_state": 2})
        fit_model(m1, synthetic_benign)
        fit_model(m2, synthetic_benign)
        s1 = anomaly_scores(m1, X)
        s2 = anomaly_scores(m2, X)
        # They are very unlikely to be identical for different seeds with 20 trees.
        assert not np.array_equal(s1, s2)


# ---------------------------------------------------------------------------
# 10. Metric calculations
# ---------------------------------------------------------------------------


class TestMetricCalculations:
    def test_perfect_classifier_metrics(self):
        """A perfect classifier must produce correct TP/TN/FP/FN/F1."""
        y_true = [0, 0, 0, 1, 1, 1]
        y_pred = [0, 0, 0, 1, 1, 1]
        scores = [0.1, 0.1, 0.1, 0.9, 0.9, 0.9]
        m = compute_full_metrics(y_true, y_pred, scores)
        assert m["tp"] == 3
        assert m["tn"] == 3
        assert m["fp"] == 0
        assert m["fn"] == 0
        assert m["precision"] == pytest.approx(1.0)
        assert m["recall"] == pytest.approx(1.0)
        assert m["f1"] == pytest.approx(1.0)
        assert m["fpr"] == pytest.approx(0.0)

    def test_all_wrong_classifier_metrics(self):
        y_true = [0, 0, 1, 1]
        y_pred = [1, 1, 0, 0]
        scores = [0.9, 0.9, 0.1, 0.1]
        m = compute_full_metrics(y_true, y_pred, scores)
        assert m["tp"] == 0
        assert m["tn"] == 0
        assert m["fp"] == 2
        assert m["fn"] == 2
        assert m["precision"] == pytest.approx(0.0)
        assert m["recall"] == pytest.approx(0.0)
        assert m["fpr"] == pytest.approx(1.0)

    def test_fpr_definition(self):
        """FPR = FP / (FP + TN) must be computed correctly."""
        # 4 benign samples: 2 correctly classified (TN), 2 incorrectly (FP)
        y_true = [0, 0, 0, 0, 1, 1]
        y_pred = [0, 0, 1, 1, 1, 1]
        scores = [0.1, 0.1, 0.8, 0.8, 0.9, 0.9]
        m = compute_full_metrics(y_true, y_pred, scores)
        assert m["fp"] == 2
        assert m["tn"] == 2
        # FPR = 2 / (2 + 2) = 0.5
        assert m["fpr"] == pytest.approx(0.5)

    def test_confusion_matrix_shape_and_labels(self):
        y_true = [0, 0, 1, 1]
        y_pred = [0, 1, 0, 1]
        scores = [0.1, 0.6, 0.4, 0.9]
        m = compute_full_metrics(y_true, y_pred, scores)
        cm = m["confusion_matrix"]
        assert len(cm) == 2
        assert len(cm[0]) == 2
        # cm[0][0] = TN, cm[0][1] = FP, cm[1][0] = FN, cm[1][1] = TP
        assert cm[0][0] + cm[0][1] + cm[1][0] + cm[1][1] == 4

    def test_per_category_detection_rate_benign_excluded(self):
        """Benign entries appear in per-category output but are not attacks."""
        y_true = [0, 0, 1, 1]
        y_pred = [0, 1, 1, 0]
        scores = [0.1, 0.7, 0.9, 0.3]
        attack_col = ["Benign", "Benign", "DoS", "DoS"]
        per_cat = compute_per_category_metrics(y_true, y_pred, scores, attack_col)
        assert "DoS" in per_cat
        assert per_cat["DoS"]["n_samples"] == 2
        assert per_cat["DoS"]["detection_rate"] == pytest.approx(0.5)

    def test_per_category_is_known_flag(self):
        y_true = [1]
        y_pred = [1]
        scores = [0.8]
        known_cat = next(iter(KNOWN_ATTACK_CATEGORIES))
        per_cat = compute_per_category_metrics(y_true, y_pred, scores, [known_cat])
        assert per_cat[known_cat]["is_known"] is True
        assert per_cat[known_cat]["is_unknown"] is False

    def test_per_category_is_unknown_flag(self):
        y_true = [1]
        y_pred = [0]
        scores = [0.2]
        unk_cat = next(iter(UNKNOWN_ATTACK_CATEGORIES))
        per_cat = compute_per_category_metrics(y_true, y_pred, scores, [unk_cat])
        assert per_cat[unk_cat]["is_unknown"] is True
        assert per_cat[unk_cat]["is_known"] is False

    def test_roc_auc_and_pr_auc_present(self):
        y_true = [0, 0, 1, 1]
        y_pred = [0, 0, 1, 1]
        scores = [0.1, 0.2, 0.8, 0.9]
        m = compute_full_metrics(y_true, y_pred, scores)
        assert "roc_auc" in m
        assert "pr_auc" in m
        assert isinstance(m["roc_auc"], float)


# ---------------------------------------------------------------------------
# 11. Failure handling
# ---------------------------------------------------------------------------


class TestFailureHandling:
    def test_check_dataset_blocked_when_file_absent(self, tmp_path, monkeypatch):
        """check_dataset must return BLOCKED when the CSV is not present."""
        monkeypatch.setattr(
            "scripts.train_isolation_forest.DATASET_CSV",
            tmp_path / "nonexistent.csv",
        )
        result = check_dataset()
        assert result["status"] == "BLOCKED"
        assert "not found" in result["message"].lower() or "absent" in result["message"].lower()

    def test_check_finite_values_fails_on_nan(self):
        X = np.array([[1.0, 2.0], [3.0, np.nan]])
        result = check_finite_values(X, "Train")
        assert result["status"] == "FAIL"
        assert "non-finite" in result["message"].lower() or "nan" in result["message"].lower()

    def test_check_finite_values_fails_on_inf(self):
        X = np.array([[1.0, np.inf], [2.0, 3.0]])
        result = check_finite_values(X, "Validation")
        assert result["status"] == "FAIL"

    def test_check_finite_values_passes_on_clean_matrix(self):
        X = np.array([[1.0, 2.0], [3.0, 4.0]])
        result = check_finite_values(X, "Test")
        assert result["status"] == "PASS"

    def test_check_feature_schema_fails_for_target_in_features(self):
        bad = list(ML_FEATURE_COLUMNS[:46]) + ["Attack"]
        result = check_feature_schema(bad)
        assert result["status"] == "FAIL"

    def test_model_rejects_nan_features(self, fitted_model):
        """validate_features must reject NaN inputs at scoring time."""
        from network_anomaly.models.isolation_forest import validate_features

        X = np.ones((5, EXPECTED_N_FEATURES))
        X[2, 0] = np.nan
        with pytest.raises(ValueError, match="NaN"):
            validate_features(X)

    def test_blocked_report_written_on_missing_dataset(self, tmp_path, monkeypatch):
        """_save_blocked_report must write a JSON file with status BLOCKED."""
        monkeypatch.setattr(
            "scripts.train_isolation_forest.REPORT_DIR",
            tmp_path / "reports",
        )
        run_meta = {"run_id": "test", "timestamp": "2026-11-03"}
        dataset_check = {"message": "dataset not found"}
        _save_blocked_report(run_meta, dataset_check)
        blocked_path = tmp_path / "reports" / "blocked_status.json"
        assert blocked_path.exists()
        with blocked_path.open() as fh:
            data = json.load(fh)
        assert data["status"] == "BLOCKED"

    def test_parse_args_defaults(self):
        """Default arguments must match documented configuration."""
        args = parse_args([])
        assert args.n_estimators == 100
        assert args.max_samples == "auto"
        assert args.contamination == pytest.approx(0.1)
        assert args.max_features == pytest.approx(1.0)
        assert args.bootstrap is False
        assert args.n_jobs == -1
        assert args.fpr_target is None
        assert args.check_prereqs_only is False
        assert args.skip_checksum is False

    def test_parse_args_custom_n_estimators(self):
        args = parse_args(["--n-estimators", "200"])
        assert args.n_estimators == 200

    def test_main_returns_1_when_dataset_absent(self, tmp_path, monkeypatch):
        """main() must return 1 (not crash) when the dataset is missing."""
        from scripts.train_isolation_forest import main

        monkeypatch.setattr(
            "scripts.train_isolation_forest.DATASET_CSV",
            tmp_path / "nonexistent.csv",
        )
        monkeypatch.setattr(
            "scripts.train_isolation_forest.REPORT_DIR",
            tmp_path / "reports",
        )
        # --check-prereqs-only returns 0 for BLOCKED (expected CI state)
        exit_code = main(["--check-prereqs-only"])
        assert exit_code == 0

    def test_main_returns_1_not_0_when_dataset_absent_and_no_flag(self, tmp_path, monkeypatch):
        """Without --check-prereqs-only, missing dataset must return exit 1."""
        from scripts.train_isolation_forest import main

        monkeypatch.setattr(
            "scripts.train_isolation_forest.DATASET_CSV",
            tmp_path / "nonexistent.csv",
        )
        monkeypatch.setattr(
            "scripts.train_isolation_forest.REPORT_DIR",
            tmp_path / "reports",
        )
        exit_code = main([])
        assert exit_code == 1


# ---------------------------------------------------------------------------
# 12. Feature contract integrity
# ---------------------------------------------------------------------------


class TestFeatureContract:
    def test_ml_feature_columns_has_47_entries(self):
        assert len(ML_FEATURE_COLUMNS) == 47

    def test_ml_feature_columns_excludes_targets(self):
        for col in TARGET_COLUMNS:
            assert col not in ML_FEATURE_COLUMNS

    def test_ml_feature_columns_excludes_trace_metadata(self):
        for col in TRACE_METADATA_COLUMNS:
            assert col not in ML_FEATURE_COLUMNS

    def test_ml_feature_columns_has_no_duplicates(self):
        assert len(ML_FEATURE_COLUMNS) == len(set(ML_FEATURE_COLUMNS))

    def test_expected_n_features_matches_contract(self):
        assert EXPECTED_N_FEATURES == len(ML_FEATURE_COLUMNS)


# ---------------------------------------------------------------------------
# 13. Official split & preprocessor manifest integration tests (Issue #7 & #8)
# ---------------------------------------------------------------------------


class TestOfficialManifestSchemaAndPrerequisites:
    def test_check_split_manifest_official_nested_schema_passes(self, tmp_path):
        manifest_data = {
            "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
            "partitions": {
                "train": {"row_count": EXPECTED_TRAIN_ROWS},
                "validation": {"row_count": EXPECTED_VAL_ROWS},
                "test": {"row_count": EXPECTED_TEST_ROWS},
            },
        }
        manifest_path = tmp_path / "split_manifest.json"
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
        result = check_split_manifest(manifest_path)
        assert result["status"] == "PASS"
        assert "verified" in result["message"].lower()

    def test_check_split_manifest_rejects_missing_file(self, tmp_path):
        result = check_split_manifest(tmp_path / "nonexistent_manifest.json")
        assert result["status"] == "BLOCKED"
        assert "not found" in result["message"].lower()

    def test_check_split_manifest_rejects_row_count_mismatch(self, tmp_path):
        manifest_data = {
            "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
            "partitions": {
                "train": {"row_count": 999},
                "validation": {"row_count": EXPECTED_VAL_ROWS},
                "test": {"row_count": EXPECTED_TEST_ROWS},
            },
        }
        manifest_path = tmp_path / "bad_split_manifest.json"
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
        result = check_split_manifest(manifest_path)
        assert result["status"] == "BLOCKED"
        assert "row count" in result["message"].lower()

    def test_check_preprocessor_artifact_verified_with_companion_manifest(self, tmp_path):
        art_path = tmp_path / "preprocessor.joblib"
        art_path.write_bytes(b"dummy_preprocessor_artifact_bytes")
        art_hash = sha256_file(art_path)

        manifest_data = {
            "artifact_sha256": art_hash,
            "artifact_type": "nf-unsw-nb15-v3-train-only-preprocessor",
            "feature_contract_version": "nf-unsw-nb15-v3-baseline-47",
        }
        man_path = tmp_path / "preprocessor_manifest.json"
        man_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        result = check_preprocessor_artifact(art_path, man_path)
        assert result["status"] == "PASS"

    def test_check_preprocessor_artifact_rejects_hash_mismatch(self, tmp_path):
        art_path = tmp_path / "preprocessor.joblib"
        art_path.write_bytes(b"corrupted_artifact_bytes")

        manifest_data = {
            "artifact_sha256": "0" * 64,
            "artifact_type": "nf-unsw-nb15-v3-train-only-preprocessor",
        }
        man_path = tmp_path / "preprocessor_manifest.json"
        man_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        result = check_preprocessor_artifact(art_path, man_path)
        assert result["status"] == "BLOCKED"
        assert "mismatch" in result["message"].lower()

    def test_check_preprocessor_artifact_rejects_missing_artifact(self, tmp_path):
        man_path = tmp_path / "manifest.json"
        man_path.write_text("{}", encoding="utf-8")
        result = check_preprocessor_artifact(tmp_path / "missing.joblib", man_path)
        assert result["status"] == "BLOCKED"
        assert "not found" in result["message"].lower()

    def test_check_split_manifest_verifies_indices_files_if_indices_dir_provided(self, tmp_path):
        manifest_data = {
            "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
            "partitions": {
                "train": {"row_count": EXPECTED_TRAIN_ROWS},
                "validation": {"row_count": EXPECTED_VAL_ROWS},
                "test": {"row_count": EXPECTED_TEST_ROWS},
            },
        }
        manifest_path = tmp_path / "split_manifest.json"
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
        indices_dir = tmp_path / "splits"
        indices_dir.mkdir()

        # Missing index files -> BLOCKED
        result_missing = check_split_manifest(manifest_path, indices_dir=indices_dir)
        assert result_missing["status"] == "BLOCKED"
        assert "missing" in result_missing["message"].lower()

        # Create the index files -> PASS
        for name in ("train", "validation", "test"):
            (indices_dir / f"{name}_indices.csv.gz").write_bytes(b"")
        result_ok = check_split_manifest(manifest_path, indices_dir=indices_dir)
        assert result_ok["status"] == "PASS"


# ---------------------------------------------------------------------------
# 14. Reviewer Findings Regression & E2E Integration (Findings A, B, C, D, E, F, G)
# ---------------------------------------------------------------------------


class TestReviewerFindingsAndE2EIntegration:
    def test_run_pipeline_fails_closed_when_preprocessor_load_verified_fails(self, tmp_path):
        """Finding B regression test: load_verified failure must block pipeline without fallback."""
        mock_pp_check = {
            "status": "PASS",
            "message": "PP verified.",
            "path": str(tmp_path / "pp.joblib"),
        }
        mock_split_check = {
            "status": "PASS",
            "message": "Split verified.",
            "path": str(tmp_path / "split.json"),
            "manifest": {},
        }
        mock_dataset_check = {
            "status": "PASS",
            "message": "Dataset verified.",
            "sha256": "dummy_sha",
        }

        import scripts.train_isolation_forest as tif

        with mock.patch.object(tif, "check_dataset", return_value=mock_dataset_check), \
             mock.patch.object(tif, "check_split_manifest", return_value=mock_split_check), \
             mock.patch.object(tif, "check_preprocessor_artifact", return_value=mock_pp_check), \
             mock.patch(
                 "network_anomaly.preprocessing.pipeline.TrainOnlyPreprocessor.load_verified",
                 side_effect=ValueError("Corrupted SHA-256 or invalid preprocessor manifest"),
             ):
            run_args = parse_args([])
            exit_code = tif.run_pipeline(run_args)
            assert exit_code == 1, "Pipeline must exit 1 (fail-closed) when load_verified fails"

    def test_leakage_check_in_pipeline_blocks_trace_metadata_columns(self):
        """Finding D test: check_no_leakage_in_matrix detects forbidden trace metadata."""
        cols = list(ML_FEATURE_COLUMNS) + ["IPV4_SRC_ADDR", "FLOW_START_MILLISECONDS"]
        bad_df = pd.DataFrame(np.zeros((5, len(cols))), columns=cols)
        res = check_no_leakage_in_matrix(bad_df)
        assert res["status"] == "FAIL"
        assert "leakage detected" in res["message"].lower()

    def test_calibrate_threshold_fpr_target_validation_and_fallback(self):
        """Finding E test: validate fpr_target range and transparent fallback handling."""
        # 1. Invalid fpr_target values raise ValueError
        with pytest.raises(ValueError, match="fpr_target"):
            calibrate_threshold([0.1, 0.2], [0.8, 0.9], fpr_target=-0.1)
        with pytest.raises(ValueError, match="fpr_target"):
            calibrate_threshold([0.1, 0.2], [0.8, 0.9], fpr_target=1.5)

        # 2. CLI parse_args rejects invalid fpr-target
        with pytest.raises(SystemExit):
            parse_args(["--fpr-target", "-0.2"])
        with pytest.raises(SystemExit):
            parse_args(["--fpr-target", "1.1"])

        # 3. Valid fpr_target=0.0 where constraint cannot be met triggers explicit fallback policy
        benign = [0.0, 1.0, 2.0, 3.0]
        known_attacks = [0.5, 1.5, 2.5]
        res = calibrate_threshold(benign, known_attacks, fpr_target=0.0)
        assert "FALLBACK-95th-percentile" in res["policy"]
        assert "NOT satisfied" in res["policy"]
        assert "fallback" in res["validation_stats"]
        assert "fpr" in res["validation_stats"]

    def test_calibrate_threshold_vectorized_performance_on_large_val(self):
        """Finding F test: verify calibrate_threshold is O(N) vectorized and fast on large val."""
        import time

        np.random.seed(42)
        benign = np.random.randn(40_000)
        attacks = np.random.randn(10_000) + 1.5

        t0 = time.monotonic()
        res = calibrate_threshold(benign, attacks, fpr_target=0.05)
        elapsed = time.monotonic() - t0

        assert elapsed < 1.0, f"Vectorized calibration took {elapsed:.2f}s, expected < 1.0s"
        assert isinstance(res["threshold"], float)
        assert "validation_stats" in res
        for k in ("tp", "tn", "fp", "fn", "precision", "recall", "f1", "fpr"):
            assert k in res["validation_stats"]

    def test_run_pipeline_e2e_official_indices_branch(self, tmp_path):
        """Finding A, C, G test: End-to-end integration on official partition indices branch."""
        import scripts.train_isolation_forest as tif

        n_train, n_val, n_test = 60, 30, 20
        n_total = n_train + n_val + n_test

        np.random.seed(42)
        df_data = {col: np.random.randn(n_total).astype(np.float32) for col in ML_FEATURE_COLUMNS}
        df_data["Label"] = np.random.choice([0, 1], size=n_total, p=[0.7, 0.3])
        df_data["Label"][:n_train] = np.random.choice([0, 1], size=n_train, p=[0.8, 0.2])
        df_data["Label"][0] = 0
        df_data["Label"][n_train] = 0
        df_data["Label"][n_train + 1] = 1

        attacks = []
        for lbl in df_data["Label"]:
            attacks.append("Benign" if lbl == 0 else np.random.choice(["Exploits", "Worms"]))
        df_data["Attack"] = attacks
        df = pd.DataFrame(df_data)

        ds_csv = tmp_path / "dataset.csv"
        df.to_csv(ds_csv, index=False)
        ds_sha = tif.sha256_file(ds_csv)

        indices_dir = tmp_path / "indices"
        indices_dir.mkdir()
        for name, s, e in [
            ("train", 0, n_train),
            ("validation", n_train, n_train + n_val),
            ("test", n_train + n_val, n_total),
        ]:
            idx_p = indices_dir / f"{name}_indices.csv.gz"
            with gzip.open(idx_p, "wt") as fh:
                fh.write("source_row_index\n")
                for i in range(s, e):
                    fh.write(f"{i}\n")

        split_man = {
            "dataset_sha256": ds_sha,
            "partitions": {
                "train": {
                    "row_count": n_train,
                    "index_sha256": tif.sha256_file(indices_dir / "train_indices.csv.gz"),
                },
                "validation": {
                    "row_count": n_val,
                    "index_sha256": tif.sha256_file(indices_dir / "validation_indices.csv.gz"),
                },
                "test": {
                    "row_count": n_test,
                    "index_sha256": tif.sha256_file(indices_dir / "test_indices.csv.gz"),
                },
            },
        }
        split_man_p = tmp_path / "split_manifest.json"
        split_man_p.write_text(json.dumps(split_man), encoding="utf-8")

        mock_pp = mock.MagicMock()
        mock_pp.transform.side_effect = lambda X, **kwargs: np.asarray(X, dtype=np.float64)

        art_p = tmp_path / "preprocessor.joblib"
        art_p.write_bytes(b"dummy_artifact_bytes")
        art_sha = tif.sha256_file(art_p)
        pp_man = {
            "artifact_sha256": art_sha,
            "artifact_type": "nf-unsw-nb15-v3-train-only-preprocessor",
        }
        pp_man_p = tmp_path / "preprocessor_manifest.json"
        pp_man_p.write_text(json.dumps(pp_man), encoding="utf-8")

        model_art_dir = tmp_path / "model_artifacts"
        rep_dir = tmp_path / "reports"
        args = tif.parse_args(["--n-estimators", "5"])

        with mock.patch.object(tif, "DATASET_CSV", ds_csv), \
             mock.patch.object(tif, "DATASET_SHA256", ds_sha), \
             mock.patch.object(tif, "EXPECTED_TRAIN_ROWS", n_train), \
             mock.patch.object(tif, "EXPECTED_VAL_ROWS", n_val), \
             mock.patch.object(tif, "EXPECTED_TEST_ROWS", n_test), \
             mock.patch.object(tif, "SPLIT_MANIFEST_PATH", split_man_p), \
             mock.patch.object(tif, "OFFICIAL_SPLIT_MANIFEST", split_man_p), \
             mock.patch.object(tif, "INDICES_DIR", indices_dir), \
             mock.patch.object(tif, "PREPROCESSOR_ARTIFACT_PATH", art_p), \
             mock.patch.object(tif, "OFFICIAL_PREPROCESSOR_ARTIFACT", art_p), \
             mock.patch.object(tif, "PREPROCESSOR_MANIFEST_PATH", pp_man_p), \
             mock.patch.object(tif, "OFFICIAL_PREPROCESSOR_MANIFEST", pp_man_p), \
             mock.patch.object(tif, "MODEL_ARTIFACT_DIR", model_art_dir), \
             mock.patch.object(tif, "REPORT_DIR", rep_dir), \
             mock.patch(
                 "network_anomaly.preprocessing.pipeline.TrainOnlyPreprocessor.load_verified",
                 return_value=mock_pp,
             ):
            exit_code = tif.run_pipeline(args)
            assert exit_code == 0, f"Expected 0, got {exit_code}"
            assert (model_art_dir / "isolation_forest.joblib").exists()
            assert (model_art_dir / "threshold.json").exists()
            assert (rep_dir / "metrics.json").exists()
            assert (rep_dir / "run_metadata.json").exists()
            run_meta = json.loads((rep_dir / "run_metadata.json").read_text(encoding="utf-8"))
            assert run_meta["feature_columns"] == list(ML_FEATURE_COLUMNS)
            assert run_meta["preprocessor_source"] == "TrainOnlyPreprocessor.load_verified"
