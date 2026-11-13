#!/usr/bin/env python3
"""Unit tests — Isolation Forest model component (Issue #11).

Synthetic fixtures only. These tests cover configuration, validation and the
model contract; they do not fit on UNSW-NB15 and are not experimental results.
"""

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

from network_anomaly import config
from network_anomaly.models.isolation_forest import (
    SUPPORTED_PARAMS,
    IsolationForestModel,
    anomaly_scores,
    build_model,
    fit_model,
    validate_config,
    validate_features,
)


@pytest.fixture
def synthetic_matrix():
    """Small deterministic fixture: one tight cluster plus one extreme point."""
    rng = np.random.default_rng(0)
    normal = rng.normal(loc=0.0, scale=0.1, size=(200, 3))
    outlier = np.array([[10.0, -10.0, 10.0]])
    return np.vstack([normal, outlier]), len(normal)


# --- construction and defaults -------------------------------------------------


def test_build_model_returns_isolation_forest():
    model = build_model()
    assert isinstance(model, IsolationForest)


def test_build_model_uses_documented_defaults():
    model = build_model()
    for name, expected in config.ISOLATION_FOREST_DEFAULTS.items():
        assert getattr(model, name) == expected


def test_build_model_sets_random_state_explicitly():
    model = build_model()
    assert model.random_state == config.RANDOM_SEED
    assert model.random_state is not None


def test_build_model_merges_partial_config_over_defaults():
    model = build_model({"n_estimators": 25})
    assert model.n_estimators == 25
    # Untouched parameters keep the documented defaults.
    assert model.random_state == config.RANDOM_SEED
    assert model.contamination == config.ISOLATION_FOREST_DEFAULTS["contamination"]


def test_build_model_keyword_overrides_win_over_config():
    model = build_model({"n_estimators": 25}, n_estimators=10)
    assert model.n_estimators == 10


def test_build_model_supports_the_documented_parameters():
    model = build_model(
        {
            "n_estimators": 50,
            "max_samples": 128,
            "contamination": 0.05,
            "max_features": 0.5,
            "random_state": 7,
            "n_jobs": 1,
        }
    )
    assert model.n_estimators == 50
    assert model.max_samples == 128
    assert model.contamination == 0.05
    assert model.max_features == 0.5
    assert model.random_state == 7
    assert model.n_jobs == 1


def test_build_model_does_not_mutate_the_shared_defaults():
    before = dict(config.ISOLATION_FOREST_DEFAULTS)
    build_model({"n_estimators": 3, "contamination": 0.2})
    assert config.ISOLATION_FOREST_DEFAULTS == before


def test_build_model_does_not_mutate_the_caller_config():
    supplied = {"n_estimators": 3}
    build_model(supplied)
    assert supplied == {"n_estimators": 3}


def test_supported_params_cover_the_documented_set():
    for name in (
        "n_estimators",
        "max_samples",
        "contamination",
        "max_features",
        "random_state",
        "n_jobs",
    ):
        assert name in SUPPORTED_PARAMS


# --- invalid configuration -----------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {"n_estimators": 0},
        {"n_estimators": -5},
        {"n_estimators": 1.5},
        {"n_estimators": "100"},
        {"max_samples": 0},
        {"max_samples": 0.0},
        {"max_samples": 1.5},
        {"max_samples": "many"},
        {"contamination": 0.0},
        {"contamination": 0.6},
        {"contamination": -0.1},
        {"contamination": "0.1"},
        {"max_features": 0},
        {"max_features": 1.5},
        {"max_features": "all"},
        {"max_features": None},
        {"bootstrap": "yes"},
        {"random_state": None},
        {"random_state": "42"},
        {"n_jobs": 0},
        {"n_jobs": "1"},
    ],
)
def test_build_model_rejects_invalid_parameters(params):
    with pytest.raises(ValueError):
        build_model(params)


def test_build_model_rejects_unknown_parameter():
    with pytest.raises(TypeError):
        build_model({"verbose": 1})


def test_build_model_rejects_non_mapping_config():
    with pytest.raises(TypeError):
        build_model(["n_estimators", 10])


def test_invalid_value_is_not_silently_corrected():
    with pytest.raises(ValueError):
        build_model({"contamination": 0.9})


def test_validate_config_accepts_a_partial_mapping():
    validate_config({"n_estimators": 10})


def test_validate_config_rejects_non_mapping():
    with pytest.raises(TypeError):
        validate_config([("n_estimators", 10)])


# --- feature matrix contract ---------------------------------------------------


def test_validate_features_accepts_numeric_array():
    validate_features(np.zeros((3, 2)))


def test_validate_features_accepts_numeric_dataframe():
    validate_features(pd.DataFrame({"a": [1.0, 2.0], "b": [3.0, 4.0]}))


def test_validate_features_rejects_non_numeric_column():
    frame = pd.DataFrame({"a": [1.0, 2.0], "Attack": ["DoS", "Recon"]})
    with pytest.raises(TypeError, match="Attack"):
        validate_features(frame)


def test_validate_features_rejects_non_numeric_array():
    with pytest.raises(TypeError):
        validate_features(np.array([["a", "b"], ["c", "d"]]))


def test_validate_features_rejects_missing_values():
    with pytest.raises(ValueError, match="NaN"):
        validate_features(np.array([[1.0, 2.0], [3.0, np.nan]]))


def test_validate_features_rejects_infinite_values():
    with pytest.raises(ValueError, match="infinite"):
        validate_features(np.array([[1.0, 2.0], [3.0, np.inf]]))


def test_validate_features_rejects_none():
    with pytest.raises(TypeError):
        validate_features(None)


# --- regression: complex dtype rejection ---------------------------------------


def test_validate_features_rejects_complex_numpy_array():
    """Complex NumPy arrays must be rejected, not silently stripped of imaginary parts."""
    X = np.array([[1.0 + 2j, 3.0 + 4j], [5.0 + 6j, 7.0 + 8j]])
    with pytest.raises(TypeError, match="complex"):
        validate_features(X)


def test_validate_features_rejects_complex_dataframe_column():
    """DataFrames with complex-dtype columns must be rejected."""
    frame = pd.DataFrame({"a": np.array([1.0 + 2j, 3.0 + 4j])})
    with pytest.raises(TypeError, match="complex"):
        validate_features(frame)


# --- regression: shape validation ---------------------------------------------


def test_validate_features_rejects_1d_array():
    """1-D arrays are not a valid feature matrix."""
    with pytest.raises(ValueError, match="2-D"):
        validate_features(np.array([1.0, 2.0, 3.0]))


def test_validate_features_rejects_empty_sample_matrix():
    """A matrix with zero rows must be rejected."""
    with pytest.raises(ValueError, match="at least one sample"):
        validate_features(np.empty((0, 5)))


def test_validate_features_rejects_zero_column_array():
    """A matrix with zero columns must be rejected."""
    with pytest.raises(ValueError, match="at least one feature"):
        validate_features(np.empty((5, 0)))


def test_validate_features_rejects_zero_column_dataframe():
    """A DataFrame with no columns must be rejected."""
    with pytest.raises(ValueError, match="at least one feature"):
        validate_features(pd.DataFrame(index=range(5)))


def test_validate_features_rejects_empty_row_dataframe():
    """A DataFrame with zero rows must be rejected."""
    frame = pd.DataFrame({"a": pd.Series([], dtype="float64")})
    with pytest.raises(ValueError, match="at least one sample"):
        validate_features(frame)


# --- regression: valid inputs still pass --------------------------------------


def test_validate_features_accepts_int_array():
    """Integer arrays (unsigned, signed) are valid real numerics."""
    validate_features(np.array([[1, 2, 3], [4, 5, 6]], dtype=np.int32))


def test_validate_features_accepts_float32_array():
    """float32 arrays are valid."""
    validate_features(np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32))


def test_validate_features_accepts_mixed_numeric_dataframe():
    """DataFrames mixing int and float columns are valid."""
    frame = pd.DataFrame({"a": [1, 2, 3], "b": [0.1, 0.2, 0.3]})
    validate_features(frame)


# --- fit and score contract on a synthetic fixture ------------------------------


def test_fit_model_fits_without_any_target(synthetic_matrix):
    X, _ = synthetic_matrix
    model = build_model({"n_estimators": 50, "n_jobs": 1, "contamination": 0.05})
    fitted = fit_model(model, X)
    assert fitted is model
    assert fitted.n_features_in_ == X.shape[1]


def test_fit_model_accepts_no_label_argument(synthetic_matrix):
    X, _ = synthetic_matrix
    model = build_model({"n_estimators": 50, "n_jobs": 1})
    with pytest.raises(TypeError):
        fit_model(model, X, np.zeros(len(X)))


def test_fit_model_rejects_a_non_numeric_matrix():
    model = build_model({"n_estimators": 10, "n_jobs": 1})
    with pytest.raises(TypeError):
        fit_model(model, pd.DataFrame({"Attack": ["DoS", "Recon"]}))


def test_predict_marks_the_extreme_point_as_anomalous(synthetic_matrix):
    X, n_normal = synthetic_matrix
    model = build_model({"n_estimators": 50, "n_jobs": 1, "contamination": 0.05})
    fit_model(model, X)
    labels = model.predict(X)
    assert set(np.unique(labels)) <= {-1, 1}
    assert labels[-1] == -1
    # The tight cluster is not wiped out by the anomaly threshold.
    assert float(np.mean(labels[:n_normal] == 1)) >= 0.9


def test_anomaly_score_direction_is_higher_for_more_anomalous(synthetic_matrix):
    X, n_normal = synthetic_matrix
    model = build_model({"n_estimators": 50, "n_jobs": 1, "contamination": 0.05})
    fit_model(model, X)
    scores = anomaly_scores(model, X)
    assert scores.shape == (X.shape[0],)
    assert scores[-1] > scores[:n_normal].max()


def test_anomaly_scores_is_reproducible_for_a_fixed_seed(synthetic_matrix):
    X, _ = synthetic_matrix
    first = build_model({"n_estimators": 50, "n_jobs": 1, "random_state": 42})
    second = build_model({"n_estimators": 50, "n_jobs": 1, "random_state": 42})
    fit_model(first, X)
    fit_model(second, X)
    assert np.array_equal(anomaly_scores(first, X), anomaly_scores(second, X))


# --- IsolationForestModel component tests (Issue #54 / Track C) ----------------


class TestIsolationForestModel:
    def test_model_init_defaults(self):
        model = IsolationForestModel()
        assert model.model_type == "IsolationForest"
        assert model.score_direction == "higher_is_more_anomalous"
        assert model.label_mapping == {"0": "Benign", "1": "Attack"}
        assert model.threshold is None
        assert not model._is_fitted

    def test_model_init_with_config_and_threshold(self):
        model = IsolationForestModel(config={"n_estimators": 25}, threshold=0.15)
        assert model.config["n_estimators"] == 25
        assert model.threshold == 0.15

    def test_model_fit_and_predict_binary_labels(self, synthetic_matrix):
        X, n_normal = synthetic_matrix
        model = IsolationForestModel(threshold=0.0)
        model.fit(X)
        assert model._is_fitted

        y_pred = model.predict(X)
        assert set(np.unique(y_pred)).issubset({0, 1})
        assert y_pred.shape == (X.shape[0],)
        assert y_pred[-1] == 1  # Outlier labeled as Attack (1)
        # Tight normal cluster mostly labeled as Benign (0)
        assert float(np.mean(y_pred[:n_normal] == 0)) >= 0.85

    def test_model_predict_requires_fitted(self, synthetic_matrix):
        X, _ = synthetic_matrix
        model = IsolationForestModel(threshold=0.0)
        with pytest.raises(NotFittedError):
            model.predict(X)

    def test_model_predict_requires_threshold(self, synthetic_matrix):
        X, _ = synthetic_matrix
        model = IsolationForestModel()
        model.fit(X)
        with pytest.raises(ValueError, match="Threshold is not set"):
            model.predict(X)

    def test_model_decision_function_matches_anomaly_scores(self, synthetic_matrix):
        X, _ = synthetic_matrix
        model = IsolationForestModel(threshold=0.0)
        model.fit(X)
        scores = model.anomaly_scores(X)
        dec = model.decision_function(X)
        assert np.array_equal(scores, dec)

    def test_model_fit_records_feature_names(self):
        df = pd.DataFrame({"f1": [1.0, 2.0, 3.0], "f2": [4.0, 5.0, 6.0]})
        model = IsolationForestModel()
        model.fit(df)
        assert model.feature_names == ("f1", "f2")

    def test_save_and_load_roundtrip(self, synthetic_matrix, tmp_path):
        X, _ = synthetic_matrix
        model = IsolationForestModel(threshold=0.12)
        model.fit(X)

        model_file = tmp_path / "model.joblib"
        man_file = tmp_path / "manifest.json"
        valid_prep_sha = "e" * 64
        valid_sm_sha = "d" * 64

        sha = model.save(
            model_path=model_file,
            manifest_path=man_file,
            preprocessor_artifact_sha256=valid_prep_sha,
            split_manifest_sha256=valid_sm_sha,
        )
        assert model_file.exists()
        assert man_file.exists()
        assert len(sha) == 64

        loaded = IsolationForestModel.load(model_file)
        assert loaded._is_fitted
        assert loaded.threshold == 0.12
        assert loaded.score_direction == "higher_is_more_anomalous"
        assert np.array_equal(model.predict(X), loaded.predict(X))

    def test_save_and_load_verified_roundtrip(self, synthetic_matrix, tmp_path):
        X, _ = synthetic_matrix
        model = IsolationForestModel(threshold=0.12)
        model.fit(X)

        model_file = tmp_path / "model.joblib"
        man_file = tmp_path / "manifest.json"
        valid_prep_sha = "e" * 64

        model.save(
            model_path=model_file,
            manifest_path=man_file,
            preprocessor_artifact_sha256=valid_prep_sha,
        )

        verified = IsolationForestModel.load_verified(
            model_path=model_file,
            manifest_path=man_file,
            expected_preprocessor_artifact_sha256=valid_prep_sha,
            expected_threshold=0.12,
        )
        assert verified._is_fitted
        assert verified.threshold == 0.12
        assert np.array_equal(model.predict(X), verified.predict(X))

    def test_load_verified_fails_on_hash_tamper(self, synthetic_matrix, tmp_path):
        X, _ = synthetic_matrix
        model = IsolationForestModel(threshold=0.12)
        model.fit(X)

        model_file = tmp_path / "model.joblib"
        man_file = tmp_path / "manifest.json"
        valid_prep_sha = "e" * 64

        model.save(
            model_path=model_file,
            manifest_path=man_file,
            preprocessor_artifact_sha256=valid_prep_sha,
        )

        with open(model_file, "ab") as f:
            f.write(b"tamper")

        with pytest.raises(ValueError, match="Integrity check failed"):
            IsolationForestModel.load_verified(
                model_path=model_file,
                manifest_path=man_file,
            )

    def test_load_verified_fails_on_threshold_mismatch(self, synthetic_matrix, tmp_path):
        X, _ = synthetic_matrix
        model = IsolationForestModel(threshold=0.12)
        model.fit(X)

        model_file = tmp_path / "model.joblib"
        man_file = tmp_path / "manifest.json"
        valid_prep_sha = "e" * 64

        model.save(
            model_path=model_file,
            manifest_path=man_file,
            preprocessor_artifact_sha256=valid_prep_sha,
        )

        with pytest.raises(ValueError, match="Threshold mismatch"):
            IsolationForestModel.load_verified(
                model_path=model_file,
                manifest_path=man_file,
                expected_threshold=0.99,
            )

    def test_load_verified_fails_on_preprocessor_mismatch(self, synthetic_matrix, tmp_path):
        X, _ = synthetic_matrix
        model = IsolationForestModel(threshold=0.12)
        model.fit(X)

        model_file = tmp_path / "model.joblib"
        man_file = tmp_path / "manifest.json"
        valid_prep_sha = "e" * 64

        model.save(
            model_path=model_file,
            manifest_path=man_file,
            preprocessor_artifact_sha256=valid_prep_sha,
        )

        with pytest.raises(ValueError, match="Preprocessor artifact SHA-256 mismatch"):
            IsolationForestModel.load_verified(
                model_path=model_file,
                manifest_path=man_file,
                expected_preprocessor_artifact_sha256="f" * 64,
            )

    def test_load_verified_fails_on_missing_files(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            IsolationForestModel.load_verified(
                model_path=tmp_path / "nonexistent.joblib",
                manifest_path=tmp_path / "nonexistent.json",
            )


def test_anomaly_scores_helper_with_wrapper(synthetic_matrix):
    X, _ = synthetic_matrix
    wrapper = IsolationForestModel(threshold=0.0)
    wrapper.fit(X)
    scores = anomaly_scores(wrapper, X)
    assert scores.shape == (X.shape[0],)
    assert np.array_equal(scores, wrapper.anomaly_scores(X))


def test_anomaly_scores_helper_with_payload_dict(synthetic_matrix):
    X, _ = synthetic_matrix
    model = build_model({"n_estimators": 20, "n_jobs": 1})
    fit_model(model, X)
    payload = {"estimator": model}
    scores = anomaly_scores(payload, X)
    assert scores.shape == (X.shape[0],)
    assert np.array_equal(scores, anomaly_scores(model, X))
