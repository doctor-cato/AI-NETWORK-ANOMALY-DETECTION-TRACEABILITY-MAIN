"""Unit tests for NF-UNSW-NB15-v3 train-only preprocessing pipeline (Issue #8).

Tests all 13 mandatory criteria:
1. Exact 47 baseline ML features in exact contract order.
2. Targets and trace metadata excluded from X.
3. Fit executes exclusively on Train.
4. Validation and Test data modifications do not alter fitted state.
5. Extreme outliers in Validation/Test do not alter Train fit statistics.
6. NaN, infinity, and invalid numeric tokens handled according to policy.
7. Missing, extra, or reordered columns fail closed.
8. Save and load artifact produces bit-identical transformation.
9. Artifact with mismatched checksum or altered metadata is rejected.
10. Input data is never modified in-place.
11. Features with zero variance (constants) or all-missing values are handled robustly.
12. Outputs have exact shape, column names, dtypes, and finite values.
13. Preprocessing strictly never uses targets as features.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
from pathlib import Path
from typing import Dict, Tuple
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import (
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.preprocessing.pipeline import (
    EXPECTED_DATASET_SHA256,
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_POLICY_VERSION,
    REQUIRED_COMPANION_MANIFEST_FIELDS,
    SPLIT_PROTOCOL_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
    _sha256_file,
    audit_column_tokens,
    verify_preprocessing_artifact,
    verify_zero_duration_retention,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PREPROCESS_SCRIPT = REPOSITORY_ROOT / "scripts" / "preprocess_nf_unsw_nb15_v3.py"
SMOKE_REPORT_SCRIPT = REPOSITORY_ROOT / "scripts" / "generate_real_data_smoke_report.py"


def _load_preprocess_cli():
    spec = importlib.util.spec_from_file_location("preprocess_cli", PREPROCESS_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_smoke_report_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_real_data_smoke_report", SMOKE_REPORT_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def synthetic_47_feature_data() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Generate small synthetic Train, Validation, and Test feature matrices."""
    rng = np.random.default_rng(42)
    n_train = 50
    n_val = 20
    n_test = 20

    def _make_df(n_rows: int) -> pd.DataFrame:
        data: Dict[str, np.ndarray] = {}
        for col in ML_FEATURE_COLUMNS:
            if col in CATEGORICAL_CODED_COLUMNS:
                data[col] = rng.integers(0, 10, size=n_rows)
            else:
                data[col] = rng.normal(loc=100.0, scale=15.0, size=n_rows)
        return pd.DataFrame(data, columns=list(ML_FEATURE_COLUMNS))

    df_train = _make_df(n_train)
    df_val = _make_df(n_val)
    df_test = _make_df(n_test)
    return df_train, df_val, df_test


def test_criterion_1_exact_47_features_in_exact_order(synthetic_47_feature_data):
    """Criterion 1: Exactly 47 baseline ML features in exact order."""
    df_train, df_val, df_test = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)

    out_train = prep.transform(df_train)
    out_val = prep.transform(df_val)
    out_test = prep.transform(df_test)

    for out in [out_train, out_val, out_test]:
        assert list(out.columns) == list(ML_FEATURE_COLUMNS)
        assert len(out.columns) == 47


def test_criterion_2_targets_and_trace_metadata_rejected(synthetic_47_feature_data):
    """Criterion 2: Targets and trace metadata must never enter X."""
    df_train, _, _ = synthetic_47_feature_data

    # Test rejecting targets in X
    for target_col in TARGET_COLUMNS:
        df_bad = df_train.copy()
        df_bad[target_col] = 1
        prep = TrainOnlyPreprocessor()
        with pytest.raises(ValueError, match="forbidden columns"):
            prep.fit(df_bad)

    # Test rejecting trace metadata in X
    for meta_col in TRACE_METADATA_COLUMNS:
        df_bad = df_train.copy()
        df_bad[meta_col] = 1000
        prep = TrainOnlyPreprocessor()
        with pytest.raises(ValueError, match="forbidden columns"):
            prep.fit(df_bad)


def test_criterion_3_fit_strictly_on_train(synthetic_47_feature_data):
    """Criterion 3: Imputer statistics and vocabularies are learned EXCLUSIVELY from Train."""
    df_train, df_val, _ = synthetic_47_feature_data

    # Set specific known values in Train for a quantitative feature
    col_q = "IN_BYTES"
    known_train_vals = np.array([10.0, 20.0, 30.0, 40.0, 50.0] * 10)
    df_train[col_q] = known_train_vals
    expected_median = float(np.median(known_train_vals))

    # Set completely different values in Val
    df_val[col_q] = np.array([999.0] * len(df_val))

    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)

    assert prep.imputed_values_[col_q] == expected_median
    assert prep.train_row_count_ == len(df_train)

    # Transform val where one value is NaN
    df_val_with_nan = df_val.copy()
    df_val_with_nan.loc[0, col_q] = np.nan
    out_val = prep.transform(df_val_with_nan)

    # The imputed value in val must be the TRAIN median, not anything from val
    assert out_val.loc[0, col_q] == expected_median


def test_criterion_4_changing_val_test_does_not_affect_fitted_state(synthetic_47_feature_data):
    """Criterion 4: Modifying Validation/Test data does not alter fitted state."""
    df_train, df_val, df_test = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)

    imputed_before = copy.deepcopy(prep.imputed_values_)
    vocab_before = copy.deepcopy(prep.category_vocabularies_)

    # Transform normal val
    prep.transform(df_val)
    assert prep.imputed_values_ == imputed_before
    assert prep.category_vocabularies_ == vocab_before

    # Transform modified val with new values
    df_val_altered = df_val.copy() * 10.0
    prep.transform(df_val_altered)
    assert prep.imputed_values_ == imputed_before
    assert prep.category_vocabularies_ == vocab_before


def test_criterion_5_extreme_outliers_in_val_test_do_not_alter_train_statistics(
    synthetic_47_feature_data,
):
    """Criterion 5: Extreme outliers in Validation/Test do not leak into Train statistics."""
    df_train, df_val, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="standard"))
    prep.fit(df_train)

    imputed_frozen = copy.deepcopy(prep.imputed_values_)
    scaler_frozen = copy.deepcopy(prep.scaler_params_)

    # Introduce extreme values and infinities in validation
    df_val_extreme = df_val.copy()
    df_val_extreme.iloc[0, 2] = 1e18
    df_val_extreme.iloc[1, 2] = -1e18
    df_val_extreme.iloc[2, 2] = np.inf
    df_val_extreme.iloc[3, 2] = -np.inf
    df_val_extreme.iloc[4, 2] = np.nan

    out_val = prep.transform(df_val_extreme)

    # Ensure train parameters were not altered
    assert prep.imputed_values_ == imputed_frozen
    assert prep.scaler_params_ == scaler_frozen
    # Ensure transformed values are finite
    assert np.all(np.isfinite(out_val.to_numpy()))


def test_criterion_6_nan_infinity_and_invalid_numeric_handling(synthetic_47_feature_data):
    """Criterion 6: NaN and infinities imputed with train median/mode; invalid numerics rejected."""
    df_train, df_val, _ = synthetic_47_feature_data
    col = "SRC_TO_DST_SECOND_BYTES"

    # Insert NaN, +inf, -inf into Train
    df_train.loc[0, col] = np.nan
    df_train.loc[1, col] = np.inf
    df_train.loc[2, col] = -np.inf

    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)

    # Assert audit counts on train recorded non-finite values correctly
    audit = prep.audit_counts_train_[col]
    assert audit["nan"] == 1
    assert audit["positive_infinity"] == 1
    assert audit["negative_infinity"] == 1
    assert audit["total_non_finite"] == 3

    # Transform and verify finite output
    out_train = prep.transform(df_train)
    assert np.all(np.isfinite(out_train[col].to_numpy()))

    # Ensure +inf in val is transformed to train median (not zero)
    df_val_inf = df_val.copy()
    df_val_inf.loc[0, col] = np.inf
    out_val = prep.transform(df_val_inf)
    assert out_val.loc[0, col] == prep.imputed_values_[col]
    assert prep.imputed_values_[col] != 0.0

    # Ensure invalid numeric strings raise ValueError fail-closed
    df_bad = df_train.copy()
    df_bad[col] = df_bad[col].astype(object)
    df_bad.loc[5, col] = "unparseable_string_token"
    prep_fail = TrainOnlyPreprocessor()
    with pytest.raises(ValueError, match="invalid numeric token"):
        prep_fail.fit(df_bad)


def test_criterion_7_schema_mismatch_fails_closed(synthetic_47_feature_data):
    """Criterion 7: Missing, extra, or reordered columns fail closed."""
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor()

    # Missing column
    df_missing = df_train.drop(columns=[ML_FEATURE_COLUMNS[0]])
    with pytest.raises(ValueError, match="does not match the ordered v3 ML contract"):
        prep.fit(df_missing)

    # Extra unknown column
    df_extra = df_train.copy()
    df_extra["UNKNOWN_COL"] = 123
    with pytest.raises(ValueError, match="unknown columns"):
        prep.fit(df_extra)

    # Reordered columns
    cols_reordered = list(ML_FEATURE_COLUMNS)
    cols_reordered[0], cols_reordered[1] = cols_reordered[1], cols_reordered[0]
    df_reordered = df_train[cols_reordered]
    with pytest.raises(ValueError, match="does not match the ordered v3 ML contract"):
        prep.fit(df_reordered)


def test_criterion_8_save_and_load_artifact_equivalence(synthetic_47_feature_data):
    """Criterion 8: Saved and loaded artifact gives identical transformation."""
    df_train, _, df_test = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="robust"))
    prep.fit(df_train)

    out_original = prep.transform(df_test)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"

        prep.save(art_path, manifest_path=man_path)

        # Load back
        prep_loaded = TrainOnlyPreprocessor.load(art_path)
        out_loaded = prep_loaded.transform(df_test)

        pd.testing.assert_frame_equal(out_original, out_loaded)
        assert prep_loaded.imputed_values_ == prep.imputed_values_
        assert prep_loaded.scaler_params_ == prep.scaler_params_


def test_criterion_9_artifact_with_wrong_checksum_rejected(synthetic_47_feature_data):
    """Criterion 9: Artifact with mismatched dataset/manifest hash is rejected."""
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256="4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        split_manifest_sha256="correct_manifest_hash",
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        prep.save(art_path)

        # Mismatched dataset SHA
        with pytest.raises(ValueError, match="Dataset SHA-256 mismatch"):
            TrainOnlyPreprocessor.load(art_path, expected_dataset_sha256="wrong_dataset_hash")

        # Mismatched manifest SHA
        with pytest.raises(ValueError, match="Split manifest SHA-256 mismatch"):
            TrainOnlyPreprocessor.load(art_path, expected_manifest_sha256="wrong_manifest_hash")


def test_criterion_10_input_dataframe_not_modified_in_place(synthetic_47_feature_data):
    """Criterion 10: Processing does not modify input DataFrame in-place."""
    df_train, df_val, _ = synthetic_47_feature_data
    df_val.loc[0, "IN_BYTES"] = np.nan

    df_val_before = df_val.copy(deep=True)

    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)
    out_val = prep.transform(df_val)

    # Input df_val must remain identical
    pd.testing.assert_frame_equal(df_val, df_val_before)
    # Output must have imputed finite value
    assert np.isfinite(out_val.loc[0, "IN_BYTES"])


def test_criterion_11_constant_and_all_missing_features(synthetic_47_feature_data):
    """Criterion 11: Constant features and all-missing features are handled robustly."""
    df_train, df_val, _ = synthetic_47_feature_data

    # Make one quantitative column constant (variance = 0)
    col_const = "DURATION_IN"
    df_train[col_const] = 42.0
    df_val[col_const] = 42.0

    # Make one column all missing in Train
    col_missing = "SRC_TO_DST_IAT_STDDEV"
    df_train[col_missing] = np.nan
    df_val[col_missing] = np.nan

    # Fit with scaler
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="standard"))
    prep.fit(df_train)

    assert col_const in prep.constant_features_
    assert col_missing in prep.all_missing_columns_

    # Verify scaler does not divide by zero or produce NaNs for constant feature
    out_train = prep.transform(df_train)
    out_val = prep.transform(df_val)

    assert np.all(np.isfinite(out_train[col_const].to_numpy()))
    assert np.all(np.isfinite(out_val[col_const].to_numpy()))
    assert np.all(np.isfinite(out_train[col_missing].to_numpy()))
    assert np.all(np.isfinite(out_val[col_missing].to_numpy()))


def test_criterion_12_output_finite_shape_and_dtypes(synthetic_47_feature_data):
    """Criterion 12: Outputs strictly have shape (N, 47), exact feature names,
    and all finite values.
    """
    df_train, df_val, df_test = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="minmax"))
    prep.fit(df_train)

    for df_in, name in [(df_train, "train"), (df_val, "val"), (df_test, "test")]:
        df_out = prep.transform(df_in, partition_name=name)
        assert df_out.shape == (len(df_in), 47)
        assert list(df_out.columns) == list(ML_FEATURE_COLUMNS)
        assert np.all(np.isfinite(df_out.to_numpy()))


def test_criterion_13_no_preprocessing_step_uses_target_as_feature(synthetic_47_feature_data):
    """Criterion 13: Passing target to fit(X, y) strictly does not influence
    feature transformation.
    """
    df_train, df_val, _ = synthetic_47_feature_data

    # Fit without y
    prep1 = TrainOnlyPreprocessor()
    prep1.fit(df_train)
    out1 = prep1.transform(df_val)

    # Fit with synthetic y
    y_synth = pd.Series(np.ones(len(df_train), dtype=int))
    prep2 = TrainOnlyPreprocessor()
    prep2.fit(df_train, y=y_synth)
    out2 = prep2.transform(df_val)

    pd.testing.assert_frame_equal(out1, out2)
    assert prep1.imputed_values_ == prep2.imputed_values_


def test_categorical_coded_columns_never_scaled_as_continuous(synthetic_47_feature_data):
    """Test that the 10 categorical-coded columns are NEVER scaled by continuous scalers."""
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="standard"))
    prep.fit(df_train)

    # Check scaler_params_ only contains quantitative columns
    for cat_col in CATEGORICAL_CODED_COLUMNS:
        assert cat_col not in prep.scaler_params_

    for quant_col in QUANTITATIVE_ML_COLUMNS:
        assert quant_col in prep.scaler_params_

    # Transform and check categorical values remain discrete codes
    out = prep.transform(df_train)
    for cat_col in CATEGORICAL_CODED_COLUMNS:
        # Values should be integers / whole numbers, not continuous standardized floats
        arr = out[cat_col].to_numpy()
        np.testing.assert_allclose(arr, np.round(arr))


def test_verify_preprocessing_artifact_helper(synthetic_47_feature_data):
    """Test verify_preprocessing_artifact on a valid artifact."""
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        res = verify_preprocessing_artifact(
            artifact_path=art_path,
            manifest_path=man_path,
            expected_dataset_sha256=EXPECTED_DATASET_SHA256,
        )
        assert res["status"] == "PASS"
        assert len(res["errors"]) == 0


def test_cli_preprocess_absent_dataset_skips(monkeypatch):
    """Test that preprocess CLI cleanly outputs SKIPPED and exits 0 when dataset is absent."""
    prep_cli = _load_preprocess_cli()

    fake_args = [
        "preprocess_nf_unsw_nb15_v3.py",
        "--dataset",
        "nonexistent_dataset.csv",
    ]
    monkeypatch.setattr("sys.argv", fake_args)
    exit_code = prep_cli.main()
    assert exit_code == 0


def test_cli_preprocess_verify_only(synthetic_47_feature_data, monkeypatch):
    """Test that preprocess CLI with --verify-only verifies an existing valid artifact."""
    prep_cli = _load_preprocess_cli()

    df_train, _, _ = synthetic_47_feature_data
    with tempfile.TemporaryDirectory() as tmp_dir:
        from network_anomaly.preprocessing.pipeline import _sha256_file

        fake_ds_path = Path(tmp_dir) / "fake_dataset.csv"
        fake_ds_path.write_text("dummy", encoding="utf-8")
        fake_ds_hash = _sha256_file(fake_ds_path)

        fake_split_manifest = Path(tmp_dir) / "split_manifest.json"
        split_content = {
            "dataset_sha256": fake_ds_hash,
            "split_protocol_version": SPLIT_PROTOCOL_VERSION,
        }
        fake_split_manifest.write_text(json.dumps(split_content), encoding="utf-8")
        sm_hash = _sha256_file(fake_split_manifest)

        prep = TrainOnlyPreprocessor(
            dataset_sha256=fake_ds_hash,
            split_manifest_sha256=sm_hash,
        )
        prep.fit(df_train)

        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        fake_args = [
            "preprocess_nf_unsw_nb15_v3.py",
            "--dataset",
            str(fake_ds_path),
            "--manifest",
            str(fake_split_manifest),
            "--output-artifact",
            str(art_path),
            "--output-manifest",
            str(man_path),
            "--expected-dataset-sha256",
            fake_ds_hash,
            "--verify-only",
        ]
        monkeypatch.setattr("sys.argv", fake_args)
        exit_code = prep_cli.main()
        assert exit_code == 0


def test_cli_preprocess_verify_only_tampered_dataset_fails(synthetic_47_feature_data, monkeypatch):
    """Test CLI --verify-only fails closed (exit code 1) when raw dataset bytes are modified."""
    prep_cli = _load_preprocess_cli()

    df_train, _, _ = synthetic_47_feature_data
    with tempfile.TemporaryDirectory() as tmp_dir:
        from network_anomaly.preprocessing.pipeline import _sha256_file

        fake_ds_path = Path(tmp_dir) / "fake_dataset.csv"
        fake_ds_path.write_text("original content", encoding="utf-8")
        fake_ds_hash = _sha256_file(fake_ds_path)

        fake_split_manifest = Path(tmp_dir) / "split_manifest.json"
        fake_split_manifest.write_text(
            json.dumps(
                {
                    "dataset_sha256": fake_ds_hash,
                    "split_protocol_version": SPLIT_PROTOCOL_VERSION,
                }
            ),
            encoding="utf-8",
        )
        sm_hash = _sha256_file(fake_split_manifest)

        prep = TrainOnlyPreprocessor(
            dataset_sha256=fake_ds_hash,
            split_manifest_sha256=sm_hash,
        )
        prep.fit(df_train)

        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        # Tamper with the raw dataset AFTER artifact creation
        fake_ds_path.write_text("tampered content modifying raw bytes", encoding="utf-8")

        fake_args = [
            "preprocess_nf_unsw_nb15_v3.py",
            "--dataset",
            str(fake_ds_path),
            "--manifest",
            str(fake_split_manifest),
            "--output-artifact",
            str(art_path),
            "--output-manifest",
            str(man_path),
            "--expected-dataset-sha256",
            fake_ds_hash,
            "--verify-only",
        ]
        monkeypatch.setattr("sys.argv", fake_args)
        exit_code = prep_cli.main()
        assert exit_code == 1


def test_cli_preprocess_verify_only_missing_manifest_fails(synthetic_47_feature_data, monkeypatch):
    """Test CLI --verify-only fails closed (exit code 1) when manifest is missing."""
    prep_cli = _load_preprocess_cli()

    df_train, _, _ = synthetic_47_feature_data
    with tempfile.TemporaryDirectory() as tmp_dir:
        from network_anomaly.preprocessing.pipeline import _sha256_file

        fake_ds_path = Path(tmp_dir) / "fake_dataset.csv"
        fake_ds_path.write_text("dummy", encoding="utf-8")
        fake_ds_hash = _sha256_file(fake_ds_path)

        fake_split_manifest = Path(tmp_dir) / "split_manifest.json"
        fake_split_manifest.write_text(
            json.dumps(
                {
                    "dataset_sha256": fake_ds_hash,
                    "split_protocol_version": SPLIT_PROTOCOL_VERSION,
                }
            ),
            encoding="utf-8",
        )
        sm_hash = _sha256_file(fake_split_manifest)

        prep = TrainOnlyPreprocessor(
            dataset_sha256=fake_ds_hash,
            split_manifest_sha256=sm_hash,
        )
        prep.fit(df_train)

        art_path = Path(tmp_dir) / "preprocessor.joblib"
        prep.save(art_path)  # saves artifact only, no companion manifest
        nonexistent_man = Path(tmp_dir) / "missing_manifest.json"

        fake_args = [
            "preprocess_nf_unsw_nb15_v3.py",
            "--dataset",
            str(fake_ds_path),
            "--manifest",
            str(fake_split_manifest),
            "--output-artifact",
            str(art_path),
            "--output-manifest",
            str(nonexistent_man),
            "--expected-dataset-sha256",
            fake_ds_hash,
            "--verify-only",
        ]
        monkeypatch.setattr("sys.argv", fake_args)
        exit_code = prep_cli.main()
        assert exit_code == 1


def test_cli_preprocess_verify_only_missing_dataset_fails(synthetic_47_feature_data, monkeypatch):
    """Test CLI --verify-only fails closed (exit code 1) when raw dataset is missing."""
    prep_cli = _load_preprocess_cli()

    df_train, _, _ = synthetic_47_feature_data
    with tempfile.TemporaryDirectory() as tmp_dir:
        from network_anomaly.preprocessing.pipeline import _sha256_file

        fake_split_manifest = Path(tmp_dir) / "split_manifest.json"
        fake_split_manifest.write_text(
            json.dumps(
                {
                    "dataset_sha256": EXPECTED_DATASET_SHA256,
                    "split_protocol_version": SPLIT_PROTOCOL_VERSION,
                }
            ),
            encoding="utf-8",
        )
        sm_hash = _sha256_file(fake_split_manifest)

        prep = TrainOnlyPreprocessor(
            dataset_sha256=EXPECTED_DATASET_SHA256,
            split_manifest_sha256=sm_hash,
        )
        prep.fit(df_train)

        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        nonexistent_dataset = Path(tmp_dir) / "absent_dataset.csv"

        fake_args = [
            "preprocess_nf_unsw_nb15_v3.py",
            "--dataset",
            str(nonexistent_dataset),
            "--manifest",
            str(fake_split_manifest),
            "--output-artifact",
            str(art_path),
            "--output-manifest",
            str(man_path),
            "--verify-only",
        ]
        monkeypatch.setattr("sys.argv", fake_args)
        exit_code = prep_cli.main()
        assert exit_code == 1


def test_cli_preprocess_verify_only_missing_split_manifest_fails(
    synthetic_47_feature_data, monkeypatch
):
    """Test CLI --verify-only fails closed (exit code 1) when split manifest is missing."""
    prep_cli = _load_preprocess_cli()

    df_train, _, _ = synthetic_47_feature_data
    with tempfile.TemporaryDirectory() as tmp_dir:
        from network_anomaly.preprocessing.pipeline import _sha256_file

        fake_ds_path = Path(tmp_dir) / "fake_dataset.csv"
        fake_ds_path.write_text("dummy", encoding="utf-8")
        fake_ds_hash = _sha256_file(fake_ds_path)
        nonexistent_sm = Path(tmp_dir) / "absent_split_manifest.json"

        prep = TrainOnlyPreprocessor(dataset_sha256=fake_ds_hash)
        prep.fit(df_train)
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        fake_args = [
            "preprocess_nf_unsw_nb15_v3.py",
            "--dataset",
            str(fake_ds_path),
            "--manifest",
            str(nonexistent_sm),
            "--output-artifact",
            str(art_path),
            "--output-manifest",
            str(man_path),
            "--expected-dataset-sha256",
            fake_ds_hash,
            "--verify-only",
        ]
        monkeypatch.setattr("sys.argv", fake_args)
        exit_code = prep_cli.main()
        assert exit_code == 1


def test_cli_preprocess_verify_only_missing_artifact_fails(monkeypatch):
    """Test CLI --verify-only fails closed (exit code 1) when artifact is missing."""
    prep_cli = _load_preprocess_cli()

    with tempfile.TemporaryDirectory() as tmp_dir:
        fake_ds_path = Path(tmp_dir) / "fake_dataset.csv"
        fake_ds_path.write_text("dummy", encoding="utf-8")
        fake_sm_path = Path(tmp_dir) / "split_manifest.json"
        fake_sm_path.write_text("{}", encoding="utf-8")
        man_path = Path(tmp_dir) / "manifest.json"
        man_path.write_text("{}", encoding="utf-8")
        nonexistent_art = Path(tmp_dir) / "absent_artifact.joblib"

        fake_args = [
            "preprocess_nf_unsw_nb15_v3.py",
            "--dataset",
            str(fake_ds_path),
            "--manifest",
            str(fake_sm_path),
            "--output-artifact",
            str(nonexistent_art),
            "--output-manifest",
            str(man_path),
            "--verify-only",
        ]
        monkeypatch.setattr("sys.argv", fake_args)
        exit_code = prep_cli.main()
        assert exit_code == 1


def test_verify_artifact_negative_cases(synthetic_47_feature_data):
    """Negative tests for artifact verification: missing, corrupted, altered, or mismatched."""
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="valid_split_manifest_sha256",
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        # 1. Missing companion manifest
        missing_man = Path(tmp_dir) / "nonexistent.json"
        res = verify_preprocessing_artifact(art_path, manifest_path=missing_man)
        assert res["status"] == "FAIL"
        assert any("Companion manifest file not found" in e for e in res["errors"])

        # 2. Corrupted JSON companion manifest
        bad_json_man = Path(tmp_dir) / "bad_json.json"
        bad_json_man.write_text("not-a-valid-json", encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bad_json_man)
        assert res["status"] == "FAIL"
        assert any("Error reading companion manifest JSON" in e for e in res["errors"])

        # 3. Artifact tampered with on disk (corrupted content)
        tampered_art = Path(tmp_dir) / "tampered.joblib"
        tampered_art.write_bytes(art_path.read_bytes() + b"\x00\x00")
        res = verify_preprocessing_artifact(tampered_art, manifest_path=man_path)
        assert res["status"] == "FAIL"
        assert any("Artifact SHA-256 mismatch" in e for e in res["errors"])

        # 4. Companion manifest with mismatched split_manifest_sha256
        man_content = json.loads(man_path.read_text(encoding="utf-8"))
        mismatched_sm = copy.deepcopy(man_content)
        mismatched_sm["split_manifest_sha256"] = "mismatched_hash_value"
        bad_sm_man = Path(tmp_dir) / "bad_sm.json"
        bad_sm_man.write_text(json.dumps(mismatched_sm), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bad_sm_man)
        assert res["status"] == "FAIL"
        assert any("Split manifest SHA-256 mismatch" in e for e in res["errors"])

        # 5. Companion manifest with mismatched feature contract version
        mismatched_fc = copy.deepcopy(man_content)
        mismatched_fc["feature_contract_version"] = "wrong-contract-version"
        bad_fc_man = Path(tmp_dir) / "bad_fc.json"
        bad_fc_man.write_text(json.dumps(mismatched_fc), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bad_fc_man)
        assert res["status"] == "FAIL"
        assert any("Invalid feature_contract_version" in e for e in res["errors"])

        # 6. Companion manifest with mismatched preprocessing policy version
        mismatched_pv = copy.deepcopy(man_content)
        mismatched_pv["preprocessing_policy_version"] = "v999.0"
        bad_pv_man = Path(tmp_dir) / "bad_pv.json"
        bad_pv_man.write_text(json.dumps(mismatched_pv), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bad_pv_man)
        assert res["status"] == "FAIL"
        assert any("Invalid preprocessing_policy_version" in e for e in res["errors"])

        # 7. Companion manifest with tampered feature order
        tampered_order = copy.deepcopy(man_content)
        tampered_order["baseline_ml_features_in_order"].reverse()
        bad_order_man = Path(tmp_dir) / "bad_order.json"
        bad_order_man.write_text(json.dumps(tampered_order), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bad_order_man)
        assert res["status"] == "FAIL"
        assert any("baseline_ml_features_in_order" in e for e in res["errors"])

        # 8. Mismatched dataset SHA-256
        res = verify_preprocessing_artifact(
            art_path, manifest_path=man_path, expected_dataset_sha256="wrong_ds_hash"
        )
        assert res["status"] == "FAIL"
        assert any("Dataset SHA-256" in e for e in res["errors"])

        # 9. Empty companion manifest object {}
        empty_man = Path(tmp_dir) / "empty_manifest.json"
        empty_man.write_text("{}", encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=empty_man)
        assert res["status"] == "FAIL"
        assert any(
            "Companion manifest is empty or not a valid JSON object" in e for e in res["errors"]
        )

        # 10. Companion manifest as JSON array []
        array_man = Path(tmp_dir) / "array_manifest.json"
        array_man.write_text("[]", encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=array_man)
        assert res["status"] == "FAIL"
        assert any(
            "Companion manifest is empty or not a valid JSON object" in e for e in res["errors"]
        )

        # 11. Companion manifest as JSON string "hello"
        string_man = Path(tmp_dir) / "string_manifest.json"
        string_man.write_text('"hello"', encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=string_man)
        assert res["status"] == "FAIL"
        assert any(
            "Companion manifest is empty or not a valid JSON object" in e for e in res["errors"]
        )

        # 12. Missing each required field individually
        for req_field in REQUIRED_COMPANION_MANIFEST_FIELDS:
            incomplete = copy.deepcopy(man_content)
            del incomplete[req_field]
            inc_path = Path(tmp_dir) / f"missing_{req_field}.json"
            inc_path.write_text(json.dumps(incomplete), encoding="utf-8")
            res = verify_preprocessing_artifact(art_path, manifest_path=inc_path)
            assert res["status"] == "FAIL", f"Expected FAIL when missing {req_field}"
            assert any(f"missing required field: '{req_field}'" in e for e in res["errors"])

        # 13. Field type mismatches (including bool for int)
        # 13a. artifact_version as string
        bad_type_man = copy.deepcopy(man_content)
        bad_type_man["artifact_version"] = "1"
        bt_path = Path(tmp_dir) / "bad_type_str.json"
        bt_path.write_text(json.dumps(bad_type_man), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bt_path)
        assert res["status"] == "FAIL"
        assert any("must be int, got str" in e for e in res["errors"])

        # 13b. train_row_count as bool
        bad_type_bool = copy.deepcopy(man_content)
        bad_type_bool["train_row_count"] = True
        bt_bool_path = Path(tmp_dir) / "bad_type_bool.json"
        bt_bool_path.write_text(json.dumps(bad_type_bool), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bt_bool_path)
        assert res["status"] == "FAIL"
        assert any("must be int, got bool" in e for e in res["errors"])

        # 13c. config as list instead of dict
        bad_type_dict = copy.deepcopy(man_content)
        bad_type_dict["config"] = ["not", "a", "dict"]
        bt_dict_path = Path(tmp_dir) / "bad_type_dict.json"
        bt_dict_path.write_text(json.dumps(bad_type_dict), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bt_dict_path)
        assert res["status"] == "FAIL"
        assert any("must be dict, got list" in e for e in res["errors"])

        # 14. Non-positive train_row_count
        zero_rows_man = copy.deepcopy(man_content)
        zero_rows_man["train_row_count"] = 0
        zr_path = Path(tmp_dir) / "zero_rows.json"
        zr_path.write_text(json.dumps(zero_rows_man), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=zr_path)
        assert res["status"] == "FAIL"
        assert any("train_row_count' must be positive" in e for e in res["errors"])

        # 15. output_features_count mismatch with output_features_in_order
        mismatch_count_man = copy.deepcopy(man_content)
        order_len = len(mismatch_count_man["output_features_in_order"])
        mismatch_count_man["output_features_count"] = order_len + 1
        mc_path = Path(tmp_dir) / "mismatch_count.json"
        mc_path.write_text(json.dumps(mismatch_count_man), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=mc_path)
        assert res["status"] == "FAIL"
        assert any("output_features_count" in e for e in res["errors"])

        # 16. Split manifest verification negative cases
        # 16a. Nonexistent split manifest
        res = verify_preprocessing_artifact(
            art_path,
            manifest_path=man_path,
            split_manifest_path=Path(tmp_dir) / "nonexistent_sm.json",
        )
        assert res["status"] == "FAIL"
        assert any("Referenced split manifest not found" in e for e in res["errors"])

        # 16b. Empty split manifest {}
        empty_sm = Path(tmp_dir) / "empty_sm.json"
        empty_sm.write_text("{}", encoding="utf-8")
        res = verify_preprocessing_artifact(
            art_path,
            manifest_path=man_path,
            split_manifest_path=empty_sm,
        )
        assert res["status"] == "FAIL"
        assert any("Split manifest is empty or not a valid JSON object" in e for e in res["errors"])

        # 16c. Split manifest with dataset_sha256 mismatch
        bad_ds_sm = Path(tmp_dir) / "bad_ds_sm.json"
        bad_ds_sm.write_text(
            json.dumps(
                {
                    "dataset_sha256": "wrong_hash",
                    "split_protocol_version": SPLIT_PROTOCOL_VERSION,
                }
            ),
            encoding="utf-8",
        )
        res = verify_preprocessing_artifact(
            art_path,
            manifest_path=man_path,
            split_manifest_path=bad_ds_sm,
        )
        assert res["status"] == "FAIL"
        assert any("Split manifest dataset_sha256 mismatch" in e for e in res["errors"])

        # 16d. Split manifest with split_protocol_version mismatch
        bad_ver_sm = Path(tmp_dir) / "bad_ver_sm.json"
        bad_ver_sm.write_text(
            json.dumps(
                {
                    "dataset_sha256": EXPECTED_DATASET_SHA256,
                    "split_protocol_version": "v0.0.1",
                }
            ),
            encoding="utf-8",
        )
        res = verify_preprocessing_artifact(
            art_path,
            manifest_path=man_path,
            split_manifest_path=bad_ver_sm,
        )
        assert res["status"] == "FAIL"
        assert any("Split manifest protocol version mismatch" in e for e in res["errors"])


def test_audit_column_tokens_distinguishes_empty_from_nan():
    """Verify audit_column_tokens separates empty string '' from 'nan', 'inf', '-inf'."""
    s = pd.Series(["", "nan", "NaN", "inf", "+inf", "-inf", "42.0", "100.5"])
    counts, cleaned, masks = audit_column_tokens(s, "test_col", return_masks=True)

    assert counts["missing"] == 1
    assert counts["nan"] == 2
    assert counts["positive_infinity"] == 2
    assert counts["negative_infinity"] == 1
    assert counts["finite"] == 2

    assert bool(masks["missing"][0]) is True
    assert bool(masks["nan"][1]) is True
    assert bool(masks["nan"][2]) is True
    assert bool(masks["pos_inf"][3]) is True
    assert bool(masks["pos_inf"][4]) is True
    assert bool(masks["neg_inf"][5]) is True


def test_add_missing_indicators_behavior(synthetic_47_feature_data):
    """Test add_missing_indicators learns strictly on Train and transforms Val/Test consistently."""
    df_train, df_val, _ = synthetic_47_feature_data

    col_with_missing = "SRC_TO_DST_SECOND_BYTES"
    col_with_nan = "IN_BYTES"

    df_train_mod = df_train.copy()
    df_train_mod.loc[0, col_with_missing] = np.nan
    df_train_mod.loc[1, col_with_nan] = np.nan

    config = PreprocessingConfig(add_missing_indicators=True)
    prep = TrainOnlyPreprocessor(config=config)
    prep.fit(df_train_mod)

    assert len(prep.indicator_features_) >= 2
    indicator_cols = [f"{c}__is_{t}" for c, t in prep.indicator_features_]

    out_train = prep.transform(df_train_mod)
    assert all(c in out_train.columns for c in indicator_cols)
    assert len(out_train.columns) == 47 + len(prep.indicator_features_)

    # Validation missingness in unseen column does NOT add a new column to Val
    df_val_mod = df_val.copy()
    col_clean_in_train = "OUT_BYTES"
    df_val_mod.loc[0, col_clean_in_train] = np.nan

    out_val = prep.transform(df_val_mod)
    assert list(out_val.columns) == list(out_train.columns)
    assert f"{col_clean_in_train}__is_nan" not in out_val.columns

    # Test persistence of indicators across save and load
    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        loaded_prep = TrainOnlyPreprocessor.load(art_path)
        assert loaded_prep.indicator_features_ == prep.indicator_features_
        out_loaded = loaded_prep.transform(df_train_mod)
        pd.testing.assert_frame_equal(out_train, out_loaded)


def test_handle_unknown_categories_strategies(synthetic_47_feature_data):
    """Test handle_unknown_categories: passthrough, sentinel, error, and invalid rejection."""
    # 1. Invalid strategy rejected
    with pytest.raises(ValueError, match="Invalid handle_unknown_categories"):
        PreprocessingConfig(handle_unknown_categories="invalid_strategy")

    df_train, df_val, _ = synthetic_47_feature_data
    cat_col = "PROTOCOL"

    df_train_mod = df_train.copy()
    df_train_mod[cat_col] = 6  # known vocabulary is [6]

    df_val_mod = df_val.copy()
    df_val_mod[cat_col] = 99  # unknown category in Val

    # 2. Strategy: error
    config_err = PreprocessingConfig(handle_unknown_categories="error")
    prep_err = TrainOnlyPreprocessor(config=config_err)
    prep_err.fit(df_train_mod)
    with pytest.raises(ValueError, match="Unseen category encountered"):
        prep_err.transform(df_val_mod)

    # 3. Strategy: sentinel (replaces unknown with train mode, which is 6)
    config_sentinel = PreprocessingConfig(handle_unknown_categories="sentinel")
    prep_sentinel = TrainOnlyPreprocessor(config=config_sentinel)
    prep_sentinel.fit(df_train_mod)
    out_val_sentinel = prep_sentinel.transform(df_val_mod)
    assert (out_val_sentinel[cat_col] == 6).all()

    # 4. Strategy: passthrough (preserves unseen 99)
    config_pass = PreprocessingConfig(handle_unknown_categories="passthrough")
    prep_pass = TrainOnlyPreprocessor(config=config_pass)
    prep_pass.fit(df_train_mod)
    out_val_pass = prep_pass.transform(df_val_mod)
    assert (out_val_pass[cat_col] == 99).all()


def test_audit_column_tokens_safe_with_pd_na_and_nullable_dtypes():
    """Verify audit_column_tokens handles pd.NA, nullable dtypes, and invalid tokens safely."""
    # 1. Object series containing pd.NA, None, '', 'nan', 'null', np.nan, +Inf, -Inf, finite
    s_obj = pd.Series(["", pd.NA, None, "nan", "null", np.nan, "+Inf", "-inf", "42.0", "100.5"])
    counts, cleaned, masks = audit_column_tokens(s_obj, "test_obj_col", return_masks=True)

    assert counts["missing"] == 1  # only ""
    assert counts["nan"] == 5  # pd.NA, None, 'nan', 'null', np.nan
    assert counts["positive_infinity"] == 1
    assert counts["negative_infinity"] == 1
    assert counts["finite"] == 2
    assert counts["invalid_numeric"] == 0

    assert bool(masks["missing"][0]) is True
    assert bool(masks["nan"][1]) is True  # pd.NA safely mapped to nan without ambiguous bool error
    assert bool(masks["nan"][2]) is True  # None
    assert bool(masks["nan"][3]) is True  # 'nan'
    assert bool(masks["nan"][4]) is True  # 'null'
    assert bool(masks["nan"][5]) is True  # np.nan
    assert bool(masks["pos_inf"][6]) is True
    assert bool(masks["neg_inf"][7]) is True

    # 2. Nullable Float64 series
    s_float = pd.Series([1.5, pd.NA, np.nan, np.inf, -np.inf, 20.0], dtype="Float64")
    f_counts, _ = audit_column_tokens(s_float, "test_float_col")
    assert f_counts["nan"] == 2  # pd.NA + np.nan
    assert f_counts["positive_infinity"] == 1
    assert f_counts["negative_infinity"] == 1
    assert f_counts["finite"] == 2

    # 3. Nullable Int64 series
    s_int = pd.Series([10, pd.NA, 20], dtype="Int64")
    i_counts, _ = audit_column_tokens(s_int, "test_int_col")
    assert i_counts["nan"] == 1  # pd.NA
    assert i_counts["finite"] == 2

    # 4. Fail-closed on invalid numeric string
    s_inv = pd.Series(["12.3", "not_a_valid_number", "45.6"])
    with pytest.raises(ValueError, match="invalid numeric token"):
        audit_column_tokens(s_inv, "test_inv_col")


def test_deserialization_prevented_on_artifact_checksum_mismatch(synthetic_47_feature_data):
    """Verify that joblib.load is NEVER called when artifact checksum mismatches."""
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(dataset_sha256=EXPECTED_DATASET_SHA256)
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        # Tamper artifact bytes on disk
        art_path.write_bytes(art_path.read_bytes() + b"\x00\x00_tampered_payload")

        with patch("joblib.load") as mock_joblib_load:
            res = verify_preprocessing_artifact(
                artifact_path=art_path,
                manifest_path=man_path,
            )
            assert res["status"] == "FAIL"
            assert any("Artifact SHA-256 mismatch" in e for e in res["errors"])
            mock_joblib_load.assert_not_called()

        with patch("joblib.load") as mock_joblib_load:
            with pytest.raises(ValueError, match="Artifact SHA-256 mismatch"):
                TrainOnlyPreprocessor.load_verified(
                    artifact_path=art_path,
                    manifest_path=man_path,
                )
            mock_joblib_load.assert_not_called()


def test_verify_artifact_with_raw_dataset_bytes(synthetic_47_feature_data):
    """Verify that verify_preprocessing_artifact validates actual raw dataset bytes."""
    from network_anomaly.preprocessing.pipeline import _sha256_file

    df_train, _, _ = synthetic_47_feature_data
    with tempfile.TemporaryDirectory() as tmp_dir:
        fake_ds = Path(tmp_dir) / "raw_dataset.csv"
        fake_ds.write_text("legitimate raw dataset content", encoding="utf-8")
        actual_ds_hash = _sha256_file(fake_ds)

        fake_sm = Path(tmp_dir) / "split_manifest.json"
        fake_sm.write_text(
            json.dumps(
                {
                    "dataset_sha256": actual_ds_hash,
                    "split_protocol_version": SPLIT_PROTOCOL_VERSION,
                }
            ),
            encoding="utf-8",
        )
        sm_hash = _sha256_file(fake_sm)

        prep = TrainOnlyPreprocessor(
            dataset_sha256=actual_ds_hash,
            split_manifest_sha256=sm_hash,
        )
        prep.fit(df_train)

        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        # 1. Valid dataset bytes -> PASS
        res_pass = verify_preprocessing_artifact(
            artifact_path=art_path,
            manifest_path=man_path,
            split_manifest_path=fake_sm,
            dataset_path=fake_ds,
            expected_dataset_sha256=actual_ds_hash,
        )
        assert res_pass["status"] == "PASS"

        # 2. Tampered dataset bytes -> FAIL
        tampered_ds = Path(tmp_dir) / "tampered_dataset.csv"
        tampered_ds.write_text("tampered bytes that differ from manifest", encoding="utf-8")
        res_fail = verify_preprocessing_artifact(
            artifact_path=art_path,
            manifest_path=man_path,
            split_manifest_path=fake_sm,
            dataset_path=tampered_ds,
            expected_dataset_sha256=actual_ds_hash,
        )
        assert res_fail["status"] == "FAIL"
        assert any("Raw dataset file SHA-256 mismatch" in e for e in res_fail["errors"])

        # 3. Missing dataset file -> FAIL
        res_missing = verify_preprocessing_artifact(
            artifact_path=art_path,
            manifest_path=man_path,
            split_manifest_path=fake_sm,
            dataset_path=Path(tmp_dir) / "nonexistent.csv",
            expected_dataset_sha256=actual_ds_hash,
        )
        assert res_missing["status"] == "FAIL"
        assert any("Referenced raw dataset file not found" in e for e in res_missing["errors"])


def test_load_verified_provenance_enforcement(synthetic_47_feature_data):
    """Test TrainOnlyPreprocessor.load_verified enforces schema, checksums, and policy."""
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        # 1. Valid verified load
        loaded = TrainOnlyPreprocessor.load_verified(
            artifact_path=art_path,
            manifest_path=man_path,
        )
        assert loaded.is_fitted_ is True
        out = loaded.transform(df_train)
        assert len(out) == len(df_train)

        # 2. Missing manifest -> raises ValueError
        with pytest.raises(ValueError, match="Companion manifest file not found"):
            TrainOnlyPreprocessor.load_verified(
                artifact_path=art_path,
                manifest_path=Path(tmp_dir) / "missing_manifest.json",
            )

        # 3. Wrong policy version in manifest -> raises ValueError
        man_dict = json.loads(man_path.read_text(encoding="utf-8"))
        bad_pv_man = Path(tmp_dir) / "bad_pv_man.json"
        bad_pv = copy.deepcopy(man_dict)
        bad_pv["preprocessing_policy_version"] = "invalid_v99"
        bad_pv_man.write_text(json.dumps(bad_pv), encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid preprocessing_policy_version"):
            TrainOnlyPreprocessor.load_verified(
                artifact_path=art_path,
                manifest_path=bad_pv_man,
            )

        # 4. Wrong feature contract in manifest -> raises ValueError
        bad_fc_man = Path(tmp_dir) / "bad_fc_man.json"
        bad_fc = copy.deepcopy(man_dict)
        bad_fc["feature_contract_version"] = "wrong_contract_v0"
        bad_fc_man.write_text(json.dumps(bad_fc), encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid feature_contract_version"):
            TrainOnlyPreprocessor.load_verified(
                artifact_path=art_path,
                manifest_path=bad_fc_man,
            )


def test_direct_load_embedded_metadata_validation(synthetic_47_feature_data):
    """Test TrainOnlyPreprocessor.load() validates embedded policy version and schema."""
    import joblib

    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(dataset_sha256=EXPECTED_DATASET_SHA256)
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        prep.save(art_path)

        payload = joblib.load(art_path)

        # 1. Embedded policy version tampered
        bad_payload = copy.deepcopy(payload)
        bad_payload["metadata"]["preprocessing_policy_version"] = "tampered_policy_v2"
        bad_art = Path(tmp_dir) / "bad_art.joblib"
        joblib.dump(bad_payload, bad_art)

        with pytest.raises(ValueError, match="Preprocessing policy version mismatch"):
            TrainOnlyPreprocessor.load(bad_art)

        # 2. Embedded split protocol version tampered
        bad_sp_payload = copy.deepcopy(payload)
        bad_sp_payload["metadata"]["split_protocol_version"] = "wrong_split_v9"
        bad_sp_art = Path(tmp_dir) / "bad_sp_art.joblib"
        joblib.dump(bad_sp_payload, bad_sp_art)

        with pytest.raises(ValueError, match="Split protocol version mismatch"):
            TrainOnlyPreprocessor.load(bad_sp_art)


def test_zero_duration_flows_regression(synthetic_47_feature_data):
    """Regression test for zero-duration and near-zero duration flows under policy.

    Verifies:
    1. Flows with FLOW_DURATION_MILLISECONDS == 0.0 and <= 1.0 are retained (not dropped).
    2. FLOW_DURATION_MILLISECONDS is not altered or modified.
    3. Throughput features containing infinities (+/- inf) are imputed with Train median,
       never silently zeroed.
    4. Transform outputs strictly 47 features with all finite values.
    5. Save and load maintains bit-identical output.
    """
    df_train, df_val, df_test = synthetic_47_feature_data

    # Inject zero-duration and short-duration edge cases into Train, Val, Test
    for df in (df_train, df_val, df_test):
        df.loc[0, "FLOW_DURATION_MILLISECONDS"] = 0.0
        df.loc[0, "SRC_TO_DST_SECOND_BYTES"] = np.inf
        df.loc[0, "DST_TO_SRC_SECOND_BYTES"] = np.inf

        df.loc[1, "FLOW_DURATION_MILLISECONDS"] = 0.5
        df.loc[1, "SRC_TO_DST_SECOND_BYTES"] = -np.inf
        df.loc[1, "DST_TO_SRC_SECOND_BYTES"] = 100.0

        df.loc[2, "FLOW_DURATION_MILLISECONDS"] = 1.0
        df.loc[2, "SRC_TO_DST_SECOND_BYTES"] = np.nan
        df.loc[2, "DST_TO_SRC_SECOND_BYTES"] = 200.0

    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)

    # Ensure train median was computed from finite values only
    med = prep.imputed_values_["SRC_TO_DST_SECOND_BYTES"]
    assert np.isfinite(med)
    assert med > 0  # Imputed with finite median, NOT silently replaced with zero!

    # Transform all three partitions
    out_train = prep.transform(df_train, partition_name="train")
    out_val = prep.transform(df_val, partition_name="val")
    out_test = prep.transform(df_test, partition_name="test")

    for out, original in ((out_train, df_train), (out_val, df_val), (out_test, df_test)):
        # 1. No rows dropped
        assert len(out) == len(original)
        # 2. Exact 47 baseline columns
        assert list(out.columns) == list(ML_FEATURE_COLUMNS)
        # 3. All finite values
        assert np.all(np.isfinite(out.to_numpy()))
        # 4. Duration values preserved exactly
        assert out.loc[0, "FLOW_DURATION_MILLISECONDS"] == 0.0
        assert out.loc[1, "FLOW_DURATION_MILLISECONDS"] == 0.5
        assert out.loc[2, "FLOW_DURATION_MILLISECONDS"] == 1.0
        # 5. Throughput infinities imputed with finite Train median (not zero)
        assert out.loc[0, "SRC_TO_DST_SECOND_BYTES"] == med
        assert out.loc[1, "SRC_TO_DST_SECOND_BYTES"] == med
        assert out.loc[2, "SRC_TO_DST_SECOND_BYTES"] == med

    # 6. Save and load maintains bit-identical output
    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        loaded = TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)
        out_loaded = loaded.transform(df_val, partition_name="val")
        pd.testing.assert_frame_equal(out_val, out_loaded)


def test_load_verified_deserializes_exactly_once(synthetic_47_feature_data):
    """Verify that load_verified() calls joblib.load exactly once on success.

    Also proves that on artifact checksum mismatch, joblib.load is called ZERO times
    and raises ValueError fail-closed before any deserialization.
    """
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="test_split_manifest_sha256",
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        # 1. Happy path: joblib.load() is called EXACTLY ONCE
        with patch("joblib.load", wraps=joblib.load) as mock_load:
            loaded_prep = TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)
            assert mock_load.call_count == 1
            assert isinstance(loaded_prep, TrainOnlyPreprocessor)
            # Verify transform output is preserved
            out_orig = prep.transform(df_train)
            out_loaded = loaded_prep.transform(df_train)
            pd.testing.assert_frame_equal(out_orig, out_loaded)

        # 2. Checksum mismatch: joblib.load() is called ZERO times
        art_path.write_bytes(b"tampered_bytes_with_checksum_mismatch")
        with patch("joblib.load", wraps=joblib.load) as mock_load:
            with pytest.raises(ValueError, match="Artifact SHA-256 mismatch"):
                TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)
            assert mock_load.call_count == 0


def test_load_verified_rejects_provenance_mismatches(synthetic_47_feature_data):
    """Verify that load_verified() strictly validates split manifest and dataset provenance."""
    df_train, _, _ = synthetic_47_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="canonical_split_sha256",
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        split_path = Path(tmp_dir) / "split_manifest.json"
        ds_path = Path(tmp_dir) / "dataset.csv"

        prep.save(art_path, manifest_path=man_path)

        # Create valid split manifest and raw dataset
        split_path.write_text(
            json.dumps(
                {
                    "dataset_sha256": EXPECTED_DATASET_SHA256,
                    "split_protocol_version": SPLIT_PROTOCOL_VERSION,
                }
            ),
            encoding="utf-8",
        )
        ds_path.write_bytes(b"sample_dataset_bytes")

        # Split manifest mismatch between disk and companion manifest
        with pytest.raises(ValueError, match="does not match current split manifest hash"):
            TrainOnlyPreprocessor.load_verified(
                art_path,
                manifest_path=man_path,
                split_manifest_path=split_path,
            )

        # Raw dataset SHA-256 mismatch
        with pytest.raises(ValueError, match="Raw dataset file SHA-256 mismatch"):
            TrainOnlyPreprocessor.load_verified(
                art_path,
                manifest_path=man_path,
                dataset_path=ds_path,
            )


def test_smoke_report_matches_canonical_provenance_metadata():
    """Verify that REAL_DATA_SMOKE_REPORT.md strictly matches companion manifest and constants."""
    smoke_report_path = REPOSITORY_ROOT / "reports" / "preprocessing" / "REAL_DATA_SMOKE_REPORT.md"
    manifest_path = (
        REPOSITORY_ROOT
        / "reports"
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )
    split_manifest_path = (
        REPOSITORY_ROOT / "data" / "processed" / "nf_unsw_nb15_v3_split_manifest.json"
    )

    if not smoke_report_path.is_file():
        pytest.skip("REAL_DATA_SMOKE_REPORT.md not found")

    assert manifest_path.is_file(), "Companion manifest must exist alongside smoke report"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_text = smoke_report_path.read_text(encoding="utf-8")

    # 1. Split manifest hash consistency
    recorded_sm_sha = manifest["split_manifest_sha256"]
    assert f"`{recorded_sm_sha}`" in report_text
    if split_manifest_path.is_file():
        actual_sm_sha = _sha256_file(split_manifest_path)
        assert recorded_sm_sha == actual_sm_sha

    # 2. Canonical version strings consistency
    assert manifest["preprocessing_policy_version"] == PREPROCESSING_POLICY_VERSION
    assert f"`{PREPROCESSING_POLICY_VERSION}`" in report_text

    assert manifest["feature_contract_version"] == FEATURE_CONTRACT_VERSION
    assert f"`{FEATURE_CONTRACT_VERSION}`" in report_text

    assert manifest["split_protocol_version"] == SPLIT_PROTOCOL_VERSION
    assert f"`{SPLIT_PROTOCOL_VERSION}`" in report_text

    # 3. Artifact SHA-256 consistency
    assert f"`{manifest['artifact_sha256']}`" in report_text

    # 4. Verify description does not claim 'without loading joblib'
    assert "without loading joblib" not in report_text


def _create_mini_smoke_fixture(tmp_dir: Path, df_train: pd.DataFrame):
    """Helper to create a fully consistent, self-contained mini real-data fixture."""
    dataset_p = tmp_dir / "NF-UNSW-NB15-v3.csv"
    dataset_p.write_bytes(b"dummy_dataset_bytes_for_fail_closed_testing")
    ds_sha = _sha256_file(dataset_p)

    split_p = tmp_dir / "split_manifest.json"
    split_manifest = {
        "dataset_name": "NF-UNSW-NB15-v3",
        "dataset_sha256": ds_sha,
        "split_protocol_version": SPLIT_PROTOCOL_VERSION,
        "total_source_rows": len(df_train) + 40 + 5,
        "features": {
            "baseline_ml_features_count": len(ML_FEATURE_COLUMNS),
            "baseline_ml_features_in_order": list(ML_FEATURE_COLUMNS),
        },
        "partitions": {
            "train": {"row_count": len(df_train)},
            "validation": {"row_count": 20},
            "test": {"row_count": 20},
        },
        "audit_summary": {"purged_records": {"total_purged_rows": 5}},
    }
    split_p.write_text(json.dumps(split_manifest), encoding="utf-8")
    sm_sha = _sha256_file(split_p)

    art_p = tmp_dir / "preprocessor.joblib"
    man_p = tmp_dir / "manifest.json"
    prep = TrainOnlyPreprocessor(dataset_sha256=ds_sha, split_manifest_sha256=sm_sha)
    prep.fit(df_train)
    prep.save(art_p, manifest_path=man_p)
    art_sha = _sha256_file(art_p)

    ev_p = tmp_dir / "execution_evidence.json"
    evidence = {
        "schema_version": "v1",
        "dataset_path": dataset_p.as_posix(),
        "dataset_sha256": ds_sha,
        "dataset_bytes": len(dataset_p.read_bytes()),
        "split_manifest_path": split_p.as_posix(),
        "split_manifest_sha256": sm_sha,
        "artifact_path": art_p.as_posix(),
        "artifact_sha256": art_sha,
        "companion_manifest_path": man_p.as_posix(),
        "fit_and_transform": {
            "status": "PASS",
            "execution_time_seconds": 1.23,
            "scaler_type": "none",
            "features_count": 47,
            "partitions": {
                "train": {
                    "row_count": len(df_train),
                    "feature_count": 47,
                    "all_finite": True,
                    "zero_duration_flows_count": 2,
                    "zero_duration_retained": True,
                    "zero_duration_retention_status": "PASS",
                },
                "validation": {
                    "row_count": 20,
                    "feature_count": 47,
                    "all_finite": True,
                    "zero_duration_flows_count": 1,
                    "zero_duration_retained": True,
                    "zero_duration_retention_status": "PASS",
                },
                "test": {
                    "row_count": 20,
                    "feature_count": 47,
                    "all_finite": True,
                    "zero_duration_flows_count": 1,
                    "zero_duration_retained": True,
                    "zero_duration_retention_status": "PASS",
                },
            },
            "purged_rows": 5,
            "total_rows": len(df_train) + 40 + 5,
        },
        "verify_only": {
            "status": "PASS",
            "exit_code": 0,
            "artifact_integrity_verified": True,
            "dataset_bytes_verified": True,
            "manifest_schema_verified": True,
        },
        "check_reproducibility": {
            "status": "PASS",
            "exit_code": 0,
            "parameters_identical": True,
            "outputs_identical": True,
        },
    }
    ev_p.write_text(json.dumps(evidence), encoding="utf-8")
    return dataset_p, split_p, art_p, man_p, ev_p, ds_sha


def test_smoke_generator_fails_when_raw_dataset_missing(synthetic_47_feature_data):
    """Negative test: fail-closed if raw dataset is missing (no fallback!)."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Delete raw dataset file
        dataset_p.unlink()
        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_split_manifest_missing(synthetic_47_feature_data):
    """Negative test: fail-closed if split manifest is missing (no fallback to companion!)."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Delete split manifest file
        split_p.unlink()
        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_artifact_missing(synthetic_47_feature_data):
    """Negative test: fail-closed if artifact .joblib is missing (no fallback!)."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Delete artifact file
        art_p.unlink()
        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_companion_manifest_missing(synthetic_47_feature_data):
    """Negative test: fail-closed if companion manifest is missing."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Delete companion manifest file
        man_p.unlink()
        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_execution_evidence_missing(synthetic_47_feature_data):
    """Negative test: fail-closed if execution evidence is missing."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Delete execution evidence file
        ev_p.unlink()
        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_execution_evidence_not_pass(synthetic_47_feature_data):
    """Negative test: fail-closed if execution evidence recorded a FAIL status."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Corrupt evidence status to FAIL
        ev_data = json.loads(ev_p.read_text(encoding="utf-8"))
        ev_data["fit_and_transform"]["status"] = "FAIL"
        ev_p.write_text(json.dumps(ev_data), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_artifact_tampered_before_deserialization(
    synthetic_47_feature_data,
):
    """Negative test: checksum mismatch fails closed BEFORE joblib.load is called."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Tamper artifact bytes on disk
        art_p.write_bytes(b"tampered_artifact_bytes")

        with patch("joblib.load") as mock_load:
            success = gen_mod.generate_smoke_report(
                report_path=rep_p,
                manifest_path=man_p,
                artifact_path=art_p,
                split_manifest_path=split_p,
                dataset_path=dataset_p,
                evidence_path=ev_p,
                expected_dataset_sha256=ds_sha,
            )
            assert not success
            assert mock_load.call_count == 0
            assert not rep_p.is_file()


def test_smoke_generator_fails_when_dataset_tampered(synthetic_47_feature_data):
    """Negative test: dataset bytes tampered after manifest generation fails closed."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Tamper dataset bytes
        dataset_p.write_bytes(b"tampered_dataset_bytes")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_split_tampered(synthetic_47_feature_data):
    """Negative test: split manifest modified after companion generation fails closed."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # Tamper split manifest
        split_p.write_text('{"modified": true}', encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_succeeds_with_valid_fixture(synthetic_47_feature_data):
    """Positive test: complete, consistent fixture generates report and passes verify_real_data."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        # 1. Generate report
        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert success
        assert rep_p.is_file()
        rep_text = rep_p.read_text(encoding="utf-8")
        assert "1.23s execution time" in rep_text
        assert "REAL-DATA VERIFIED" not in rep_text or "Status:" in rep_text

        # 2. Verify with verify_real_data=True
        verify_success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
            verify_real_data=True,
        )
        assert verify_success


def test_smoke_generator_check_consistency_mode():
    """Test check-report-consistency mode verifies Markdown syntax without requiring raw CSV."""
    gen_mod = _load_smoke_report_generator()
    smoke_report_path = REPOSITORY_ROOT / "reports" / "preprocessing" / "REAL_DATA_SMOKE_REPORT.md"
    manifest_path = (
        REPOSITORY_ROOT
        / "reports"
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )

    if not smoke_report_path.is_file():
        pytest.skip("REAL_DATA_SMOKE_REPORT.md not found")

    # Consistent report passes
    assert gen_mod.verify_report_consistency(smoke_report_path, manifest_path)

    # Inconsistent manifest path fails
    nonexistent_man = REPOSITORY_ROOT / "reports" / "preprocessing" / "nonexistent.json"
    assert not gen_mod.verify_report_consistency(smoke_report_path, nonexistent_man)


def test_smoke_generator_fails_when_evidence_train_rows_mismatch(synthetic_47_feature_data):
    """Negative test: fail-closed if evidence train row_count mismatches split manifest."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["partitions"]["train"]["row_count"] += 1
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_evidence_val_rows_mismatch(synthetic_47_feature_data):
    """Negative test: fail-closed if evidence validation row_count mismatches split manifest."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["partitions"]["validation"]["row_count"] += 1
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_evidence_test_rows_mismatch(synthetic_47_feature_data):
    """Negative test: fail-closed if evidence test row_count mismatches split manifest."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["partitions"]["test"]["row_count"] += 1
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_evidence_purged_rows_mismatch(synthetic_47_feature_data):
    """Negative test: fail-closed if evidence purged_rows mismatches split manifest."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["purged_rows"] += 1
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_evidence_total_rows_mismatch(synthetic_47_feature_data):
    """Negative test: fail-closed if evidence total_rows mismatches canonical sum."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["total_rows"] += 1
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_evidence_partition_count_missing(synthetic_47_feature_data):
    """Negative test: fail-closed if required partition is missing in evidence."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        del ev["fit_and_transform"]["partitions"]["validation"]
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_evidence_row_count_not_strict_int(synthetic_47_feature_data):
    """Negative test: reject bool, float, or negative integers for row counts in evidence."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    for invalid_val in (True, 20.5, -1, "20"):
        with tempfile.TemporaryDirectory() as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
                tmp_dir, df_train
            )
            rep_p = tmp_dir / "REPORT.md"

            ev = json.loads(ev_p.read_text(encoding="utf-8"))
            ev["fit_and_transform"]["partitions"]["validation"]["row_count"] = invalid_val
            ev_p.write_text(json.dumps(ev), encoding="utf-8")

            success = gen_mod.generate_smoke_report(
                report_path=rep_p,
                manifest_path=man_p,
                artifact_path=art_p,
                split_manifest_path=split_p,
                dataset_path=dataset_p,
                evidence_path=ev_p,
                expected_dataset_sha256=ds_sha,
            )
            assert not success
            assert not rep_p.is_file()


def test_smoke_generator_fails_when_row_count_tampered_with_unchanged_hashes(
    synthetic_47_feature_data,
):
    """Negative test: modifying row counts while keeping checksums identical fails verification."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["partitions"]["train"]["row_count"] = 999999
        ev["fit_and_transform"]["total_rows"] = 999999 + 40 + 5
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
            verify_real_data=True,
        )
        assert not success


def test_smoke_generator_fails_when_evidence_features_count_mismatch(synthetic_47_feature_data):
    """Negative test: fail-closed if evidence features_count != 47."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["features_count"] = 46
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_companion_manifest_features_count_mismatch(
    synthetic_47_feature_data,
):
    """Negative test: fail-closed if companion manifest output_features_count != 47."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        man = json.loads(man_p.read_text(encoding="utf-8"))
        man["output_features_count"] = 46
        man_p.write_text(json.dumps(man), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_companion_manifest_features_order_mismatch(
    synthetic_47_feature_data,
):
    """Negative test: fail-closed if companion manifest feature ordering is altered."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        man = json.loads(man_p.read_text(encoding="utf-8"))
        order = list(man["output_features_in_order"])
        order[0], order[1] = order[1], order[0]
        man["output_features_in_order"] = order
        man_p.write_text(json.dumps(man), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_smoke_generator_fails_when_evidence_partition_shape_mismatch(synthetic_47_feature_data):
    """Negative test: fail-closed if evidence partition shape does not match (N, 47)."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["partitions"]["train"]["shape"] = [len(df_train), 46]
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_zero_duration_retention_when_flows_retained():
    """Positive test: zero-duration flows preserved with exact 0.0 duration returns PASS."""
    df_before = pd.DataFrame(
        {
            "FLOW_DURATION_MILLISECONDS": [0.0, 150.0, 0.0, 25.0],
            "IN_BYTES": [100, 200, 300, 400],
        },
        index=[0, 1, 2, 3],
    )
    df_after = df_before.copy()

    res = verify_zero_duration_retention(df_before, df_after)
    assert res["status"] == "PASS"
    assert res["zero_duration_flows_count"] == 2
    assert res["zero_duration_retained"] is True


def test_zero_duration_retention_when_no_zero_duration_flows():
    """Boundary test: input with no zero-duration flows returns NOT APPLICABLE."""
    df_before = pd.DataFrame(
        {
            "FLOW_DURATION_MILLISECONDS": [100.0, 150.0, 25.0],
        },
        index=[0, 1, 2],
    )
    df_after = df_before.copy()

    res = verify_zero_duration_retention(df_before, df_after)
    assert res["status"] == "NOT APPLICABLE"
    assert res["zero_duration_flows_count"] == 0
    assert res["zero_duration_retained"] is True


def test_zero_duration_retention_when_flow_dropped():
    """Negative test: dropping a zero-duration row returns FAIL."""
    df_before = pd.DataFrame(
        {
            "FLOW_DURATION_MILLISECONDS": [0.0, 100.0, 0.0],
        },
        index=[0, 1, 2],
    )
    df_after = df_before.loc[[0, 1]].copy()

    res = verify_zero_duration_retention(df_before, df_after)
    assert res["status"] == "FAIL"
    assert res["zero_duration_retained"] is False


def test_zero_duration_retention_when_duration_modified():
    """Negative test: altering duration value from 0.0 to non-zero returns FAIL."""
    df_before = pd.DataFrame(
        {
            "FLOW_DURATION_MILLISECONDS": [0.0, 100.0],
        },
        index=[0, 1],
    )
    df_after = df_before.copy()
    df_after.loc[0, "FLOW_DURATION_MILLISECONDS"] = 1.0

    res = verify_zero_duration_retention(df_before, df_after)
    assert res["status"] == "FAIL"
    assert res["zero_duration_retained"] is False


def test_zero_duration_retention_with_duplicate_records():
    """Duplicate records with distinct indices retain unambiguous 1-to-1 mapping."""
    df_before = pd.DataFrame(
        {
            "FLOW_DURATION_MILLISECONDS": [0.0, 0.0],
            "IN_BYTES": [100, 100],
        },
        index=[10, 20],
    )
    df_after = df_before.copy()

    res = verify_zero_duration_retention(df_before, df_after)
    assert res["status"] == "PASS"
    assert res["zero_duration_flows_count"] == 2
    assert res["zero_duration_retained"] is True


def test_zero_duration_retention_ambiguous_row_identity():
    """Ambiguous row identity (duplicate index labels) returns NOT VERIFIED."""
    df_before = pd.DataFrame(
        {
            "FLOW_DURATION_MILLISECONDS": [0.0, 0.0],
        },
        index=[0, 0],
    )
    df_after = df_before.copy()

    res = verify_zero_duration_retention(df_before, df_after)
    assert res["status"] == "NOT VERIFIED"
    assert res["zero_duration_retained"] is False


def test_zero_duration_retention_missing_column():
    """Missing duration column returns NOT VERIFIED."""
    df_before = pd.DataFrame({"IN_BYTES": [100]})
    df_after = pd.DataFrame({"IN_BYTES": [100]})

    res = verify_zero_duration_retention(df_before, df_after)
    assert res["status"] == "NOT VERIFIED"
    assert res["zero_duration_retained"] is False


def test_zero_duration_retention_does_not_mutate_inputs_or_policy():
    """Verification is read-only and does not mutate DataFrames or imputation policy."""
    df_before = pd.DataFrame(
        {
            "FLOW_DURATION_MILLISECONDS": [0.0, 50.0],
        }
    )
    df_after = df_before.copy()
    orig_before = df_before.copy(deep=True)
    orig_after = df_after.copy(deep=True)

    verify_zero_duration_retention(df_before, df_after)
    pd.testing.assert_frame_equal(df_before, orig_before)
    pd.testing.assert_frame_equal(df_after, orig_after)


def test_smoke_generator_fails_when_evidence_zero_duration_not_retained(synthetic_47_feature_data):
    """Negative test: fail-closed if evidence records zero_duration_retained as False or FAIL."""
    df_train, _, _ = synthetic_47_feature_data
    gen_mod = _load_smoke_report_generator()

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        dataset_p, split_p, art_p, man_p, ev_p, ds_sha = _create_mini_smoke_fixture(
            tmp_dir, df_train
        )
        rep_p = tmp_dir / "REPORT.md"

        ev = json.loads(ev_p.read_text(encoding="utf-8"))
        ev["fit_and_transform"]["partitions"]["train"]["zero_duration_retention_status"] = "FAIL"
        ev["fit_and_transform"]["partitions"]["train"]["zero_duration_retained"] = False
        ev_p.write_text(json.dumps(ev), encoding="utf-8")

        success = gen_mod.generate_smoke_report(
            report_path=rep_p,
            manifest_path=man_p,
            artifact_path=art_p,
            split_manifest_path=split_p,
            dataset_path=dataset_p,
            evidence_path=ev_p,
            expected_dataset_sha256=ds_sha,
        )
        assert not success
        assert not rep_p.is_file()


def test_real_data_smoke_report_in_repo_is_fully_verified():
    """Verify that the repository's REAL_DATA_SMOKE_REPORT.md passes full verification."""
    gen_mod = _load_smoke_report_generator()
    dataset_p = (
        REPOSITORY_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
    )
    if not dataset_p.is_file():
        pytest.skip("Raw dataset not present in this environment")

    assert gen_mod.generate_smoke_report(verify_real_data=True)
