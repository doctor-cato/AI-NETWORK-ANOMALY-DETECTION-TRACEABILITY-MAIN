"""Unit tests for NetFlow Sentinel v2 train-only preprocessing pipeline.

Tests all mandatory criteria on the canonical 18-feature v2 contract (canonical-flow-v2-18):
1. Exact 18 baseline ML features in exact contract order.
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
14. asinh_robust scaler behavior and real v2 preprocessor artifact verification.
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from typing import Dict, Tuple
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.v2_schema import (
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.preprocessing.pipeline import (
    ARTIFACT_TYPE,
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_POLICY_VERSION,
    SPLIT_PROTOCOL_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
    _sha256_file,
    audit_column_tokens,
    verify_preprocessing_artifact,
    verify_zero_duration_retention,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TEST_DATASET_SHA = "cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf"
TEST_SPLIT_SHA = "1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a"


@pytest.fixture
def synthetic_18_feature_data() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Generate small synthetic Train, Validation, and Test feature matrices."""
    rng = np.random.default_rng(42)

    def _make_df(n_rows: int) -> pd.DataFrame:
        data: Dict[str, np.ndarray] = {}
        for col in ML_FEATURE_COLUMNS:
            if col in CATEGORICAL_CODED_COLUMNS:
                data[col] = rng.choice([6, 17, 1], size=n_rows)
            elif col in ("bytes_in_ratio", "pkts_in_ratio"):
                data[col] = rng.uniform(0.1, 0.9, size=n_rows)
            elif col in ("has_response", "is_tcp", "is_udp"):
                data[col] = rng.integers(0, 2, size=n_rows).astype(float)
            else:
                data[col] = np.abs(rng.normal(loc=100.0, scale=15.0, size=n_rows)) + 1.0
        return pd.DataFrame(data, columns=list(ML_FEATURE_COLUMNS))

    return _make_df(50), _make_df(20), _make_df(20)


def test_criterion_1_exact_18_features_in_exact_order(synthetic_18_feature_data):
    """Criterion 1: Exactly 18 baseline ML features in exact order."""
    df_train, df_val, df_test = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)

    assert len(ML_FEATURE_COLUMNS) == 18
    for df_in in (df_train, df_val, df_test):
        out = prep.transform(df_in)
        assert list(out.columns) == list(ML_FEATURE_COLUMNS)
        assert len(out.columns) == 18


def test_criterion_2_targets_and_trace_metadata_rejected(synthetic_18_feature_data):
    """Criterion 2: Targets and trace metadata are strictly rejected in X."""
    df_train, _, _ = synthetic_18_feature_data

    for target_col in TARGET_COLUMNS:
        df_bad = df_train.copy()
        df_bad[target_col] = 1
        prep = TrainOnlyPreprocessor()
        with pytest.raises(ValueError, match="forbidden|Contract"):
            prep.fit(df_bad)

    for meta_col in TRACE_METADATA_COLUMNS:
        df_bad = df_train.copy()
        df_bad[meta_col] = 1000
        prep = TrainOnlyPreprocessor()
        with pytest.raises(ValueError, match="forbidden|Contract"):
            prep.fit(df_bad)


def test_criterion_3_fit_strictly_on_train(synthetic_18_feature_data):
    """Criterion 3: Imputer statistics and vocabularies are learned EXCLUSIVELY from Train."""
    df_train, df_val, _ = synthetic_18_feature_data

    col_q = "bytes_in"
    known_train_vals = np.array([10.0, 20.0, 30.0, 40.0, 50.0] * 10)
    df_train[col_q] = known_train_vals
    expected_median = float(np.median(known_train_vals))

    df_val[col_q] = np.array([999.0] * len(df_val))

    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)
    assert prep.train_row_count_ == len(df_train)

    df_val_with_nan = df_val.copy()
    df_val_with_nan.loc[0, col_q] = np.nan
    out_val = prep.transform(df_val_with_nan)

    assert out_val.loc[0, col_q] == expected_median


def test_criterion_4_changing_val_test_does_not_affect_fitted_state(synthetic_18_feature_data):
    """Criterion 4: Modifying Validation/Test data does not alter fitted state."""
    df_train, df_val, _ = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)

    imputed_before = copy.deepcopy(prep.imputed_values_)
    vocab_before = copy.deepcopy(prep.category_vocabularies_)

    prep.transform(df_val)
    assert prep.imputed_values_ == imputed_before
    assert prep.category_vocabularies_ == vocab_before

    prep.transform(df_val.copy() * 10.0)
    assert prep.imputed_values_ == imputed_before
    assert prep.category_vocabularies_ == vocab_before


def test_criterion_5_extreme_outliers_in_val_test_do_not_alter_train_statistics(
    synthetic_18_feature_data,
):
    """Criterion 5: Extreme outliers in Validation/Test do not leak into Train statistics."""
    df_train, df_val, _ = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="standard"))
    prep.fit(df_train)

    imputed_frozen = copy.deepcopy(prep.imputed_values_)
    scaler_frozen = copy.deepcopy(prep.scaler_params_)

    df_val_extreme = df_val.copy()
    df_val_extreme.iloc[0, 2] = 1e18
    df_val_extreme.iloc[1, 2] = -1e18
    df_val_extreme.iloc[2, 2] = np.inf
    df_val_extreme.iloc[3, 2] = -np.inf
    df_val_extreme.iloc[4, 2] = np.nan

    out_val = prep.transform(df_val_extreme)

    assert prep.imputed_values_ == imputed_frozen
    assert prep.scaler_params_ == scaler_frozen
    assert np.all(np.isfinite(out_val.to_numpy()))


def test_criterion_6_nan_infinity_and_invalid_numeric_handling(synthetic_18_feature_data):
    """Criterion 6: NaN and infinities imputed with train median/mode; invalid numerics rejected."""
    df_train, df_val, _ = synthetic_18_feature_data
    col = "bytes_per_sec_in"

    df_train.loc[0, col] = np.nan
    df_train.loc[1, col] = np.inf
    df_train.loc[2, col] = -np.inf

    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)

    audit = prep.audit_counts_train_[col]
    assert audit["nan"] == 1
    assert audit["positive_infinity"] == 1
    assert audit["negative_infinity"] == 1
    assert audit["total_non_finite"] == 3

    out_train = prep.transform(df_train)
    assert np.all(np.isfinite(out_train[col].to_numpy()))

    df_val_inf = df_val.copy()
    df_val_inf.loc[0, col] = np.inf
    out_val = prep.transform(df_val_inf)
    assert out_val.loc[0, col] == prep.imputed_values_[col]
    assert prep.imputed_values_[col] != 0.0

    df_bad = df_train.copy()
    df_bad[col] = df_bad[col].astype(object)
    df_bad.loc[5, col] = "unparseable_string_token"
    prep_fail = TrainOnlyPreprocessor()
    with pytest.raises(ValueError, match="invalid numeric token"):
        prep_fail.fit(df_bad)


def test_criterion_7_schema_mismatch_fails_closed(synthetic_18_feature_data):
    """Criterion 7: Missing, extra, or reordered columns fail closed."""
    df_train, _, _ = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor()

    df_missing = df_train.drop(columns=[ML_FEATURE_COLUMNS[0]])
    with pytest.raises(ValueError):
        prep.fit(df_missing)

    df_extra = df_train.copy()
    df_extra["UNKNOWN_COL"] = 123
    with pytest.raises(ValueError):
        prep.fit(df_extra)

    cols_reordered = list(ML_FEATURE_COLUMNS)
    cols_reordered[0], cols_reordered[1] = cols_reordered[1], cols_reordered[0]
    df_reordered = df_train[cols_reordered]
    with pytest.raises(ValueError):
        prep.fit(df_reordered)


def test_criterion_8_save_and_load_artifact_equivalence(synthetic_18_feature_data):
    """Criterion 8: Saved and loaded artifact gives identical transformation."""
    df_train, _, df_test = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="asinh_robust"),
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)

    out_original = prep.transform(df_test)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"

        prep.save(art_path, manifest_path=man_path)

        prep_loaded = TrainOnlyPreprocessor.load(art_path)
        out_loaded = prep_loaded.transform(df_test)

        pd.testing.assert_frame_equal(out_original, out_loaded)
        assert prep_loaded.imputed_values_ == prep.imputed_values_
        assert prep_loaded.scaler_params_ == prep.scaler_params_


def test_criterion_9_artifact_with_wrong_checksum_rejected(synthetic_18_feature_data):
    """Criterion 9: Artifact with mismatched dataset/manifest hash is rejected."""
    df_train, _, _ = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        prep.save(art_path)

        with pytest.raises(ValueError, match="Dataset SHA-256 mismatch"):
            TrainOnlyPreprocessor.load(art_path, expected_dataset_sha256="wrong_dataset_hash")

        with pytest.raises(ValueError, match="Split manifest SHA-256 mismatch"):
            TrainOnlyPreprocessor.load(art_path, expected_manifest_sha256="wrong_manifest_hash")


def test_criterion_10_input_dataframe_not_modified_in_place(synthetic_18_feature_data):
    """Criterion 10: Processing does not modify input DataFrame in-place."""
    df_train, df_val, _ = synthetic_18_feature_data
    df_val.loc[0, "bytes_in"] = np.nan

    df_val_before = df_val.copy(deep=True)

    prep = TrainOnlyPreprocessor(
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)
    out_val = prep.transform(df_val)

    pd.testing.assert_frame_equal(df_val, df_val_before)
    assert np.isfinite(out_val.loc[0, "bytes_in"])


def test_criterion_11_constant_and_all_missing_features(synthetic_18_feature_data):
    """Criterion 11: Constant features and all-missing features are handled robustly."""
    df_train, df_val, _ = synthetic_18_feature_data

    col_const = "duration_ms"
    df_train[col_const] = 42.0
    df_val[col_const] = 42.0

    col_missing = "bytes_per_pkt_in"
    df_train[col_missing] = np.nan
    df_val[col_missing] = np.nan

    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="asinh_robust"))
    prep.fit(df_train)

    assert col_const in prep.constant_features_
    assert col_missing in prep.all_missing_columns_

    out_train = prep.transform(df_train)
    out_val = prep.transform(df_val)

    assert np.all(np.isfinite(out_train[col_const].to_numpy()))
    assert np.all(np.isfinite(out_val[col_const].to_numpy()))
    assert np.all(np.isfinite(out_train[col_missing].to_numpy()))
    assert np.all(np.isfinite(out_val[col_missing].to_numpy()))


def test_criterion_12_output_finite_shape_and_dtypes(synthetic_18_feature_data):
    """Criterion 12: Outputs strictly have shape (N, 18), exact feature names, and all finite values."""
    df_train, df_val, df_test = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type="minmax"))
    prep.fit(df_train)

    for df_in, name in [(df_train, "train"), (df_val, "val"), (df_test, "test")]:
        df_out = prep.transform(df_in, partition_name=name)
        assert df_out.shape == (len(df_in), 18)
        assert list(df_out.columns) == list(ML_FEATURE_COLUMNS)
        assert np.all(np.isfinite(df_out.to_numpy()))


def test_criterion_13_no_preprocessing_step_uses_target_as_feature(synthetic_18_feature_data):
    """Criterion 13: Passing target to fit(X, y) strictly does not influence transformation."""
    df_train, df_val, _ = synthetic_18_feature_data

    prep1 = TrainOnlyPreprocessor()
    prep1.fit(df_train)
    out1 = prep1.transform(df_val)

    y_synth = pd.Series(np.ones(len(df_train), dtype=int))
    prep2 = TrainOnlyPreprocessor()
    prep2.fit(df_train, y=y_synth)
    out2 = prep2.transform(df_val)

    pd.testing.assert_frame_equal(out1, out2)
    assert prep1.imputed_values_ == prep2.imputed_values_


def test_categorical_coded_columns_never_scaled_as_continuous(synthetic_18_feature_data):
    """Test that protocol_num (categorical-coded) is NEVER scaled by continuous scalers."""
    df_train, _, _ = synthetic_18_feature_data
    for scaler in ("standard", "robust", "asinh_robust"):
        prep = TrainOnlyPreprocessor(config=PreprocessingConfig(scaler_type=scaler))
        prep.fit(df_train)

        for cat_col in CATEGORICAL_CODED_COLUMNS:
            assert cat_col not in prep.scaler_params_

        for quant_col in QUANTITATIVE_ML_COLUMNS:
            assert quant_col in prep.scaler_params_

        out = prep.transform(df_train)
        for cat_col in CATEGORICAL_CODED_COLUMNS:
            arr = out[cat_col].to_numpy()
            np.testing.assert_allclose(arr, np.round(arr))


def test_verify_preprocessing_artifact_helper(synthetic_18_feature_data):
    """Test verify_preprocessing_artifact on a valid artifact."""
    df_train, _, _ = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        res = verify_preprocessing_artifact(
            artifact_path=art_path,
            manifest_path=man_path,
            expected_dataset_sha256=TEST_DATASET_SHA,
        )
        assert res["status"] == "PASS"
        assert len(res["errors"]) == 0


def test_verify_artifact_negative_cases(synthetic_18_feature_data):
    """Negative tests for artifact verification: missing, corrupted, altered, or mismatched."""
    df_train, _, _ = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        missing_man = Path(tmp_dir) / "nonexistent.json"
        res = verify_preprocessing_artifact(art_path, manifest_path=missing_man)
        assert res["status"] == "FAIL"

        bad_json_man = Path(tmp_dir) / "bad_json.json"
        bad_json_man.write_text("not-a-valid-json", encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=bad_json_man)
        assert res["status"] == "FAIL"

        tampered_art = Path(tmp_dir) / "tampered.joblib"
        tampered_art.write_bytes(art_path.read_bytes() + b"\x00\x00")
        res = verify_preprocessing_artifact(tampered_art, manifest_path=man_path)
        assert res["status"] == "FAIL"
        assert any("SHA-256 mismatch" in e for e in res["errors"])

        man_content = json.loads(man_path.read_text(encoding="utf-8"))
        for key, bad_val in (
            ("split_manifest_sha256", "b" * 64),
            ("feature_contract_version", "wrong-contract-version"),
            ("preprocessing_policy_version", "v999.0"),
        ):
            altered = copy.deepcopy(man_content)
            altered[key] = bad_val
            p = Path(tmp_dir) / f"bad_{key}.json"
            p.write_text(json.dumps(altered), encoding="utf-8")
            res = verify_preprocessing_artifact(art_path, manifest_path=p)
            assert res["status"] == "FAIL"

        tampered_order = copy.deepcopy(man_content)
        tampered_order["baseline_ml_features_in_order"].reverse()
        p_ord = Path(tmp_dir) / "bad_order.json"
        p_ord.write_text(json.dumps(tampered_order), encoding="utf-8")
        res = verify_preprocessing_artifact(art_path, manifest_path=p_ord)
        assert res["status"] == "FAIL"


def test_audit_column_tokens_distinguishes_empty_from_nan():
    """Verify audit_column_tokens separates empty string '' from 'nan', 'inf', '-inf'."""
    s = pd.Series(["", "nan", "NaN", "inf", "+inf", "-inf", "42.0", "100.5"])
    counts, _, masks = audit_column_tokens(s, "test_col", return_masks=True)

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


def test_add_missing_indicators_behavior(synthetic_18_feature_data):
    """Test add_missing_indicators learns strictly on Train and transforms Val/Test consistently."""
    df_train, df_val, _ = synthetic_18_feature_data

    col_with_missing = "bytes_per_sec_in"
    col_with_nan = "bytes_in"

    df_train_mod = df_train.copy()
    df_train_mod.loc[0, col_with_missing] = np.nan
    df_train_mod.loc[1, col_with_nan] = np.nan

    config = PreprocessingConfig(add_missing_indicators=True)
    prep = TrainOnlyPreprocessor(
        config=config,
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train_mod)

    assert len(prep.indicator_features_) >= 2
    indicator_cols = [f"{c}__is_{t}" for c, t in prep.indicator_features_]

    out_train = prep.transform(df_train_mod)
    assert all(c in out_train.columns for c in indicator_cols)
    assert len(out_train.columns) == 18 + len(prep.indicator_features_)

    df_val_mod = df_val.copy()
    col_clean_in_train = "bytes_out"
    df_val_mod.loc[0, col_clean_in_train] = np.nan

    out_val = prep.transform(df_val_mod)
    assert list(out_val.columns) == list(out_train.columns)
    assert f"{col_clean_in_train}__is_nan" not in out_val.columns

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        loaded_prep = TrainOnlyPreprocessor.load(art_path)
        assert loaded_prep.indicator_features_ == prep.indicator_features_
        out_loaded = loaded_prep.transform(df_train_mod)
        pd.testing.assert_frame_equal(out_train, out_loaded)


def test_handle_unknown_categories_strategies(synthetic_18_feature_data):
    """Test handle_unknown_categories: passthrough, sentinel, error, and invalid rejection."""
    with pytest.raises(ValueError, match="Invalid handle_unknown_categories"):
        PreprocessingConfig(handle_unknown_categories="invalid_strategy")

    df_train, df_val, _ = synthetic_18_feature_data
    cat_col = "protocol_num"

    df_train_mod = df_train.copy()
    df_train_mod[cat_col] = 6

    df_val_mod = df_val.copy()
    df_val_mod[cat_col] = 99

    prep_err = TrainOnlyPreprocessor(config=PreprocessingConfig(handle_unknown_categories="error"))
    prep_err.fit(df_train_mod)
    with pytest.raises(ValueError, match="Unseen category in 'protocol_num'"):
        prep_err.transform(df_val_mod)

    prep_sentinel = TrainOnlyPreprocessor(
        config=PreprocessingConfig(handle_unknown_categories="sentinel")
    )
    prep_sentinel.fit(df_train_mod)
    out_val_sentinel = prep_sentinel.transform(df_val_mod)
    assert (out_val_sentinel[cat_col] == 6).all()

    prep_pass = TrainOnlyPreprocessor(
        config=PreprocessingConfig(handle_unknown_categories="passthrough")
    )
    prep_pass.fit(df_train_mod)
    out_val_pass = prep_pass.transform(df_val_mod)
    assert (out_val_pass[cat_col] == 99).all()


def test_deserialization_prevented_on_artifact_checksum_mismatch(synthetic_18_feature_data):
    """Verify that joblib.load is NEVER called when artifact checksum mismatches."""
    df_train, _, _ = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "preprocessor.joblib"
        man_path = Path(tmp_dir) / "manifest.json"
        prep.save(art_path, manifest_path=man_path)

        art_path.write_bytes(art_path.read_bytes() + b"tampered")
        with patch("network_anomaly.preprocessing.pipeline.joblib.load") as mock_load:
            with pytest.raises(ValueError, match="SHA-256 mismatch"):
                TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)
            assert mock_load.call_count == 0


def test_v1_preprocessor_artifact_rejected_fail_closed(synthetic_18_feature_data, tmp_path):
    """Verify TrainOnlyPreprocessor rejects any v1 NF-UNSW-NB15-v3 artifact or metadata."""
    df_train, _, _ = synthetic_18_feature_data
    prep = TrainOnlyPreprocessor(
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)
    art_path = tmp_path / "v1_prep.joblib"
    prep.save(art_path)

    payload = joblib.load(art_path)
    payload["metadata"]["artifact_type"] = "nf-unsw-nb15-v3-train-only-preprocessor"
    joblib.dump(payload, art_path)

    with pytest.raises(ValueError, match="v1 artifacts rejected"):
        TrainOnlyPreprocessor.load(art_path)


def test_zero_duration_flows_regression(synthetic_18_feature_data):
    """Verify zero-duration flows are retained cleanly without dropping rows or distorting duration."""
    df_train, df_val, df_test = synthetic_18_feature_data
    for df in (df_train, df_val, df_test):
        df.loc[0, "duration_ms"] = 0.0
        df.loc[0, "bytes_per_sec_in"] = np.inf
        df.loc[1, "duration_ms"] = 0.5
        df.loc[1, "bytes_per_sec_in"] = -np.inf

    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256=TEST_DATASET_SHA,
        split_manifest_sha256=TEST_SPLIT_SHA,
    )
    prep.fit(df_train)
    med = prep.imputed_values_["bytes_per_sec_in"]
    out_val = prep.transform(df_val, partition_name="val")

    assert len(out_val) == len(df_val)
    assert list(out_val.columns) == list(ML_FEATURE_COLUMNS)
    assert out_val.loc[0, "duration_ms"] == 0.0
    assert out_val.loc[1, "duration_ms"] == 0.5
    assert out_val.loc[0, "bytes_per_sec_in"] == med
    assert verify_zero_duration_retention(df_val, out_val)["zero_duration_retained"] is True


def test_real_v2_preprocessor_artifact_verified():
    """Verify the real fitted v2 preprocessor artifact if present in working tree."""
    art_path = REPOSITORY_ROOT / "artifacts" / "preprocessing" / "v2_flow_preprocessor.joblib"
    man_path = (
        REPOSITORY_ROOT
        / "reports"
        / "preprocessing"
        / "v2_flow_preprocessing_manifest.json"
    )
    if not art_path.is_file() or not man_path.is_file():
        pytest.skip("v2 preprocessor artifact absent in checkout")

    res = verify_preprocessing_artifact(art_path, manifest_path=man_path)
    assert res["status"] == "PASS"
    assert res["metadata"]["feature_contract_version"] == FEATURE_CONTRACT_VERSION
    loaded = TrainOnlyPreprocessor.load_verified(art_path, manifest_path=man_path)
    assert loaded.config.scaler_type == "asinh_robust"
    assert loaded.train_row_count_ == 1930219
    assert ARTIFACT_TYPE == "v2-flow-train-only-preprocessor"
    assert PREPROCESSING_POLICY_VERSION == "v2-flow-preprocessing-v1"
    assert SPLIT_PROTOCOL_VERSION == "v2-scenario-group-purged-v1"
