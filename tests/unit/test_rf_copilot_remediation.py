"""Unit and regression tests for Copilot review remediation (PR #43).

Verifies resolutions for:
- Finding 1: Test indices isolation during training-stage verification.
- Finding 2: compute_metrics() label normalization and inference with string labels.
- Finding 3: compute_metrics() Macro-F1 across both canonical classes on single-class subsets.
- Finding 4: RandomForestModel.fit() strict feature contract and target leakage locking.
- Finding 5: RandomForestModel.load_verified() fail-closed environment.git_commit validation.
- Finding 6: RandomForestModel.load_verified() cross-object consistency.
- Finding 7: RandomForestModel constructor and build_model() fail-closed validation.
"""

from __future__ import annotations

import json

import joblib
import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
)
from network_anomaly.data.split import _sha256_file
from network_anomaly.evaluation.metrics import (
    compute_metrics,
)
from network_anomaly.models.random_forest import (
    RandomForestBaselineConfig,
    RandomForestModel,
    build_model,
    create_rf_baseline_protocol,
)
from network_anomaly.models.random_forest_protocol import (
    CANONICAL_BASELINE_PARAMS,
    FEATURE_CONTRACT_VERSION,
    PROTOCOL_IDENTIFIER,
)
from scripts.train_random_forest import check_prerequisites

# ==============================================================================
# Finding 1: Test Indices Isolation During Verification
# ==============================================================================


def test_finding1_verification_call_graph_never_loads_test_indices(tmp_path, monkeypatch):
    """Prove that training-stage check_prerequisites never deserializes test_indices.csv.gz."""
    import scripts.train_random_forest as trf
    from network_anomaly.data import split as split_module

    # Spy on load_partition_indices
    loaded_partitions = []

    def _tracking_load_indices(manifest, indices_dir, partition_name):
        loaded_partitions.append(partition_name)
        if partition_name == "test":
            raise RuntimeError("VIOLATION: load_partition_indices called with 'test' partition!")
        if partition_name == "train":
            return np.arange(10, dtype=np.int64)
        if partition_name == "validation":
            return np.arange(10, 20, dtype=np.int64)
        return np.arange(10, dtype=np.int64)

    monkeypatch.setattr(trf, "load_partition_indices", _tracking_load_indices)
    monkeypatch.setattr(split_module, "load_partition_indices", _tracking_load_indices)

    # Set up mock split files
    dummy_ds = tmp_path / "dummy.csv"
    dummy_ds.write_bytes(b"dummy_dataset_bytes")
    ds_hash = _sha256_file(dummy_ds)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    train_idx_file = indices_dir / "train_indices.csv.gz"
    train_idx_file.write_bytes(b"train_idx_bytes")
    train_idx_hash = _sha256_file(train_idx_file)

    val_idx_file = indices_dir / "validation_indices.csv.gz"
    val_idx_file.write_bytes(b"val_idx_bytes")
    val_idx_hash = _sha256_file(val_idx_file)

    test_idx_file = indices_dir / "test_indices.csv.gz"
    test_idx_file.write_bytes(b"test_idx_bytes")
    test_idx_hash = _sha256_file(test_idx_file)

    sm_data = {
        "dataset_name": "NF-UNSW-NB15-v3",
        "dataset_sha256": ds_hash,
        "split_protocol_version": "nf-unsw-nb15-v3-chronological-group-purged-v1",
        "partitions": {
            "train": {"row_count": 10, "index_sha256": train_idx_hash},
            "validation": {"row_count": 10, "index_sha256": val_idx_hash},
            "test": {"row_count": 10, "index_sha256": test_idx_hash},
        },
    }
    sm_path = tmp_path / "sm.json"
    sm_path.write_text(json.dumps(sm_data), encoding="utf-8")
    sm_hash = _sha256_file(sm_path)

    prep_art = tmp_path / "prep.joblib"
    prep_art.write_bytes(b"prep_bytes")
    prep_hash = _sha256_file(prep_art)

    pm_data = {
        "artifact_type": "nf-unsw-nb15-v3-train-only-preprocessor",
        "artifact_version": 1,
        "dataset_name": "NF-UNSW-NB15-v3",
        "dataset_sha256": ds_hash,
        "split_protocol_version": "nf-unsw-nb15-v3-chronological-group-purged-v1",
        "split_manifest_sha256": sm_hash,
        "feature_contract_version": "nf-unsw-nb15-v3-baseline-47",
        "preprocessing_policy_version": "nf-unsw-nb15-v3-train-only-v1",
        "baseline_ml_features_count": 47,
        "baseline_ml_features_in_order": list(ML_FEATURE_COLUMNS),
        "train_row_count": 10,
        "artifact_sha256": prep_hash,
    }
    pm_path = tmp_path / "pm.json"
    pm_path.write_text(json.dumps(pm_data), encoding="utf-8")

    monkeypatch.setattr(trf, "EXPECTED_DATASET_SHA256", ds_hash)
    monkeypatch.setattr(trf, "EXPECTED_SPLIT_MANIFEST_SHA256", sm_hash)
    monkeypatch.setattr(trf, "EXPECTED_PREPROCESSOR_ARTIFACT_SHA256", prep_hash)
    monkeypatch.setattr(trf, "EXPECTED_PREPROCESSOR_MANIFEST_SHA256", _sha256_file(pm_path))

    # Mock verify_preprocessing_artifact to return PASS
    monkeypatch.setattr(
        trf,
        "verify_preprocessing_artifact",
        lambda **kwargs: {"status": "PASS", "errors": []},
    )

    audit = check_prerequisites(
        dataset_path=dummy_ds,
        split_manifest_path=sm_path,
        indices_dir=indices_dir,
        preprocessor_artifact_path=prep_art,
        preprocessor_manifest_path=pm_path,
    )

    assert audit["status"] == "PASS"
    assert "test" not in loaded_partitions
    assert "train" in loaded_partitions
    assert "validation" in loaded_partitions


# ==============================================================================
# Finding 2: compute_metrics() String Labels & Normalization
# ==============================================================================


def test_finding2_mandatory_regression_case():
    """Finding 2: y_true/pred with string labels and labels=None returns correct FPR and CM."""
    y_true = ["Benign", "Benign", "Attack"]
    y_pred = ["Benign", "Attack", "Attack"]

    metrics = compute_metrics(y_true, y_pred)

    assert metrics["false_positive_rate"] == 0.5
    assert metrics["fpr"] == 0.5
    assert metrics["confusion_matrix"] == [[1, 1], [0, 1]]
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == pytest.approx(2 / 3)
    assert metrics["macro_f1"] == pytest.approx(2 / 3)


def test_finding2_numeric_and_string_equivalence():
    """Finding 2: Numeric [0, 1] and string ['Benign', 'Attack'] produce identical metrics."""
    y_num_true = [0, 0, 1, 1, 0, 1]
    y_num_pred = [0, 1, 1, 0, 0, 1]

    y_str_true = ["Benign", "Benign", "Attack", "Attack", "Benign", "Attack"]
    y_str_pred = ["Benign", "Attack", "Attack", "Benign", "Benign", "Attack"]

    m_num = compute_metrics(y_num_true, y_num_pred)
    m_str = compute_metrics(y_str_true, y_str_pred)

    assert m_num["precision"] == m_str["precision"]
    assert m_num["recall"] == m_str["recall"]
    assert m_num["f1"] == m_str["f1"]
    assert m_num["macro_f1"] == m_str["macro_f1"]
    assert m_num["fpr"] == m_str["fpr"]
    assert m_num["confusion_matrix"] == m_str["confusion_matrix"]


def test_finding2_label_order_invariance():
    """Finding 2: Inverting explicit labels order does not change semantic FPR or positive F1."""
    y_true = ["Benign", "Benign", "Attack"]
    y_pred = ["Benign", "Attack", "Attack"]

    m_canonical = compute_metrics(y_true, y_pred, labels=["Benign", "Attack"])
    m_inverted = compute_metrics(y_true, y_pred, labels=["Attack", "Benign"])

    assert m_canonical["fpr"] == 0.5
    assert m_inverted["fpr"] == 0.5
    assert m_canonical["precision"] == m_inverted["precision"]
    assert m_canonical["recall"] == m_inverted["recall"]
    assert m_canonical["f1"] == m_inverted["f1"]
    assert m_canonical["macro_f1"] == m_inverted["macro_f1"]


def test_finding2_unsupported_or_mixed_labels_rejection():
    """Finding 2: Unsupported or mixed labels without explicit labels raise ValueError."""
    # Mixed numeric and string
    with pytest.raises(ValueError, match="Cannot infer canonical label order"):
        compute_metrics([0, "Attack"], [0, "Attack"])

    # Arbitrary strings
    with pytest.raises(ValueError, match="Cannot infer canonical label order"):
        compute_metrics(["Exploits", "DoS"], ["Exploits", "DoS"])


# ==============================================================================
# Finding 3: Macro-F1 Across Both Canonical Classes (Single-Class Subsets)
# ==============================================================================


def test_finding3_macro_f1_all_benign_correct():
    """Finding 3: All-Benign subset correctly predicted yields Macro-F1 = 0.5."""
    y_true = [0, 0, 0]
    y_pred = [0, 0, 0]

    metrics = compute_metrics(y_true, y_pred)

    assert metrics["macro_f1"] == 0.5
    assert metrics["f1"] == 0.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["confusion_matrix"] == [[3, 0], [0, 0]]


def test_finding3_macro_f1_all_attack_correct():
    """Finding 3: All-Attack subset correctly predicted yields Macro-F1 = 0.5."""
    y_true = [1, 1, 1]
    y_pred = [1, 1, 1]

    metrics = compute_metrics(y_true, y_pred)

    assert metrics["macro_f1"] == 0.5
    assert metrics["f1"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["confusion_matrix"] == [[0, 0], [0, 3]]


def test_finding3_macro_f1_string_single_class():
    """Finding 3: Single-class string subsets also compute Macro-F1 across both classes."""
    metrics_benign = compute_metrics(["Benign", "Benign"], ["Benign", "Benign"])
    assert metrics_benign["macro_f1"] == 0.5

    metrics_attack = compute_metrics(["Attack", "Attack"], ["Attack", "Attack"])
    assert metrics_attack["macro_f1"] == 0.5


# ==============================================================================
# Finding 4: Feature Schema Enforcement in RandomForestModel.fit()
# ==============================================================================


@pytest.fixture
def dummy_47_df():
    """Valid 47-feature DataFrame with exact NetFlow v3 column names."""
    rng = np.random.default_rng(42)
    data = {col: rng.normal(0, 1, size=20) for col in ML_FEATURE_COLUMNS}
    return pd.DataFrame(data)


def test_finding4_fit_rejects_dataframe_with_label_column(dummy_47_df):
    """Finding 4: fit() rejects DataFrame containing target column 'Label'."""
    df = dummy_47_df.copy()
    df["Label"] = [0] * len(df)
    model = RandomForestModel()

    with pytest.raises(ValueError, match="forbidden columns"):
        model.fit(df, [0] * len(df))


def test_finding4_fit_rejects_dataframe_with_attack_column(dummy_47_df):
    """Finding 4: fit() rejects DataFrame containing target column 'Attack'."""
    df = dummy_47_df.copy()
    df["Attack"] = ["Benign"] * len(df)
    model = RandomForestModel()

    with pytest.raises(ValueError, match="forbidden columns"):
        model.fit(df, [0] * len(df))


def test_finding4_fit_rejects_dataframe_with_metadata_column(dummy_47_df):
    """Finding 4: fit() rejects DataFrame containing trace metadata."""
    df = dummy_47_df.copy()
    df["IPV4_SRC_ADDR"] = ["10.0.0.1"] * len(df)
    model = RandomForestModel()

    with pytest.raises(ValueError, match="forbidden columns"):
        model.fit(df, [0] * len(df))


def test_finding4_fit_rejects_dataframe_with_missing_or_extra_columns(dummy_47_df):
    """Finding 4: fit() rejects DataFrame with fewer or more than 47 features."""
    model = RandomForestModel()

    # Missing 1 column
    df_missing = dummy_47_df.drop(columns=[ML_FEATURE_COLUMNS[-1]])
    with pytest.raises(ValueError, match="ordered v3 ML contract"):
        model.fit(df_missing, [0] * len(df_missing))

    # Extra unknown column
    df_extra = dummy_47_df.copy()
    df_extra["EXTRA_UNKNOWN_COL"] = 1.0
    with pytest.raises(ValueError, match="unknown columns"):
        model.fit(df_extra, [0] * len(df_extra))


def test_finding4_fit_rejects_dataframe_with_reversed_feature_order(dummy_47_df):
    """Finding 4: fit() rejects DataFrame with wrong column order."""
    cols_reversed = list(reversed(ML_FEATURE_COLUMNS))
    df_reversed = dummy_47_df[cols_reversed]
    model = RandomForestModel()

    with pytest.raises(ValueError, match="ordered v3 ML contract"):
        model.fit(df_reversed, [0] * len(df_reversed))


def test_finding4_fit_rejects_dataframe_with_duplicate_columns():
    """Finding 4: fit() rejects DataFrame with duplicate columns."""
    cols = list(ML_FEATURE_COLUMNS)
    cols[1] = cols[0]  # duplicate first column
    df_dup = pd.DataFrame(np.zeros((10, 47)), columns=cols)
    model = RandomForestModel()

    with pytest.raises(ValueError, match="duplicate columns"):
        model.fit(df_dup, [0] * 10)


def test_finding4_fit_rejects_ndarray_with_wrong_dimensions():
    """Finding 4: fit() rejects ndarray with wrong column width or 1D shape."""
    model = RandomForestModel()

    # 1D array
    with pytest.raises(ValueError, match="Expected 2D feature matrix"):
        model.fit(np.zeros(47), [0])

    # Wrong column count
    with pytest.raises(ValueError, match="Expected 47 feature columns"):
        model.fit(np.zeros((10, 46)), [0] * 10)

    with pytest.raises(ValueError, match="Expected 47 feature columns"):
        model.fit(np.zeros((10, 48)), [0] * 10)


def test_finding4_fit_accepts_valid_dataframe_and_ndarray(dummy_47_df):
    """Finding 4: fit() accepts valid 47-feature DataFrame and ndarray."""
    # Fast shallow model for test speed
    model1 = RandomForestModel(
        config=RandomForestBaselineConfig(
            n_estimators=2,
            max_depth=2,
            is_canonical_baseline=False,
            configuration_id="rf-test-fast",
        )
    )
    y = [0] * 10 + [1] * 10
    model1.fit(dummy_47_df, y)
    assert model1.is_fitted is True
    assert model1.estimator.n_features_in_ == 47

    model2 = RandomForestModel(
        config=RandomForestBaselineConfig(
            n_estimators=2,
            max_depth=2,
            is_canonical_baseline=False,
            configuration_id="rf-test-fast",
        )
    )
    model2.fit(dummy_47_df.to_numpy(), y)
    assert model2.is_fitted is True
    assert model2.estimator.n_features_in_ == 47


# ==============================================================================
# Finding 5: Environment & Git Provenance Validation in load_verified()
# ==============================================================================


@pytest.fixture
def saved_verified_model(tmp_path, dummy_47_df):
    """Fixture returning (model_path, manifest_path, valid_manifest_dict)."""
    model = RandomForestModel()
    model.fit(dummy_47_df.to_numpy(), [0] * 10 + [1] * 10)

    model_path = tmp_path / "model.joblib"
    actual_sha = model.save(model_path)

    ds_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    sm_sha = "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88"
    prep_sha = "12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19"

    base_manifest = {
        "model_artifact_sha256": actual_sha,
        "dataset_sha256": ds_sha,
        "split_manifest_sha256": sm_sha,
        "preprocessor_artifact_sha256": prep_sha,
        "environment": {
            "git_commit": "73c6f32a0cc7b94bbe938edda0a331db97e55a6b",
            "python_version": "3.11.0",
        },
        "provenance_complete": True,
        "provenance_status": "VERIFIED",
        "is_canonical_baseline": True,
        "configuration_id": "rf-baseline-canonical-v1",
        "protocol_version": PROTOCOL_IDENTIFIER,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "selected_features": list(ML_FEATURE_COLUMNS),
        "hyperparameters": CANONICAL_BASELINE_PARAMS,
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(base_manifest), encoding="utf-8")

    return model_path, manifest_path, base_manifest


@pytest.mark.parametrize(
    "bad_env_update,match_msg",
    [
        ({"environment": None}, "Missing or invalid required 'environment' object"),
        ({"environment": "not_a_dict"}, "Missing or invalid required 'environment' object"),
        ({"environment": {}}, "Missing required 'environment.git_commit'"),
        ({"environment": {"git_commit": ""}}, "Invalid or unknown environment.git_commit"),
        ({"environment": {"git_commit": "   "}}, "Invalid or unknown environment.git_commit"),
        ({"environment": {"git_commit": "UNKNOWN"}}, "Invalid or unknown environment.git_commit"),
        ({"environment": {"git_commit": "unknown"}}, "Invalid or unknown environment.git_commit"),
        ({"environment": {"git_commit": "short"}}, "Invalid format for environment.git_commit"),
        (
            {"environment": {"git_commit": "not_a_hex_hash_at_all_!"}},
            "Invalid format for environment.git_commit",
        ),
    ],
)
def test_finding5_load_verified_rejects_missing_or_invalid_environment_git_commit(
    saved_verified_model, bad_env_update, match_msg
):
    """Finding 5: load_verified() fails closed when git_commit is missing or invalid."""
    model_path, manifest_path, base_manifest = saved_verified_model
    bad_manifest = dict(base_manifest)
    bad_manifest.update(bad_env_update)
    manifest_path.write_text(json.dumps(bad_manifest), encoding="utf-8")

    with pytest.raises(ValueError, match=match_msg):
        RandomForestModel.load_verified(model_path, manifest_path)


# ==============================================================================
# Finding 6: Cross-Object Consistency Between Model Payload & Manifest
# ==============================================================================


def test_finding6_load_verified_rejects_experimental_model_with_canonical_manifest(
    tmp_path, dummy_47_df, saved_verified_model
):
    """Finding 6: load_verified() rejects experimental payload with canonical manifest."""
    _, manifest_path, base_manifest = saved_verified_model

    # Build an experimental model with experimental protocol (e.g. 50 trees)
    exp_proto = create_rf_baseline_protocol(
        n_estimators=50,
        is_canonical_baseline=False,
    )
    exp_model = RandomForestModel(protocol=exp_proto)
    exp_model.fit(dummy_47_df.to_numpy(), [0] * 10 + [1] * 10)
    exp_model_path = tmp_path / "exp_model.joblib"
    actual_exp_sha = exp_model.save(exp_model_path)

    # Manifest claims canonical baseline but points to experimental model SHA
    tampered_manifest = dict(base_manifest)
    tampered_manifest["model_artifact_sha256"] = actual_exp_sha
    tampered_manifest["is_canonical_baseline"] = True
    manifest_path.write_text(json.dumps(tampered_manifest), encoding="utf-8")

    expected_regex = (
        "Protocol version mismatch|"
        "Canonical baseline flag mismatch|"
        "Manifest claims is_canonical_baseline=True"
    )
    with pytest.raises(
        ValueError,
        match=expected_regex,
    ):
        RandomForestModel.load_verified(exp_model_path, manifest_path)


def test_finding6_load_verified_rejects_mismatched_hyperparameters(saved_verified_model):
    """Finding 6: load_verified() rejects manifest with conflicting hyperparameters."""
    model_path, manifest_path, base_manifest = saved_verified_model

    tampered_manifest = dict(base_manifest)
    tampered_hp = dict(CANONICAL_BASELINE_PARAMS)
    tampered_hp["n_estimators"] = 100  # Model payload actually has 200
    tampered_manifest["hyperparameters"] = tampered_hp
    manifest_path.write_text(json.dumps(tampered_manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Hyperparameter 'n_estimators' mismatch"):
        RandomForestModel.load_verified(model_path, manifest_path)


def test_finding6_load_verified_rejects_mismatched_protocol_version(saved_verified_model):
    """Finding 6: load_verified() rejects manifest with tampered protocol_version."""
    model_path, manifest_path, base_manifest = saved_verified_model

    tampered_manifest = dict(base_manifest)
    tampered_manifest["protocol_version"] = "tampered-protocol-v999"
    manifest_path.write_text(json.dumps(tampered_manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Protocol version mismatch"):
        RandomForestModel.load_verified(model_path, manifest_path)


def test_finding6_load_verified_rejects_unfitted_model(tmp_path, saved_verified_model):
    """Finding 6: load_verified() rejects model artifact if is_fitted is False."""
    model_path, manifest_path, base_manifest = saved_verified_model

    # Tamper saved model payload so that is_fitted=False
    payload = joblib.load(model_path)
    payload["is_fitted"] = False
    unfitted_path = tmp_path / "tampered_unfitted.joblib"
    joblib.dump(payload, unfitted_path)
    unfitted_sha = _sha256_file(unfitted_path)

    tampered_manifest = dict(base_manifest)
    tampered_manifest["model_artifact_sha256"] = unfitted_sha
    manifest_path.write_text(json.dumps(tampered_manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="is not fitted"):
        RandomForestModel.load_verified(unfitted_path, manifest_path)


# ==============================================================================
# Finding 7: Constructor and build_model() Fail-Closed Validation
# ==============================================================================


def test_finding7_constructor_rejects_invalid_config_instances():
    """Finding 7: RandomForestModel rejects invalid RandomForestBaselineConfig upon init."""
    # n_estimators <= 0
    with pytest.raises(ValueError, match="n_estimators must be positive"):
        RandomForestModel(config=RandomForestBaselineConfig(n_estimators=0))

    # n_jobs invalid (e.g. 0)
    with pytest.raises(ValueError, match="n_jobs must be -1, >= 1, or None"):
        RandomForestModel(config=RandomForestBaselineConfig(n_jobs=0))


def test_finding7_build_model_rejects_invalid_configs_and_protocols():
    """Finding 7: build_model() validates config or protocol before returning estimator."""
    with pytest.raises(ValueError, match="n_estimators must be positive"):
        build_model(RandomForestBaselineConfig(n_estimators=0))

    with pytest.raises(ValueError, match="n_jobs must be -1, >= 1, or None"):
        build_model(RandomForestBaselineConfig(n_jobs=0))
