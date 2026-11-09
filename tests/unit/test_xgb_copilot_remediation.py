"""Unit and regression tests for XGBoost verified loading and provenance remediation (PR #40).

Verifies resolutions for F01 and F02 findings:
- Finding F01: Strict XGBoostModel.load_verified() enforcing companion manifest, required hashes,
  format validation, nested provenance consistency, environment.git_commit, fitted state,
  estimator type, feature contract (47 features, order, leakage exclusion), label order [0, 1].
- Finding F02: Full protocol serialization round-trip across save, load, and load_verified.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
)
from network_anomaly.data.split import _sha256_file
from network_anomaly.models.xgboost_model import (
    XGBoostBaselineConfig,
    XGBoostModel,
    build_model,
)
from network_anomaly.models.xgboost_protocol import (
    FEATURE_CONTRACT_VERSION,
    PROTOCOL_IDENTIFIER,
    create_xgb_baseline_protocol,
)


@pytest.fixture
def dummy_47_df() -> pd.DataFrame:
    """Return a DataFrame with 20 rows and exact 47 ML features."""
    rng = np.random.RandomState(42)
    data = rng.randn(20, len(ML_FEATURE_COLUMNS))
    return pd.DataFrame(data, columns=list(ML_FEATURE_COLUMNS))


@pytest.fixture
def saved_verified_xgb_model(tmp_path: Path, dummy_47_df: pd.DataFrame):
    """Fixture returning (model_path, manifest_path, valid_manifest_dict)."""
    model = XGBoostModel()
    y = np.array([0] * 10 + [1] * 10)
    model.fit(dummy_47_df, y)

    model_path = tmp_path / "model.joblib"
    actual_sha = model.save(model_path)

    ds_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    sm_sha = "845d8863deeae84d2f7ce29758366d8e8146d0484faadc3b2721cdcc2fc92b2f"
    prep_sha = "e1e89bde7c6504cc26bc48a5ef41fc151f762dc61fe8f053252fb32035fb25e6"

    base_manifest: Dict[str, Any] = {
        "model_type": "XGBoost",
        "task": "binary_classification",
        "target": "Label",
        "positive_class": "Attack",
        "model_artifact_sha256": actual_sha,
        "dataset_sha256": ds_sha,
        "split_manifest_sha256": sm_sha,
        "preprocessor_artifact_sha256": prep_sha,
        "environment": {
            "git_commit": "7d760e0ca3b43e1ed48108978922bf8638168dde",
            "python_version": "3.12.0",
        },
        "provenance_complete": True,
        "provenance_status": "VERIFIED",
        "is_canonical_baseline": True,
        "configuration_id": "xgb-baseline-canonical-v1",
        "protocol_version": PROTOCOL_IDENTIFIER,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "selected_features": list(ML_FEATURE_COLUMNS),
        "hyperparameters": {
            "n_estimators": 200,
            "max_depth": 6,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "objective": "binary:logistic",
            "eval_metric": "logloss",
            "tree_method": "hist",
            "random_state": 42,
            "n_jobs": -1,
        },
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(base_manifest), encoding="utf-8")

    return model_path, manifest_path, base_manifest


# ==============================================================================
# F01 Tests: Strict load_verified() and Provenance Integrity
# ==============================================================================


def test_f01_load_verified_success(saved_verified_xgb_model):
    """F01: Valid manifest and model load successfully with load_verified()."""
    model_path, manifest_path, _ = saved_verified_xgb_model
    model = XGBoostModel.load_verified(model_path, manifest_path)
    assert model.is_fitted is True
    assert model.model_type == "XGBoost"
    assert len(model.feature_names) == 47


def test_f01_load_verified_rejects_missing_manifest():
    """F01: load_verified() rejects None or missing manifest_path fail-closed."""
    with pytest.raises(ValueError, match="Companion manifest path is required"):
        XGBoostModel.load_verified("some_model.joblib", None)


def test_f01_load_verified_rejects_nonexistent_manifest(tmp_path, saved_verified_xgb_model):
    """F01: load_verified() raises FileNotFoundError when manifest does not exist."""
    model_path, _, _ = saved_verified_xgb_model
    with pytest.raises(FileNotFoundError, match="Model manifest not found"):
        XGBoostModel.load_verified(model_path, tmp_path / "nonexistent_manifest.json")


def test_f01_load_verified_rejects_malformed_json_manifest(tmp_path, saved_verified_xgb_model):
    """F01: load_verified() rejects malformed JSON manifest fail-closed."""
    model_path, _, _ = saved_verified_xgb_model
    bad_manifest = tmp_path / "bad.json"
    bad_manifest.write_text("{not-valid-json", encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed model manifest JSON"):
        XGBoostModel.load_verified(model_path, bad_manifest)


def test_f01_load_verified_rejects_non_dict_manifest(tmp_path, saved_verified_xgb_model):
    """F01: load_verified() rejects non-dict JSON manifest fail-closed."""
    model_path, _, _ = saved_verified_xgb_model
    bad_manifest = tmp_path / "bad_array.json"
    bad_manifest.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="Model manifest must be a JSON object"):
        XGBoostModel.load_verified(model_path, bad_manifest)


@pytest.mark.parametrize(
    "missing_hash_field",
    [
        "model_artifact_sha256",
        "dataset_sha256",
        "split_manifest_sha256",
        "preprocessor_artifact_sha256",
    ],
)
def test_f01_load_verified_rejects_missing_provenance_hashes(
    saved_verified_xgb_model, missing_hash_field
):
    """F01: load_verified() rejects manifest missing mandatory provenance hashes."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    del tampered[missing_hash_field]
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match=f"Missing required field '{missing_hash_field}'"):
        XGBoostModel.load_verified(model_path, manifest_path)


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "",
        "abc",
        "not_64_characters_long",
        "g" * 64,  # 'g' is not hex
        123456,
        None,
    ],
)
def test_f01_load_verified_rejects_invalid_hex_hashes(saved_verified_xgb_model, invalid_hash):
    """F01: load_verified() rejects malformed or non-hex SHA-256 strings."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    tampered["dataset_sha256"] = invalid_hash
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid or malformed 64-character hexadecimal SHA-256"):
        XGBoostModel.load_verified(model_path, manifest_path)


def test_f01_load_verified_rejects_model_artifact_hash_mismatch(saved_verified_xgb_model):
    """F01: load_verified() rejects tampered model artifact bytes."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    tampered["model_artifact_sha256"] = "1" * 64
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="Integrity check failed"):
        XGBoostModel.load_verified(model_path, manifest_path)


def test_f01_load_verified_rejects_expected_dataset_sha_mismatch(saved_verified_xgb_model):
    """F01: load_verified() rejects mismatch between caller expected dataset hash and manifest."""
    model_path, manifest_path, _ = saved_verified_xgb_model
    with pytest.raises(ValueError, match="Dataset SHA-256 mismatch in manifest"):
        XGBoostModel.load_verified(model_path, manifest_path, expected_dataset_sha256="1" * 64)


def test_f01_load_verified_rejects_expected_split_manifest_sha_mismatch(
    saved_verified_xgb_model,
):
    """F01: load_verified() rejects mismatch between expected split manifest hash and manifest."""
    model_path, manifest_path, _ = saved_verified_xgb_model
    with pytest.raises(ValueError, match="Split manifest SHA-256 mismatch in manifest"):
        XGBoostModel.load_verified(
            model_path, manifest_path, expected_split_manifest_sha256="1" * 64
        )


def test_f01_load_verified_rejects_expected_preprocessor_sha_mismatch(
    saved_verified_xgb_model,
):
    """F01: load_verified() rejects mismatch between expected preprocessor hash and manifest."""
    model_path, manifest_path, _ = saved_verified_xgb_model
    with pytest.raises(ValueError, match="Preprocessor artifact SHA-256 mismatch in manifest"):
        XGBoostModel.load_verified(
            model_path, manifest_path, expected_preprocessor_artifact_sha256="1" * 64
        )


def test_f01_load_verified_rejects_nested_split_provenance_conflict(saved_verified_xgb_model):
    """F01: load_verified() rejects conflicting top-level and nested split_provenance hashes."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    tampered["split_provenance"] = {"split_manifest_sha256": "1" * 64}
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="Conflicting split_manifest_sha256 in manifest"):
        XGBoostModel.load_verified(model_path, manifest_path)


def test_f01_load_verified_rejects_nested_preprocessor_provenance_conflict(
    saved_verified_xgb_model,
):
    """F01: load_verified() rejects conflicting top-level and nested preprocessor hashes."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    tampered["preprocessing_provenance"] = {"preprocessor_artifact_sha256": "1" * 64}
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="Conflicting preprocessor_artifact_sha256 in manifest"):
        XGBoostModel.load_verified(model_path, manifest_path)


@pytest.mark.parametrize(
    "bad_prov_field,bad_prov_value,match_pattern",
    [
        ("provenance_complete", False, "incomplete provenance"),
        ("provenance_status", "INCOMPLETE", "incomplete provenance"),
        ("provenance_status", "FAIL", "incomplete provenance"),
        ("provenance_status", "PARTIAL", "VERIFIED"),
    ],
)
def test_f01_load_verified_rejects_incomplete_provenance(
    saved_verified_xgb_model, bad_prov_field, bad_prov_value, match_pattern
):
    """F01: load_verified() rejects manifests with incomplete provenance status."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    tampered[bad_prov_field] = bad_prov_value
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match=match_pattern):
        XGBoostModel.load_verified(model_path, manifest_path)


@pytest.mark.parametrize(
    "bad_env_update,match_pattern",
    [
        ({"environment": None}, "Missing or invalid required 'environment' object"),
        ({"environment": "not_a_dict"}, "Missing or invalid required 'environment' object"),
        ({"environment": {}}, "Missing required 'environment.git_commit'"),
        ({"environment": {"git_commit": ""}}, "Invalid or unknown environment.git_commit"),
        ({"environment": {"git_commit": "   "}}, "Invalid or unknown environment.git_commit"),
        ({"environment": {"git_commit": "UNKNOWN"}}, "Invalid or unknown environment.git_commit"),
        ({"environment": {"git_commit": "short"}}, "Invalid format for environment.git_commit"),
        (
            {"environment": {"git_commit": "not_hex_chars_at_all!"}},
            "Invalid format for environment.git_commit",
        ),
    ],
)
def test_f01_load_verified_rejects_missing_or_invalid_git_commit(
    saved_verified_xgb_model, bad_env_update, match_pattern
):
    """F01: load_verified() rejects missing, UNKNOWN, or invalid git_commit."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    tampered.update(bad_env_update)
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match=match_pattern):
        XGBoostModel.load_verified(model_path, manifest_path)


def test_f01_load_verified_rejects_wrong_estimator_type(tmp_path, saved_verified_xgb_model):
    """F01: load_verified() rejects artifact whose estimator is not XGBClassifier."""
    from sklearn.ensemble import RandomForestClassifier

    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    payload = joblib.load(model_path)

    # Replace estimator with RandomForestClassifier
    rf = RandomForestClassifier(n_estimators=10)
    rf.fit(np.zeros((10, 47)), np.array([0] * 5 + [1] * 5))
    payload["estimator"] = rf
    bad_model_path = tmp_path / "bad_estimator.joblib"
    joblib.dump(payload, bad_model_path)
    new_sha = _sha256_file(bad_model_path)

    tampered = dict(base_manifest)
    tampered["model_artifact_sha256"] = new_sha
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="must be XGBClassifier"):
        XGBoostModel.load_verified(bad_model_path, manifest_path)


def test_f01_load_verified_rejects_unfitted_model(tmp_path, saved_verified_xgb_model):
    """F01: load_verified() rejects unfitted model payload."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    payload = joblib.load(model_path)
    payload["is_fitted"] = False

    unfitted_path = tmp_path / "unfitted.joblib"
    joblib.dump(payload, unfitted_path)
    unfitted_sha = _sha256_file(unfitted_path)

    tampered = dict(base_manifest)
    tampered["model_artifact_sha256"] = unfitted_sha
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="is not fitted"):
        XGBoostModel.load_verified(unfitted_path, manifest_path)


@pytest.mark.parametrize(
    "tampered_hp_key,tampered_hp_val",
    [
        ("n_estimators", 100),
        ("max_depth", 4),
        ("learning_rate", 0.05),
        ("subsample", 0.5),
        ("random_state", 999),
    ],
)
def test_f01_load_verified_rejects_tampered_hyperparameters(
    saved_verified_xgb_model, tampered_hp_key, tampered_hp_val
):
    """F01: load_verified() detects tampered hyperparameters in manifest."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    tampered_hp = dict(tampered["hyperparameters"])
    tampered_hp[tampered_hp_key] = tampered_hp_val
    tampered["hyperparameters"] = tampered_hp
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match=f"Hyperparameter '{tampered_hp_key}' mismatch"):
        XGBoostModel.load_verified(model_path, manifest_path)


def test_f01_load_verified_rejects_mismatched_feature_ordering(saved_verified_xgb_model):
    """F01: load_verified() rejects manifest with reversed feature ordering."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    tampered = dict(base_manifest)
    tampered["selected_features"] = list(reversed(ML_FEATURE_COLUMNS))
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="Selected features mismatch"):
        XGBoostModel.load_verified(model_path, manifest_path)


def test_f01_load_verified_rejects_target_columns_in_features(tmp_path, dummy_47_df):
    """F01: load_verified() rejects model payload containing target column 'Label' or 'Attack'."""
    cols_with_target = list(ML_FEATURE_COLUMNS[:-1]) + ["Label"]
    payload = {
        "model_type": "XGBoost",
        "task": "binary_classification",
        "target": "Label",
        "positive_class": "Attack",
        "is_fitted": True,
        "config": XGBoostBaselineConfig().to_dict(),
        "protocol": create_xgb_baseline_protocol().to_dict(),
        "classes": [0, 1],
        "configuration_id": "xgb-baseline-canonical-v1",
        "is_canonical_baseline": True,
        "estimator": build_model(),
        "feature_names": cols_with_target,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "metadata": {},
    }
    # Fit the estimator so booster exists
    payload["estimator"].fit(dummy_47_df.values, np.array([0] * 10 + [1] * 10))

    bad_model = tmp_path / "bad_target.joblib"
    joblib.dump(payload, bad_model)
    sha = _sha256_file(bad_model)

    manifest = {
        "model_type": "XGBoost",
        "task": "binary_classification",
        "target": "Label",
        "positive_class": "Attack",
        "model_artifact_sha256": sha,
        "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        "split_manifest_sha256": (
            "845d8863deeae84d2f7ce29758366d8e8146d0484faadc3b2721cdcc2fc92b2f"
        ),
        "preprocessor_artifact_sha256": (
            "e1e89bde7c6504cc26bc48a5ef41fc151f762dc61fe8f053252fb32035fb25e6"
        ),
        "provenance_complete": True,
        "provenance_status": "VERIFIED",
        "environment": {"git_commit": "7d760e0ca3b43e1ed48108978922bf8638168dde"},
        "selected_features": cols_with_target,
    }
    manifest_path = tmp_path / "bad_target_manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Feature contract violation|Target column 'Label' found"):
        XGBoostModel.load_verified(bad_model, manifest_path)


def test_f01_load_verified_rejects_missing_protocol_in_model_payload(
    tmp_path, saved_verified_xgb_model
):
    """F01: load_verified() rejects legacy model payload missing protocol provenance."""
    model_path, manifest_path, base_manifest = saved_verified_xgb_model
    payload = joblib.load(model_path)
    payload["protocol"] = None

    no_proto_path = tmp_path / "no_proto.joblib"
    joblib.dump(payload, no_proto_path)
    no_proto_sha = _sha256_file(no_proto_path)

    tampered = dict(base_manifest)
    tampered["model_artifact_sha256"] = no_proto_sha
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="lacks required protocol provenance"):
        XGBoostModel.load_verified(no_proto_path, manifest_path)
