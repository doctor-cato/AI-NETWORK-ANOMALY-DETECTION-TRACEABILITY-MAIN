#!/usr/bin/env python3
"""Unit tests — train_autoencoder pipeline components (Issue #29 / C4).

All tests use synthetic fixtures only. Real-data training on NF-UNSW-NB15-v3
is NOT conducted here.

Covered:
- Prerequisite check functions (fail-closed behavior, checksum verification).
- Feature schema and leakage guards (47 canonical features, no target or trace metadata).
- Training on benign-only samples.
- Validation-only threshold calibration and unknown-attack holdout isolation.
- Metric computations (confusion matrix, precision, recall, F1, macro-F1, FPR, TNR).
- Per-category breakdown (benign, known attacks, unknown attacks).
- Artifact serialization, manifest generation, and verified loading.
- Tamper detection (hash mismatch fails closed).
- End-to-end synthetic integration pipeline execution.
- Regression tests for PR #51 reviewer findings:
  * P0: Partition indices header and loading.
  * P1: TrainOnlyPreprocessor.load_verified fail-closed gating.
  * P1: Actual leakage audit invocation across Train, Val, and Test.
  * P2: Non-empty index_sha256 requirement in split manifest.
  * P2: Strict target_fpr boundary validation [0.0, 1.0].
  * P2: Streamlined usecols loading and canonical feature reordering.
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path
from typing import Any
from unittest import mock

import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ALL_COLUMNS,
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.data.split import SPLIT_PROTOCOL_VERSION
from network_anomaly.models.autoencoder import (
    build_model,
    fit_model,
)
from network_anomaly.preprocessing.pipeline import (
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)
from scripts.train_autoencoder import (
    calibrate_threshold,
    check_dataset,
    check_feature_schema,
    check_finite_values,
    check_no_leakage_in_matrix,
    check_preprocessor_artifact,
    check_split_manifest,
    compute_metrics,
    load_and_transform_partitions,
    load_and_transform_test_partition,
    load_partition_indices,
    load_verified_autoencoder,
    read_partition_indices_file,
    run_pipeline,
    save_artifacts,
    sha256_file,
    verify_saved_model,
    verify_test_evaluation_lock,
)

EXPECTED_N_FEATURES = len(ML_FEATURE_COLUMNS)  # 47


class IdentityPreprocessor:
    """Mock preprocessor for synthetic testing."""

    def transform(self, X):
        return np.asarray(X, dtype=np.float64)


@pytest.fixture
def rng():
    return np.random.default_rng(42)


@pytest.fixture
def synthetic_benign(rng):
    """200 benign samples across 47 features."""
    return rng.normal(loc=0.0, scale=0.5, size=(200, EXPECTED_N_FEATURES)).astype(np.float64)


@pytest.fixture
def synthetic_attack(rng):
    """50 extreme attack samples across 47 features."""
    return rng.normal(loc=10.0, scale=0.5, size=(50, EXPECTED_N_FEATURES)).astype(np.float64)


@pytest.fixture
def fitted_autoencoder(synthetic_benign):
    """Autoencoder fitted only on benign data."""
    model = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=20, random_state=42)
    fit_model(model, synthetic_benign)
    return model


# --- Schema and Leakage Guards -------------------------------------------------


def test_check_feature_schema_passes_canonical():
    res = check_feature_schema(ML_FEATURE_COLUMNS)
    assert res["status"] == "PASS"
    assert res["count"] == 47


def test_check_feature_schema_fails_wrong_count():
    res = check_feature_schema(list(ML_FEATURE_COLUMNS)[:40])
    assert res["status"] == "FAIL"


def test_check_feature_schema_fails_wrong_order():
    reordered = list(ML_FEATURE_COLUMNS)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    res = check_feature_schema(reordered)
    assert res["status"] == "FAIL"


def test_check_no_leakage_passes_clean():
    df = pd.DataFrame(np.zeros((5, len(ML_FEATURE_COLUMNS))), columns=list(ML_FEATURE_COLUMNS))
    res = check_no_leakage_in_matrix(df)
    assert res["status"] == "PASS"


def test_check_no_leakage_detects_target():
    df = pd.DataFrame(np.zeros((5, 2)), columns=["Label", "IN_BYTES"])
    res = check_no_leakage_in_matrix(df)
    assert res["status"] == "FAIL"
    assert "targets=['Label']" in res["message"]


def test_check_no_leakage_detects_trace_metadata():
    df = pd.DataFrame(np.zeros((5, 2)), columns=["IPV4_SRC_ADDR", "IN_BYTES"])
    res = check_no_leakage_in_matrix(df)
    assert res["status"] == "FAIL"
    assert "IPV4_SRC_ADDR" in res["message"]


def test_check_finite_values_passes_clean():
    arr = np.array([[1.0, 2.0], [3.0, 4.0]])
    res = check_finite_values(arr, "TestPartition")
    assert res["status"] == "PASS"


def test_check_finite_values_fails_nan():
    arr = np.array([[1.0, np.nan], [3.0, 4.0]])
    res = check_finite_values(arr, "TestPartition")
    assert res["status"] == "FAIL"
    assert "NaN=1" in res["message"]


def test_check_finite_values_fails_inf():
    arr = np.array([[1.0, np.inf], [3.0, 4.0]])
    res = check_finite_values(arr, "TestPartition")
    assert res["status"] == "FAIL"
    assert "Inf=1" in res["message"]


# --- Prerequisite Checks -------------------------------------------------------


def test_check_dataset_missing_manifest(tmp_path):
    res = check_dataset(manifest_path=tmp_path / "missing.json")
    assert res["status"] == "BLOCKED"


def test_check_dataset_missing_raw_csv(tmp_path):
    man = tmp_path / "manifest.json"
    man.write_text(json.dumps({"files": [{"file": "data/NF-UNSW-NB15-v3.csv", "sha256": "dummy"}]}))
    res = check_dataset(manifest_path=man, raw_path=tmp_path / "nonexistent.csv")
    assert res["status"] == "BLOCKED"


def test_check_split_manifest_missing(tmp_path):
    res = check_split_manifest(manifest_path=tmp_path / "missing_split.json")
    assert res["status"] == "BLOCKED"


def test_check_split_manifest_missing_partition(tmp_path):
    train_idx_p = tmp_path / "train_indices.csv.gz"
    with gzip.open(train_idx_p, "wt") as fh:
        fh.write("source_row_index\n0\n")
    man = tmp_path / "split.json"
    man.write_text(
        json.dumps(
            {
                "partitions": {
                    "train": {
                        "index_sha256": sha256_file(train_idx_p),
                        "row_count": 1,
                    }
                }
            }
        )
    )
    res = check_split_manifest(manifest_path=man, indices_dir=tmp_path)
    assert res["status"] == "BLOCKED"
    assert "missing required partition" in res["message"]


def test_check_preprocessor_missing(tmp_path):
    res = check_preprocessor_artifact(
        artifact_path=tmp_path / "missing.joblib",
        manifest_path=tmp_path / "missing.json",
    )
    assert res["status"] == "BLOCKED"


# --- Threshold Calibration -----------------------------------------------------


def test_calibrate_threshold_benign_quantile():
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    y = np.zeros(10, dtype=int)
    attack = np.array(["Benign"] * 10)

    res = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        method="benign_quantile",
        target_fpr=0.20,
    )
    assert res["threshold_frozen"] is True
    # At 80th percentile:
    assert 0.7 <= res["threshold"] <= 0.9
    assert res["empirical_val_fpr"] <= 0.30


def test_calibrate_threshold_fpr_constrained():
    scores = np.linspace(0.1, 1.0, 100)
    y = np.zeros(100, dtype=int)
    attack = np.array(["Benign"] * 100)

    res = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=0.05,
    )
    assert res["threshold_frozen"] is True
    assert res["empirical_val_fpr"] <= 0.05


def test_calibrate_threshold_supervised_best_f1():
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.8, 0.85, 0.9, 0.95])
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    attack = np.array(
        ["Benign", "Benign", "Benign", "Benign", "DoS", "DoS", "Exploits", "Exploits"]
    )

    res = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        method="supervised_best_f1",
    )
    assert res["threshold_frozen"] is True
    assert 0.4 <= res["threshold"] <= 0.85


def test_calibrate_threshold_excludes_unknown_attacks():
    """Unknown categories (Worms, Backdoor) must NOT participate in calibration."""
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.8, 0.9, 0.95, 0.99])
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    attack = np.array(
        ["Benign", "Benign", "Benign", "Benign", "DoS", "Exploits", "Worms", "Backdoor"]
    )

    res = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        unknown_categories=frozenset({"Worms", "Backdoor"}),
    )
    assert res["n_unknown_excluded"] == 2
    assert "Worms" in res["unknown_categories_excluded"]
    assert "Backdoor" in res["unknown_categories_excluded"]


def test_calibrate_threshold_rejects_empty():
    with pytest.raises(ValueError, match="validation scores are empty"):
        calibrate_threshold(np.array([]), np.array([]), np.array([]))


# --- Metrics Computation -------------------------------------------------------


def test_compute_metrics_basic():
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    y_pred = np.array([0, 0, 0, 1, 1, 1, 1, 0])
    scores = np.array([0.1, 0.2, 0.3, 0.6, 0.8, 0.9, 0.7, 0.4])
    attack = np.array(["Benign", "Benign", "Benign", "Benign", "DoS", "DoS", "Worms", "Exploits"])

    res = compute_metrics(
        y_true=y_true,
        y_pred=y_pred,
        scores=scores,
        attack_col=attack,
        unknown_categories=frozenset({"Worms"}),
    )

    assert res["total_samples"] == 8
    assert res["tp"] == 3
    assert res["fp"] == 1
    assert res["tn"] == 3
    assert res["fn"] == 1
    assert res["precision"] == 3 / 4
    assert res["recall_detection_rate"] == 3 / 4
    assert res["fpr"] == 1 / 4
    assert res["fnr"] == 1 / 4
    assert res["tnr"] == 3 / 4
    assert res["roc_auc"] is not None
    assert 0.0 <= res["roc_auc"] <= 1.0
    assert res["pr_auc"] is not None
    assert 0.0 <= res["pr_auc"] <= 1.0

    # Check category breakdown
    assert "per_category" in res
    assert "Worms" in res["per_category"]
    assert res["per_category"]["Worms"]["type"] == "unknown_attack"
    assert res["per_category"]["Worms"]["detected"] == 1

    assert "DoS" in res["per_category"]
    assert res["per_category"]["DoS"]["type"] == "known_attack"
    assert res["per_category"]["DoS"]["detected"] == 2

    assert "Benign" in res["per_category"]
    assert res["per_category"]["Benign"]["false_positives"] == 1


# --- Artifact Serialization and Verified Loading -------------------------------


def test_save_and_verify_model(tmp_path, fitted_autoencoder, synthetic_benign):
    out_dir = tmp_path / "model_out"
    config_dict = {
        "hidden_layer_sizes": (16, 8, 16),
        "activation": "relu",
        "solver": "adam",
        "random_state": 42,
    }
    th_meta = {"threshold": 0.5, "calibration_method": "benign_quantile"}
    tr_meta = {
        "training_population": "benign-only",
        "n_train_samples": 200,
        "n_val_samples": 50,
        "dataset_sha256": "fake_sha",
        "git_commit": "abcdef",
    }

    art_res = save_artifacts(
        model=fitted_autoencoder,
        config=config_dict,
        threshold_meta=th_meta,
        training_meta=tr_meta,
        output_dir=out_dir,
    )

    model_path = Path(art_res["files"]["model"])
    manifest_path = Path(art_res["files"]["manifest"])

    assert model_path.exists()
    assert manifest_path.exists()

    # Verify reload check
    check_res = verify_saved_model(model_path, fitted_autoencoder, synthetic_benign[:20])
    assert check_res["status"] == "PASS"

    # Verify load_verified_autoencoder
    loaded_model, manifest = load_verified_autoencoder(model_path, manifest_path)
    assert loaded_model is not None
    assert manifest["model_file"] == model_path.name
    assert manifest["model_sha256"] == sha256_file(model_path)


def test_load_verified_autoencoder_fails_closed_tampered(tmp_path, fitted_autoencoder):
    out_dir = tmp_path / "tamper_out"
    art_res = save_artifacts(
        model=fitted_autoencoder,
        config={"hidden_layer_sizes": (16, 8, 16)},
        threshold_meta={"threshold": 0.5},
        training_meta={},
        output_dir=out_dir,
    )
    model_path = Path(art_res["files"]["model"])
    manifest_path = Path(art_res["files"]["manifest"])

    # Tamper with model file
    with model_path.open("ab") as fh:
        fh.write(b"corrupted_bytes")

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_verified_autoencoder(model_path, manifest_path)


# --- Regression Tests for Reviewer Findings (PR #51) ---------------------------


# P0: Partition indices loading with canonical header
def test_read_partition_indices_file_with_canonical_header(tmp_path):
    idx_p = tmp_path / "train_indices.csv"
    idx_p.write_text("source_row_index\n10\n20\n30\n", encoding="utf-8")
    indices = read_partition_indices_file(idx_p)
    np.testing.assert_array_equal(indices, np.array([10, 20, 30], dtype=np.int64))


def test_read_partition_indices_file_gzipped(tmp_path):
    idx_p = tmp_path / "val_indices.csv.gz"
    with gzip.open(idx_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n1\n2\n5\n")
    indices = read_partition_indices_file(idx_p)
    np.testing.assert_array_equal(indices, np.array([1, 2, 5], dtype=np.int64))


def test_read_partition_indices_file_excludes_header_from_data(tmp_path):
    idx_p = tmp_path / "indices.csv"
    idx_p.write_text("source_row_index\n100\n", encoding="utf-8")
    indices = read_partition_indices_file(idx_p)
    assert len(indices) == 1
    assert indices[0] == 100
    assert indices.dtype == np.int64


def test_read_partition_indices_file_rejects_missing_header(tmp_path):
    idx_p = tmp_path / "raw_indices.csv"
    idx_p.write_text("10\n20\n30\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing canonical header 'source_row_index'"):
        read_partition_indices_file(idx_p)


def test_read_partition_indices_file_rejects_non_integer_data(tmp_path):
    idx_p = tmp_path / "bad_indices.csv"
    idx_p.write_text("source_row_index\n10\nnot_an_int\n30\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid non-integer data"):
        read_partition_indices_file(idx_p)


def test_read_partition_indices_file_preserves_order(tmp_path):
    idx_p = tmp_path / "ordered_indices.csv"
    idx_p.write_text("source_row_index\n50\n10\n30\n", encoding="utf-8")
    indices = read_partition_indices_file(idx_p)
    np.testing.assert_array_equal(indices, np.array([50, 10, 30], dtype=np.int64))


def test_load_partition_indices_delegates_to_canonical_split(tmp_path):
    idx_p = tmp_path / "train_indices.csv.gz"
    with gzip.open(idx_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n0\n1\n2\n3\n")
    split_man = {"partitions": {"train": {"index_file": "train_indices.csv.gz"}}}
    indices = load_partition_indices(split_man, tmp_path, "train", max_rows=2)
    np.testing.assert_array_equal(indices, np.array([0, 1], dtype=np.int64))


# P1: TrainOnlyPreprocessor.load_verified fail-closed gating
def test_load_verified_preprocessor_fails_closed_when_load_verified_raises(tmp_path):
    with mock.patch(
        "network_anomaly.preprocessing.pipeline.TrainOnlyPreprocessor.load_verified",
        side_effect=ValueError("Tampered preprocessor artifact"),
    ):
        mock_args = argparse.Namespace(
            raw_data=tmp_path / "raw.csv",
            data_manifest=tmp_path / "data_man.json",
            split_manifest=tmp_path / "split_man.json",
            indices_dir=tmp_path / "splits",
            preprocessor_artifact=tmp_path / "preprocessor.joblib",
            preprocessor_manifest=tmp_path / "preprocessor_manifest.json",
            output_dir=tmp_path / "output",
            report_dir=tmp_path / "reports",
            skip_checksums=False,
        )
        with (
            mock.patch(
                "scripts.train_autoencoder.check_dataset",
                return_value={"status": "PASS", "path": str(mock_args.raw_data)},
            ),
            mock.patch(
                "scripts.train_autoencoder.check_split_manifest",
                return_value={
                    "status": "PASS",
                    "path": str(mock_args.split_manifest),
                    "manifest": {},
                },
            ),
            mock.patch(
                "scripts.train_autoencoder.check_preprocessor_artifact",
                return_value={
                    "status": "PASS",
                    "path": str(mock_args.preprocessor_artifact),
                },
            ),
        ):
            exit_code = run_pipeline(mock_args)
            assert exit_code == 1


# P1: Actual leakage audit invocation across Train, Val, and Test
def test_pipeline_leakage_check_detects_target_in_train():
    df_leak = pd.DataFrame(
        np.zeros((3, len(ML_FEATURE_COLUMNS) + 1)),
        columns=list(ML_FEATURE_COLUMNS) + ["Label"],
    )
    res = check_no_leakage_in_matrix(df_leak)
    assert res["status"] == "FAIL"
    assert "targets=['Label']" in res["message"]


def test_pipeline_leakage_check_detects_trace_metadata_in_train():
    df_leak = pd.DataFrame(
        np.zeros((3, len(ML_FEATURE_COLUMNS) + 1)),
        columns=list(ML_FEATURE_COLUMNS) + ["IPV4_SRC_ADDR"],
    )
    res = check_no_leakage_in_matrix(df_leak)
    assert res["status"] == "FAIL"
    assert "IPV4_SRC_ADDR" in res["message"]


def test_pipeline_leakage_check_detects_leakage_in_validation():
    df_leak = pd.DataFrame(
        np.zeros((3, len(ML_FEATURE_COLUMNS) + 1)),
        columns=list(ML_FEATURE_COLUMNS) + ["Attack"],
    )
    res = check_no_leakage_in_matrix(df_leak)
    assert res["status"] == "FAIL"
    assert "targets=['Attack']" in res["message"]


def test_pipeline_leakage_check_passes_clean_partitions():
    clean_df = pd.DataFrame(
        np.zeros((5, len(ML_FEATURE_COLUMNS))),
        columns=list(ML_FEATURE_COLUMNS),
    )
    res = check_no_leakage_in_matrix(clean_df)
    assert res["status"] == "PASS"


# P2: check_split_manifest verifies non-empty index_sha256
def test_check_split_manifest_blocked_when_index_sha256_missing(tmp_path):
    idx_p = tmp_path / "train_indices.csv.gz"
    with gzip.open(idx_p, "wt") as fh:
        fh.write("source_row_index\n1\n")
    man = tmp_path / "split.json"
    man.write_text(json.dumps({"partitions": {"train": {"row_count": 1}}}))
    res = check_split_manifest(manifest_path=man, indices_dir=tmp_path)
    assert res["status"] == "BLOCKED"
    assert "missing required non-empty 'index_sha256'" in res["message"]


def test_check_split_manifest_blocked_when_index_sha256_empty(tmp_path):
    idx_p = tmp_path / "train_indices.csv.gz"
    with gzip.open(idx_p, "wt") as fh:
        fh.write("source_row_index\n1\n")
    man = tmp_path / "split.json"
    man.write_text(json.dumps({"partitions": {"train": {"row_count": 1, "index_sha256": ""}}}))
    res = check_split_manifest(manifest_path=man, indices_dir=tmp_path)
    assert res["status"] == "BLOCKED"
    assert "missing required non-empty 'index_sha256'" in res["message"]


def test_check_split_manifest_blocked_when_index_sha256_mismatch(tmp_path):
    idx_p = tmp_path / "train_indices.csv.gz"
    with gzip.open(idx_p, "wt") as fh:
        fh.write("source_row_index\n1\n")
    val_idx_p = tmp_path / "validation_indices.csv.gz"
    with gzip.open(val_idx_p, "wt") as fh:
        fh.write("source_row_index\n2\n")
    test_idx_p = tmp_path / "test_indices.csv.gz"
    with gzip.open(test_idx_p, "wt") as fh:
        fh.write("source_row_index\n3\n")

    man = tmp_path / "split.json"
    man.write_text(
        json.dumps(
            {
                "partitions": {
                    "train": {"row_count": 1, "index_sha256": "wrong_hash"},
                    "validation": {
                        "row_count": 1,
                        "index_sha256": sha256_file(val_idx_p),
                    },
                    "test": {
                        "row_count": 1,
                        "index_sha256": sha256_file(test_idx_p),
                    },
                }
            }
        )
    )
    res = check_split_manifest(manifest_path=man, indices_dir=tmp_path)
    assert res["status"] == "BLOCKED"
    assert "Partition index SHA-256 mismatch for train" in res["message"]


def test_check_split_manifest_pass_when_checksum_matches(tmp_path):
    partitions_meta = {}
    for part in ("train", "validation", "test"):
        idx_p = tmp_path / f"{part}_indices.csv.gz"
        with gzip.open(idx_p, "wt") as fh:
            fh.write("source_row_index\n10\n")
        partitions_meta[part] = {
            "row_count": 1,
            "index_sha256": sha256_file(idx_p),
        }
    man = tmp_path / "split.json"
    man.write_text(json.dumps({"partitions": partitions_meta}))
    res = check_split_manifest(manifest_path=man, indices_dir=tmp_path)
    assert res["status"] == "PASS"


def test_check_split_manifest_blocked_when_partition_metadata_not_dict(tmp_path):
    man = tmp_path / "split.json"
    man.write_text(json.dumps({"partitions": {"train": "not_a_dict"}}))
    res = check_split_manifest(manifest_path=man, indices_dir=tmp_path)
    assert res["status"] == "BLOCKED"
    assert "must be a dict" in res["message"]


# P2: Strict target_fpr boundary validation [0.0, 1.0]
def test_calibrate_threshold_rejects_target_fpr_negative():
    scores = np.array([0.1, 0.2, 0.3])
    y = np.zeros(3, dtype=int)
    attack = np.array(["Benign"] * 3)
    with pytest.raises(ValueError, match=r"target_fpr must be in \[0\.0, 1\.0\]"):
        calibrate_threshold(scores, y, attack, target_fpr=-0.05)


def test_calibrate_threshold_rejects_target_fpr_greater_than_one():
    scores = np.array([0.1, 0.2, 0.3])
    y = np.zeros(3, dtype=int)
    attack = np.array(["Benign"] * 3)
    with pytest.raises(ValueError, match=r"target_fpr must be in \[0\.0, 1\.0\]"):
        calibrate_threshold(scores, y, attack, target_fpr=1.05)


def test_calibrate_threshold_rejects_target_fpr_nan():
    scores = np.array([0.1, 0.2, 0.3])
    y = np.zeros(3, dtype=int)
    attack = np.array(["Benign"] * 3)
    with pytest.raises(ValueError, match="target_fpr must be finite"):
        calibrate_threshold(scores, y, attack, target_fpr=float("nan"))


def test_calibrate_threshold_rejects_target_fpr_inf():
    scores = np.array([0.1, 0.2, 0.3])
    y = np.zeros(3, dtype=int)
    attack = np.array(["Benign"] * 3)
    with pytest.raises(ValueError, match="target_fpr must be finite"):
        calibrate_threshold(scores, y, attack, target_fpr=float("inf"))


def test_calibrate_threshold_rejects_target_fpr_non_numeric():
    scores = np.array([0.1, 0.2, 0.3])
    y = np.zeros(3, dtype=int)
    attack = np.array(["Benign"] * 3)
    with pytest.raises(TypeError, match="target_fpr must be a real number"):
        calibrate_threshold(scores, y, attack, target_fpr="zero_point_one")  # type: ignore


def test_calibrate_threshold_boundary_zero():
    scores = np.array([0.1, 0.2, 0.3, 0.4])
    y = np.zeros(4, dtype=int)
    attack = np.array(["Benign"] * 4)
    res = calibrate_threshold(scores, y, attack, target_fpr=0.0)
    assert res["threshold_frozen"] is True
    assert res["target_fpr"] == 0.0


def test_calibrate_threshold_boundary_one():
    scores = np.array([0.1, 0.2, 0.3, 0.4])
    y = np.zeros(4, dtype=int)
    attack = np.array(["Benign"] * 4)
    res = calibrate_threshold(scores, y, attack, target_fpr=1.0)
    assert res["threshold_frozen"] is True
    assert res["target_fpr"] == 1.0


# P2: usecols reading and canonical column reordering
def test_load_and_transform_partitions_reads_only_ml_features_and_targets(tmp_path, rng):
    n_rows = 20
    df_data = {}
    for col in ALL_COLUMNS:
        if col in ML_FEATURE_COLUMNS:
            df_data[col] = rng.normal(0, 1, n_rows)
        elif col in TRACE_METADATA_COLUMNS:
            df_data[col] = 99999
        elif col in TARGET_COLUMNS:
            df_data[col] = 0 if col == "Label" else "Benign"
        else:
            df_data[col] = 0
    df = pd.DataFrame(df_data)
    csv_path = tmp_path / "data.csv"
    df.to_csv(csv_path, index=False)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    for part, idxs in (("train", [0, 1]), ("validation", [2, 3]), ("test", [4, 5])):
        idx_p = indices_dir / f"{part}_indices.csv.gz"
        with gzip.open(idx_p, "wt") as fh:
            fh.write("source_row_index\n" + "\n".join(str(i) for i in idxs) + "\n")

    split_man = {
        "partitions": {
            part: {"index_file": f"{part}_indices.csv.gz"}
            for part in ("train", "validation", "test")
        }
    }
    parts = load_and_transform_partitions(
        raw_data_path=csv_path,
        indices_dir=indices_dir,
        split_manifest=split_man,
        preprocessor=IdentityPreprocessor(),
        include_test=True,
    )
    assert "train" in parts
    assert "validation" in parts
    assert "test" in parts
    assert parts["train"]["X_raw_df"].shape[1] == len(ML_FEATURE_COLUMNS)
    assert tuple(parts["train"]["X_raw_df"].columns) == ML_FEATURE_COLUMNS


def test_load_and_transform_partitions_reorders_columns_to_canonical(tmp_path, rng):
    n_rows = 10
    # Reverse ML features order in file
    reversed_features = list(reversed(ML_FEATURE_COLUMNS))
    df_data = {col: rng.normal(0, 1, n_rows) for col in reversed_features}
    df_data["Label"] = [0] * n_rows
    df_data["Attack"] = ["Benign"] * n_rows

    csv_path = tmp_path / "data_reversed.csv"
    pd.DataFrame(df_data).to_csv(csv_path, index=False)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    for part, idxs in (("train", [0, 1]), ("validation", [2, 3])):
        idx_p = indices_dir / f"{part}_indices.csv.gz"
        with gzip.open(idx_p, "wt") as fh:
            fh.write("source_row_index\n" + "\n".join(str(i) for i in idxs) + "\n")

    split_man = {
        "partitions": {
            part: {"index_file": f"{part}_indices.csv.gz"} for part in ("train", "validation")
        }
    }
    parts = load_and_transform_partitions(
        raw_data_path=csv_path,
        indices_dir=indices_dir,
        split_manifest=split_man,
        preprocessor=IdentityPreprocessor(),
        include_test=False,
    )
    assert tuple(parts["train"]["X_raw_df"].columns) == ML_FEATURE_COLUMNS


def test_load_and_transform_partitions_fails_closed_missing_feature(tmp_path, rng):
    n_rows = 5
    # Missing one ML feature
    features = list(ML_FEATURE_COLUMNS)[:-1]
    df_data = {col: rng.normal(0, 1, n_rows) for col in features}
    df_data["Label"] = [0] * n_rows
    df_data["Attack"] = ["Benign"] * n_rows

    csv_path = tmp_path / "data_missing_col.csv"
    pd.DataFrame(df_data).to_csv(csv_path, index=False)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    for part, idxs in (("train", [0]), ("validation", [1])):
        idx_p = indices_dir / f"{part}_indices.csv.gz"
        with gzip.open(idx_p, "wt") as fh:
            fh.write("source_row_index\n" + "\n".join(str(i) for i in idxs) + "\n")

    split_man = {
        "partitions": {
            part: {"index_file": f"{part}_indices.csv.gz"} for part in ("train", "validation")
        }
    }
    with pytest.raises(ValueError, match="Raw dataset CSV missing required columns"):
        load_and_transform_partitions(
            raw_data_path=csv_path,
            indices_dir=indices_dir,
            split_manifest=split_man,
            preprocessor=IdentityPreprocessor(),
        )


# --- End-to-End Synthetic Pipeline Integration Test ----------------------------


def test_e2e_synthetic_pipeline_execution(tmp_path, rng):
    """Run full run_pipeline end-to-end on synthetic data."""
    # 1. Create synthetic dataset with 47 features + metadata + targets
    n_rows = 150
    data = {}
    for col in ALL_COLUMNS:
        if col in ML_FEATURE_COLUMNS:
            data[col] = rng.normal(loc=0.0, scale=1.0, size=n_rows)
        elif col in TRACE_METADATA_COLUMNS:
            data[col] = 12345
        elif col == "Label":
            data[col] = [0] * 100 + [1] * 50
        elif col == "Attack":
            data[col] = ["Benign"] * 100 + ["DoS"] * 30 + ["Worms"] * 20
        else:
            data[col] = 0

    csv_path = tmp_path / "synthetic_data.csv"
    pd.DataFrame(data).to_csv(csv_path, index=False)
    csv_sha = sha256_file(csv_path)

    # 2. Dataset manifest
    data_man_path = tmp_path / "dataset_manifest.json"
    data_man_path.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file": "data/NF-UNSW-NB15-v3.csv",
                        "sha256": csv_sha,
                    }
                ]
            }
        )
    )

    # 3. Create partition indices with canonical header
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()

    train_idx = np.arange(0, 80)
    val_idx = np.arange(80, 120)
    test_idx = np.arange(120, 150)

    train_idx_path = indices_dir / "train_indices.csv.gz"
    val_idx_path = indices_dir / "validation_indices.csv.gz"
    test_idx_path = indices_dir / "test_indices.csv.gz"

    for path, idxs in (
        (train_idx_path, train_idx),
        (val_idx_path, val_idx),
        (test_idx_path, test_idx),
    ):
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write("source_row_index\n")
            for idx in idxs:
                fh.write(f"{idx}\n")

    # 4. Split manifest
    split_man_path = tmp_path / "split_manifest.json"
    split_man_path.write_text(
        json.dumps(
            {
                "partitions": {
                    "train": {
                        "index_sha256": sha256_file(train_idx_path),
                        "row_count": len(train_idx),
                    },
                    "validation": {
                        "index_sha256": sha256_file(val_idx_path),
                        "row_count": len(val_idx),
                    },
                    "test": {
                        "index_sha256": sha256_file(test_idx_path),
                        "row_count": len(test_idx),
                    },
                }
            }
        )
    )

    # 5. Preprocessor artifact and companion manifest
    import joblib

    prep_path = tmp_path / "preprocessor.joblib"
    joblib.dump(IdentityPreprocessor(), prep_path)
    prep_sha = sha256_file(prep_path)

    prep_man_path = tmp_path / "preprocessor_manifest.json"
    prep_man_path.write_text(json.dumps({"artifact_sha256": prep_sha}))

    out_dir = tmp_path / "artifacts" / "autoencoder"
    rep_dir = tmp_path / "reports" / "autoencoder"

    # 6. Execute pipeline with Held-out Test evaluation
    args = argparse.Namespace(
        raw_data=csv_path,
        data_manifest=data_man_path,
        split_manifest=split_man_path,
        indices_dir=indices_dir,
        preprocessor_artifact=prep_path,
        preprocessor_manifest=prep_man_path,
        output_dir=out_dir,
        report_dir=rep_dir,
        hidden_layers="16,8,16",
        activation="relu",
        solver="adam",
        alpha=0.0001,
        batch_size=32,
        learning_rate=0.005,
        max_iter=15,
        target_fpr=0.10,
        calibration_method="benign_quantile",
        unknown_categories="Worms",
        evaluate_test=True,
        sample_size=None,
        skip_checksums=False,
    )

    with mock.patch(
        "network_anomaly.preprocessing.pipeline.TrainOnlyPreprocessor.load_verified",
        return_value=IdentityPreprocessor(),
    ):
        exit_code = run_pipeline(args)
        assert exit_code == 0

    # 7. Verify outputs exist and are non-empty
    assert (out_dir / "autoencoder_model.joblib").exists()
    assert (out_dir / "autoencoder_manifest.json").exists()
    assert (rep_dir / "metrics.json").exists()
    assert (rep_dir / "threshold_calibration.json").exists()
    assert (rep_dir / "training_metadata.json").exists()
    assert (rep_dir / "run_metadata.json").exists()
    assert (rep_dir / "evaluation_report.md").exists()

    # Check metrics content
    with (rep_dir / "metrics.json").open("r") as fh:
        metrics = json.load(fh)
        assert "validation" in metrics
        assert "test" in metrics
        assert metrics["test"]["total_samples"] == len(test_idx)
        assert "roc_auc" in metrics["validation"]
        assert "pr_auc" in metrics["validation"]
        assert "fnr" in metrics["validation"]


def test_load_partition_indices_supports_uncompressed_csv(tmp_path):
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    csv_p = indices_dir / "train_indices.csv"
    with csv_p.open("w", encoding="utf-8") as fh:
        fh.write("source_row_index\n5\n15\n25\n")

    split_man = {
        "partitions": {
            "train": {
                "index_file": "train_indices.csv",
                "index_sha256": sha256_file(csv_p),
            }
        }
    }
    indices = load_partition_indices(split_man, indices_dir, "train")
    assert list(indices) == [5, 15, 25]


def test_load_partition_indices_rejects_negative_index(tmp_path):
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    gz_p = indices_dir / "train_indices.csv.gz"
    with gzip.open(gz_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n0\n-5\n10\n")

    split_man = {
        "partitions": {
            "train": {
                "index_file": "train_indices.csv.gz",
                "index_sha256": sha256_file(gz_p),
            }
        }
    }
    with pytest.raises(ValueError, match="negative index"):
        load_partition_indices(split_man, indices_dir, "train")


def test_load_partition_indices_rejects_duplicate_indices(tmp_path):
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    gz_p = indices_dir / "train_indices.csv.gz"
    with gzip.open(gz_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n10\n20\n10\n")

    split_man = {
        "partitions": {
            "train": {
                "index_file": "train_indices.csv.gz",
                "index_sha256": sha256_file(gz_p),
            }
        }
    }
    with pytest.raises(ValueError, match="duplicate index"):
        load_partition_indices(split_man, indices_dir, "train")


def test_load_and_transform_partitions_rejects_overlapping_partitions(tmp_path, rng):
    n_rows = 10
    df_data = {col: rng.normal(0, 1, n_rows) for col in ML_FEATURE_COLUMNS}
    df_data["Label"] = [0] * n_rows
    df_data["Attack"] = ["Benign"] * n_rows
    csv_path = tmp_path / "data.csv"
    pd.DataFrame(df_data).to_csv(csv_path, index=False)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    # Contaminated overlap: row 2 is in both train and validation
    train_idx_p = indices_dir / "train_indices.csv.gz"
    val_idx_p = indices_dir / "validation_indices.csv.gz"
    with gzip.open(train_idx_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n0\n1\n2\n")
    with gzip.open(val_idx_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n2\n3\n4\n")

    split_man = {
        "partitions": {
            "train": {
                "index_file": "train_indices.csv.gz",
                "index_sha256": sha256_file(train_idx_p),
            },
            "validation": {
                "index_file": "validation_indices.csv.gz",
                "index_sha256": sha256_file(val_idx_p),
            },
        }
    }
    with pytest.raises(ValueError, match="Split contamination"):
        load_and_transform_partitions(
            raw_data_path=csv_path,
            indices_dir=indices_dir,
            split_manifest=split_man,
            preprocessor=IdentityPreprocessor(),
        )


def test_load_and_transform_partitions_fails_closed_row_count_mismatch(tmp_path, rng):
    n_rows = 5
    df_data = {col: rng.normal(0, 1, n_rows) for col in ML_FEATURE_COLUMNS}
    df_data["Label"] = [0] * n_rows
    df_data["Attack"] = ["Benign"] * n_rows
    csv_path = tmp_path / "data_truncated.csv"
    pd.DataFrame(df_data).to_csv(csv_path, index=False)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    # Indices require row 10, which does not exist in the 5-row CSV
    train_idx_p = indices_dir / "train_indices.csv.gz"
    val_idx_p = indices_dir / "validation_indices.csv.gz"
    with gzip.open(train_idx_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n0\n10\n")
    with gzip.open(val_idx_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n2\n")

    split_man = {
        "partitions": {
            "train": {
                "index_file": "train_indices.csv.gz",
                "index_sha256": sha256_file(train_idx_p),
            },
            "validation": {
                "index_file": "validation_indices.csv.gz",
                "index_sha256": sha256_file(val_idx_p),
            },
        }
    }
    with pytest.raises(ValueError, match="Row count mismatch in Train"):
        load_and_transform_partitions(
            raw_data_path=csv_path,
            indices_dir=indices_dir,
            split_manifest=split_man,
            preprocessor=IdentityPreprocessor(),
        )


def test_load_and_transform_partitions_aligns_non_monotonic_indices(tmp_path, rng):
    n_rows = 10
    df_data = {col: np.arange(n_rows, dtype=np.float64) for col in ML_FEATURE_COLUMNS}
    df_data["Label"] = [0] * n_rows
    df_data["Attack"] = ["Benign"] * n_rows
    csv_path = tmp_path / "data_ordered.csv"
    pd.DataFrame(df_data).to_csv(csv_path, index=False)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    # Non-monotonic order: row 4, then row 1, then row 3
    train_idx_p = indices_dir / "train_indices.csv.gz"
    val_idx_p = indices_dir / "validation_indices.csv.gz"
    with gzip.open(train_idx_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n4\n1\n3\n")
    with gzip.open(val_idx_p, "wt", encoding="utf-8") as fh:
        fh.write("source_row_index\n0\n2\n")

    split_man = {
        "partitions": {
            "train": {
                "index_file": "train_indices.csv.gz",
                "index_sha256": sha256_file(train_idx_p),
            },
            "validation": {
                "index_file": "validation_indices.csv.gz",
                "index_sha256": sha256_file(val_idx_p),
            },
        }
    }
    parts = load_and_transform_partitions(
        raw_data_path=csv_path,
        indices_dir=indices_dir,
        split_manifest=split_man,
        preprocessor=IdentityPreprocessor(),
    )
    # The first feature values must match the exact row values in indices order: [4.0, 1.0, 3.0]
    col0 = ML_FEATURE_COLUMNS[0]
    np.testing.assert_array_equal(parts["train"]["X_raw_df"][col0].to_numpy(), [4.0, 1.0, 3.0])


# --- F1: Tie-Aware FPR Threshold Calibration Regression Tests ------------------


def test_calibrate_threshold_fpr_constrained_duplicate_scores_hand_calculated():
    # n=10 sorted benign scores with duplicates at 0.5 and 1.0:
    # candidate FPRs under (score >= th):
    #   th=0.1 -> 10/10=1.00, th=0.2 -> 9/10=0.90, th=0.5 -> 8/10=0.80,
    #   th=0.8 -> 4/10=0.40, th=0.9 -> 3/10=0.30, th=1.0 -> 2/10=0.20
    benign_scores = np.array([0.5, 1.0, 0.1, 0.5, 0.8, 0.5, 0.2, 1.0, 0.5, 0.9], dtype=float)
    y = np.zeros(len(benign_scores), dtype=int)
    attack = np.array(["Benign"] * len(benign_scores))

    res_20 = calibrate_threshold(
        val_scores=benign_scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=0.20,
    )
    assert res_20["threshold"] == pytest.approx(1.0)
    assert res_20["empirical_val_fpr"] == pytest.approx(0.20)
    assert float((benign_scores >= res_20["threshold"]).mean()) == pytest.approx(0.20)

    # target_fpr=0.25 must not pick 0.9 (FPR=0.30 > 0.25); it must select 1.0 (FPR=0.20)
    res_25 = calibrate_threshold(
        val_scores=benign_scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=0.25,
    )
    assert res_25["threshold"] == pytest.approx(1.0)
    assert res_25["empirical_val_fpr"] == pytest.approx(0.20)
    assert float((benign_scores >= res_25["threshold"]).mean()) <= 0.25

    # target_fpr=0.35 permits 0.9 (FPR=0.30 <= 0.35)
    res_35 = calibrate_threshold(
        val_scores=benign_scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=0.35,
    )
    assert res_35["threshold"] == pytest.approx(0.9)
    assert res_35["empirical_val_fpr"] == pytest.approx(0.30)


def test_calibrate_threshold_fpr_constrained_ties_at_max_score():
    # n=6: lowest achievable unique-value threshold 0.9 triggers 3/6=0.50 FPR > 0.10
    scores = np.array([0.1, 0.2, 0.3, 0.9, 0.9, 0.9], dtype=float)
    y = np.zeros(6, dtype=int)
    attack = np.array(["Benign"] * 6)

    res = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=0.10,
    )
    assert res["threshold"] > 0.9
    assert res["empirical_val_fpr"] == 0.0
    assert int((scores >= res["threshold"]).sum()) == 0


def test_calibrate_threshold_fpr_constrained_all_equal_scores():
    scores = np.full(20, 0.42, dtype=float)
    y = np.zeros(20, dtype=int)
    attack = np.array(["Benign"] * 20)

    res_low = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=0.05,
    )
    assert res_low["threshold"] > 0.42
    assert res_low["empirical_val_fpr"] == 0.0
    assert int((scores >= res_low["threshold"]).sum()) == 0

    res_one = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=1.0,
    )
    assert res_one["threshold"] == pytest.approx(0.42)
    assert res_one["empirical_val_fpr"] == pytest.approx(1.0)


def test_calibrate_threshold_fpr_constrained_boundary_zero_and_one():
    scores = np.array([0.1, 0.2, 0.2, 0.4, 0.8, 0.8], dtype=float)
    y = np.zeros(6, dtype=int)
    attack = np.array(["Benign"] * 6)

    res_zero = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=0.0,
    )
    assert res_zero["threshold"] > 0.8
    assert res_zero["empirical_val_fpr"] == 0.0
    assert int((scores >= res_zero["threshold"]).sum()) == 0

    res_one = calibrate_threshold(
        val_scores=scores,
        val_y=y,
        val_attack=attack,
        method="fpr_constrained",
        target_fpr=1.0,
    )
    assert res_one["threshold"] == pytest.approx(0.1)
    assert res_one["empirical_val_fpr"] == pytest.approx(1.0)
    assert float((scores >= res_one["threshold"]).mean()) <= 1.0


# --- F2: Provenance & Manifest Fail-Closed Regression Tests --------------------


def test_save_artifacts_persists_custom_unknown_categories_and_partition_hashes(
    tmp_path, fitted_autoencoder
):
    out_dir = tmp_path / "model_custom_prov"
    custom_unknown = ["DoS", "Fuzzers"]
    cfg = {
        "hidden_layer_sizes": (16, 8, 16),
        "activation": "relu",
        "solver": "adam",
        "random_state": 42,
    }
    th_meta = {
        "threshold": 0.25,
        "calibration_method": "fpr_constrained",
        "threshold_frozen": True,
        "unknown_categories_excluded": custom_unknown,
    }
    tr_meta = {
        "training_population": "benign-only",
        "n_train_samples": 120,
        "n_val_samples": 40,
        "dataset_sha256": "a" * 64,
        "split_manifest_sha256": "b" * 64,
        "partition_indices_sha256": {"train": "c" * 64, "validation": "d" * 64},
        "preprocessor_sha256": "e" * 64,
        "preprocessor_manifest_sha256": "f" * 64,
        "preprocessor_source": "TrainOnlyPreprocessor.load_verified",
        "git_commit": "deadbeef",
    }

    art_res = save_artifacts(
        model=fitted_autoencoder,
        config=cfg,
        threshold_meta=th_meta,
        training_meta=tr_meta,
        output_dir=out_dir,
        unknown_categories=custom_unknown,
    )
    manifest_path = Path(art_res["files"]["manifest"])
    model_path = Path(art_res["files"]["model"])

    loaded_model, manifest = load_verified_autoencoder(
        model_path=model_path,
        manifest_path=manifest_path,
        require_complete_provenance=True,
    )
    assert loaded_model is not None
    assert manifest["unknown_attack_categories"] == ["DoS", "Fuzzers"]
    assert manifest["partition_indices_sha256"] == {"train": "c" * 64, "validation": "d" * 64}
    assert manifest["provenance_complete"] is True
    assert manifest["provenance"]["dataset"]["sha256"] == "a" * 64
    assert manifest["provenance"]["split"]["manifest_sha256"] == "b" * 64
    assert manifest["provenance"]["preprocessor"]["artifact_sha256"] == "e" * 64
    assert manifest["provenance"]["calibration"]["unknown_attack_categories"] == ["DoS", "Fuzzers"]


def test_load_verified_autoencoder_rejects_missing_or_tampered_manifest_fields(
    tmp_path, fitted_autoencoder
):
    def _write_bundle(subdir: str):
        d = tmp_path / subdir
        art_res = save_artifacts(
            model=fitted_autoencoder,
            config={"hidden_layer_sizes": (16, 8, 16), "random_state": 42},
            threshold_meta={
                "threshold": 0.5,
                "calibration_method": "fpr_constrained",
                "threshold_frozen": True,
                "unknown_categories_excluded": ["Worms"],
            },
            training_meta={
                "dataset_sha256": "1" * 64,
                "split_manifest_sha256": "2" * 64,
                "partition_indices_sha256": {"train": "3" * 64, "validation": "4" * 64},
                "preprocessor_sha256": "5" * 64,
            },
            output_dir=d,
            unknown_categories=["Worms"],
        )
        return Path(art_res["files"]["model"]), Path(art_res["files"]["manifest"]), d

    # 1. Missing required partition_indices_sha256
    m_p, man_p, _ = _write_bundle("missing_part")
    man = json.loads(man_p.read_text(encoding="utf-8"))
    del man["partition_indices_sha256"]
    man_p.write_text(json.dumps(man), encoding="utf-8")
    with pytest.raises(ValueError, match="partition_indices_sha256"):
        load_verified_autoencoder(m_p, man_p)

    # 2. Tampered threshold.json sidecar
    m_p, man_p, d = _write_bundle("tampered_sidecar")
    (d / "threshold.json").write_text('{"threshold": 0.999}', encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_verified_autoencoder(m_p, man_p)

    # 3. Unknown categories disagreement
    m_p, man_p, _ = _write_bundle("unknown_mismatch")
    man = json.loads(man_p.read_text(encoding="utf-8"))
    man["unknown_attack_categories"] = ["DoS"]
    man_p.write_text(json.dumps(man), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown_attack_categories disagrees"):
        load_verified_autoencoder(m_p, man_p)

    # 4. Inconsistent nested provenance object
    m_p, man_p, _ = _write_bundle("prov_mismatch")
    man = json.loads(man_p.read_text(encoding="utf-8"))
    man["provenance"]["dataset"]["sha256"] = "9" * 64
    man_p.write_text(json.dumps(man), encoding="utf-8")
    with pytest.raises(ValueError, match="disagrees with top-level provenance"):
        load_verified_autoencoder(m_p, man_p)

    # 5. Incomplete provenance fails when require_complete_provenance=True
    d_inc = tmp_path / "incomplete_prov"
    art_inc = save_artifacts(
        model=fitted_autoencoder,
        config={"hidden_layer_sizes": (16, 8, 16)},
        threshold_meta={"threshold": 0.5, "threshold_frozen": True},
        training_meta={"dataset_sha256": "1" * 64},
        output_dir=d_inc,
    )
    with pytest.raises(ValueError, match="missing complete verified provenance hashes"):
        load_verified_autoencoder(
            Path(art_inc["files"]["model"]),
            Path(art_inc["files"]["manifest"]),
            require_complete_provenance=True,
        )


# --- F3: Real TrainOnlyPreprocessor End-to-End Integration Tests -------------


def _build_real_preprocessor_e2e_fixture(tmp_path: Path, rng: np.random.Generator):
    """Build synthetic 53-col CSV, split manifest, and real fitted TrainOnlyPreprocessor."""
    n_rows = 120
    data: dict[str, Any] = {}
    for col in ALL_COLUMNS:
        if col in CATEGORICAL_CODED_COLUMNS:
            data[col] = rng.integers(1, 10, size=n_rows)
        elif col in ML_FEATURE_COLUMNS:
            benign_vals = rng.normal(loc=0.0, scale=1.0, size=80)
            attack_vals = rng.normal(loc=4.0, scale=1.0, size=40)
            data[col] = np.concatenate([benign_vals, attack_vals])
        elif col in TRACE_METADATA_COLUMNS:
            data[col] = 12345
        elif col == "Label":
            data[col] = [0] * 80 + [1] * 40
        elif col == "Attack":
            data[col] = ["Benign"] * 80 + ["Exploits"] * 20 + ["DoS"] * 10 + ["Reconnaissance"] * 10
        else:
            data[col] = 0

    df_full = pd.DataFrame(data)
    csv_path = tmp_path / "real_prep_synthetic.csv"
    df_full.to_csv(csv_path, index=False)
    csv_sha = sha256_file(csv_path)

    data_man_path = tmp_path / "dataset_manifest.json"
    data_man_path.write_text(
        json.dumps({"files": [{"file": "data/NF-UNSW-NB15-v3.csv", "sha256": csv_sha}]}),
        encoding="utf-8",
    )

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    train_idx = np.concatenate([np.arange(0, 50), np.arange(80, 90)])  # 50 benign + 10 known
    val_idx = np.concatenate([np.arange(50, 70), np.arange(90, 110)])  # 20 benign + 20 attacks
    test_idx = np.concatenate([np.arange(70, 80), np.arange(110, 120)])  # 10 benign + 10 attacks

    train_idx_p = indices_dir / "train_indices.csv.gz"
    val_idx_p = indices_dir / "validation_indices.csv.gz"
    test_idx_p = indices_dir / "test_indices.csv.gz"
    for p, idxs in ((train_idx_p, train_idx), (val_idx_p, val_idx), (test_idx_p, test_idx)):
        with gzip.open(p, "wt", encoding="utf-8") as fh:
            fh.write("source_row_index\n")
            for idx in idxs:
                fh.write(f"{int(idx)}\n")

    split_man_path = tmp_path / "split_manifest.json"
    split_man_path.write_text(
        json.dumps(
            {
                "dataset_sha256": csv_sha,
                "split_protocol_version": SPLIT_PROTOCOL_VERSION,
                "partitions": {
                    "train": {
                        "index_file": train_idx_p.name,
                        "index_sha256": sha256_file(train_idx_p),
                        "row_count": len(train_idx),
                    },
                    "validation": {
                        "index_file": val_idx_p.name,
                        "index_sha256": sha256_file(val_idx_p),
                        "row_count": len(val_idx),
                    },
                    "test": {
                        "index_file": test_idx_p.name,
                        "index_sha256": sha256_file(test_idx_p),
                        "row_count": len(test_idx),
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    split_sha = sha256_file(split_man_path)

    prep_path = tmp_path / "nf_unsw_nb15_v3_preprocessor.joblib"
    prep_man_path = tmp_path / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="standard", add_missing_indicators=False),
        dataset_sha256=csv_sha,
        split_manifest_sha256=split_sha,
        split_protocol_version=SPLIT_PROTOCOL_VERSION,
    )
    X_train_only = df_full.iloc[train_idx][list(ML_FEATURE_COLUMNS)]
    prep.fit(X_train_only)
    prep_sha = prep.save(prep_path, manifest_path=prep_man_path)

    return {
        "csv_path": csv_path,
        "csv_sha": csv_sha,
        "data_man_path": data_man_path,
        "split_man_path": split_man_path,
        "split_sha": split_sha,
        "indices_dir": indices_dir,
        "train_idx_sha": sha256_file(train_idx_p),
        "val_idx_sha": sha256_file(val_idx_p),
        "prep_path": prep_path,
        "prep_man_path": prep_man_path,
        "prep_sha": prep_sha,
    }


def _make_real_prep_args(
    fixture: dict[str, Any], out_dir: Path, rep_dir: Path
) -> argparse.Namespace:
    return argparse.Namespace(
        raw_data=fixture["csv_path"],
        data_manifest=fixture["data_man_path"],
        split_manifest=fixture["split_man_path"],
        indices_dir=fixture["indices_dir"],
        preprocessor_artifact=fixture["prep_path"],
        preprocessor_manifest=fixture["prep_man_path"],
        output_dir=out_dir,
        report_dir=rep_dir,
        hidden_layers="16,8,16",
        activation="relu",
        solver="adam",
        alpha=0.0001,
        batch_size=32,
        learning_rate=0.005,
        max_iter=15,
        target_fpr=0.10,
        calibration_method="fpr_constrained",
        unknown_categories="DoS,Reconnaissance",
        evaluate_test=False,
        sample_size=None,
        skip_checksums=False,
    )


def test_e2e_pipeline_with_real_verified_preprocessor(tmp_path, rng):
    """Run full pipeline using unmocked TrainOnlyPreprocessor.load_verified()."""
    fixture = _build_real_preprocessor_e2e_fixture(tmp_path, rng)
    out_dir = tmp_path / "artifacts" / "autoencoder"
    rep_dir = tmp_path / "reports" / "autoencoder"
    args = _make_real_prep_args(fixture, out_dir, rep_dir)

    exit_code = run_pipeline(args)
    assert exit_code == 0

    manifest_path = out_dir / "autoencoder_manifest.json"
    model_path = out_dir / "autoencoder_model.joblib"
    loaded_model, manifest = load_verified_autoencoder(
        model_path=model_path,
        manifest_path=manifest_path,
        require_complete_provenance=True,
    )
    assert loaded_model is not None
    assert manifest["unknown_attack_categories"] == ["DoS", "Reconnaissance"]
    assert manifest["provenance_complete"] is True
    assert manifest["dataset_sha256"] == fixture["csv_sha"]
    assert manifest["split_manifest_sha256"] == fixture["split_sha"]
    assert manifest["preprocessor_sha256"] == fixture["prep_sha"]
    assert manifest["partition_indices_sha256"] == {
        "train": fixture["train_idx_sha"],
        "validation": fixture["val_idx_sha"],
    }
    assert manifest["model_architecture"]["input_dimension"] == 47
    assert manifest["test_lock"]["test_evaluated"] is False
    assert manifest["test_lock"]["test_rows_materialized"] == 0

    metrics = json.loads((rep_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["test"] is None
    assert metrics["threshold_calibration"]["empirical_val_fpr"] <= 0.10


def test_e2e_pipeline_rejects_tampered_real_preprocessor_artifact(tmp_path, rng):
    fixture = _build_real_preprocessor_e2e_fixture(tmp_path, rng)
    with fixture["prep_path"].open("ab") as fh:
        fh.write(b"tampered_bytes")

    args = _make_real_prep_args(
        fixture, tmp_path / "artifacts_tamper_art", tmp_path / "reports_tamper_art"
    )
    assert run_pipeline(args) == 1

    # Even with --skip-checksums, TrainOnlyPreprocessor.load_verified must fail closed
    args.skip_checksums = True
    assert run_pipeline(args) == 1


def test_e2e_pipeline_rejects_tampered_real_preprocessor_manifest(tmp_path, rng):
    fixture = _build_real_preprocessor_e2e_fixture(tmp_path, rng)
    prep_man = json.loads(fixture["prep_man_path"].read_text(encoding="utf-8"))
    prep_man["dataset_sha256"] = "0" * 64
    fixture["prep_man_path"].write_text(json.dumps(prep_man), encoding="utf-8")

    args = _make_real_prep_args(
        fixture, tmp_path / "artifacts_tamper_man", tmp_path / "reports_tamper_man"
    )
    assert run_pipeline(args) == 1


# --- F4: Held-Out Test Lock & Partition Isolation Regression Tests -----------


def test_load_and_transform_partitions_stops_streaming_at_max_idx_and_excludes_test(tmp_path, rng):
    n_rows = 20
    df_data = {col: rng.normal(0, 1, n_rows) for col in ML_FEATURE_COLUMNS}
    df_data["Label"] = [0] * 10 + [1] * 10
    df_data["Attack"] = ["Benign"] * 10 + ["DoS"] * 10

    # Inject extreme poisoned sentinel values into Test rows (interspersed 2,3 and trailing 6..19)
    poisoned_col = ML_FEATURE_COLUMNS[0]
    for test_r in [2, 3, *range(6, n_rows)]:
        df_data[poisoned_col][test_r] = 1e9

    csv_path = tmp_path / "test_lock_stream.csv"
    pd.DataFrame(df_data).to_csv(csv_path, index=False)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    part_rows = {"train": [0, 4], "validation": [1, 5], "test": [2, 3, *range(6, n_rows)]}
    for part, idxs in part_rows.items():
        with gzip.open(indices_dir / f"{part}_indices.csv.gz", "wt", encoding="utf-8") as fh:
            fh.write("source_row_index\n" + "\n".join(str(i) for i in idxs) + "\n")

    split_man = {
        "partitions": {
            part: {"index_file": f"{part}_indices.csv.gz"}
            for part in ("train", "validation", "test")
        }
    }

    transformed_batches: list[np.ndarray] = []

    class SpyPreprocessor:
        def transform(self, X):
            arr = np.asarray(X, dtype=np.float64)
            transformed_batches.append(arr.copy())
            return arr

    real_read_csv = pd.read_csv
    chunks_consumed = 0

    def counting_read_csv(*args, **kwargs):
        reader = real_read_csv(*args, **kwargs)
        if "chunksize" not in kwargs:
            return reader

        class CountingReader:
            def __enter__(self):
                reader.__enter__()
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return reader.__exit__(exc_type, exc_val, exc_tb)

            def __iter__(self):
                nonlocal chunks_consumed
                for chunk in reader:
                    chunks_consumed += 1
                    yield chunk

        return CountingReader()

    with mock.patch("scripts.train_autoencoder.pd.read_csv", side_effect=counting_read_csv):
        parts = load_and_transform_partitions(
            raw_data_path=csv_path,
            indices_dir=indices_dir,
            split_manifest=split_man,
            preprocessor=SpyPreprocessor(),
            include_test=False,
            chunk_size=2,
        )

    assert "test" not in parts
    assert len(parts["train"]["y"]) == 2
    assert len(parts["validation"]["y"]) == 2
    # Max Train/Val index is 5 -> with chunk_size=2, stream stops after 3 chunks (rows 0..5)
    assert chunks_consumed == 3
    for batch in transformed_batches:
        assert not np.any(np.isclose(batch, 1e9))


def test_verify_test_evaluation_lock_enforces_frozen_model_and_threshold(fitted_autoencoder):
    frozen_meta = {"threshold": 0.5, "threshold_frozen": True}

    # Fails if --evaluate-test is False
    with pytest.raises(RuntimeError, match="requires --evaluate-test"):
        verify_test_evaluation_lock(fitted_autoencoder, frozen_meta, evaluate_test=False)

    # Fails if model is not fitted
    unfitted_model = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=5, random_state=42)
    with pytest.raises(RuntimeError, match="must be fitted"):
        verify_test_evaluation_lock(unfitted_model, frozen_meta, evaluate_test=True)

    # Fails if threshold is not frozen
    with pytest.raises(RuntimeError, match="must be calibrated and frozen"):
        verify_test_evaluation_lock(
            fitted_autoencoder,
            {"threshold": 0.5, "threshold_frozen": False},
            evaluate_test=True,
        )

    # Fails if frozen threshold value is invalid (negative or NaN)
    with pytest.raises(RuntimeError, match="invalid frozen threshold"):
        verify_test_evaluation_lock(
            fitted_autoencoder,
            {"threshold": -0.1, "threshold_frozen": True},
            evaluate_test=True,
        )

    # Passes when model is fitted, threshold is frozen & valid, and evaluate_test=True
    verify_test_evaluation_lock(fitted_autoencoder, frozen_meta, evaluate_test=True)


def test_pipeline_strict_isolation_no_test_in_fit_or_calibration(tmp_path):
    """Poisoning held-out Test rows must not alter fitted model weights or threshold."""
    clean_dir = tmp_path / "clean"
    poisoned_dir = tmp_path / "poisoned"
    clean_dir.mkdir()
    poisoned_dir.mkdir()

    def _run_with_test_scale(base_dir: Path, test_offset: float):
        local_rng = np.random.default_rng(7)
        fixture = _build_real_preprocessor_e2e_fixture(base_dir, local_rng)
        if test_offset != 0.0:
            df = pd.read_csv(fixture["csv_path"])
            test_mask = np.isin(
                np.arange(len(df)),
                np.concatenate([np.arange(70, 80), np.arange(110, 120)]),
            )
            df.loc[test_mask, list(ML_FEATURE_COLUMNS)] += test_offset
            df.to_csv(fixture["csv_path"], index=False)
            new_sha = sha256_file(fixture["csv_path"])
            fixture["data_man_path"].write_text(
                json.dumps({"files": [{"file": "data/NF-UNSW-NB15-v3.csv", "sha256": new_sha}]}),
                encoding="utf-8",
            )
            split_obj = json.loads(fixture["split_man_path"].read_text(encoding="utf-8"))
            split_obj["dataset_sha256"] = new_sha
            fixture["split_man_path"].write_text(json.dumps(split_obj), encoding="utf-8")
            # Re-fit TrainOnlyPreprocessor identically on Train rows with updated manifests
            train_idx = np.concatenate([np.arange(0, 50), np.arange(80, 90)])
            prep = TrainOnlyPreprocessor(
                config=PreprocessingConfig(scaler_type="standard", add_missing_indicators=False),
                dataset_sha256=new_sha,
                split_manifest_sha256=sha256_file(fixture["split_man_path"]),
                split_protocol_version=SPLIT_PROTOCOL_VERSION,
            )
            prep.fit(df.iloc[train_idx][list(ML_FEATURE_COLUMNS)])
            prep.save(fixture["prep_path"], manifest_path=fixture["prep_man_path"])

        out_dir = base_dir / "out"
        rep_dir = base_dir / "rep"
        args = _make_real_prep_args(fixture, out_dir, rep_dir)
        assert run_pipeline(args) == 0
        model, man = load_verified_autoencoder(
            out_dir / "autoencoder_model.joblib",
            out_dir / "autoencoder_manifest.json",
            require_complete_provenance=True,
        )
        return model, man

    clean_model, clean_man = _run_with_test_scale(clean_dir, 0.0)
    poison_model, poison_man = _run_with_test_scale(poisoned_dir, 1e6)

    assert clean_man["threshold"] == pytest.approx(poison_man["threshold"], rel=0.0, abs=0.0)
    for w_clean, w_poison in zip(clean_model.coefs_, poison_model.coefs_, strict=True):
        np.testing.assert_array_equal(w_clean, w_poison)


def test_load_and_transform_test_partition_fails_closed_before_fit_or_freeze(
    tmp_path, fitted_autoencoder
):
    dummy_csv = tmp_path / "should_not_be_read.csv"
    dummy_man = {"partitions": {}}
    frozen_meta = {"threshold": 0.5, "threshold_frozen": True}

    with mock.patch("scripts.train_autoencoder.pd.read_csv") as mock_read_csv:
        with pytest.raises(RuntimeError, match="requires --evaluate-test"):
            load_and_transform_test_partition(
                raw_data_path=dummy_csv,
                indices_dir=tmp_path,
                split_manifest=dummy_man,
                preprocessor=IdentityPreprocessor(),
                model=fitted_autoencoder,
                threshold_meta=frozen_meta,
                evaluate_test=False,
            )

        unfitted = build_model(hidden_layer_sizes=(16, 8, 16), max_iter=5, random_state=42)
        with pytest.raises(RuntimeError, match="must be fitted"):
            load_and_transform_test_partition(
                raw_data_path=dummy_csv,
                indices_dir=tmp_path,
                split_manifest=dummy_man,
                preprocessor=IdentityPreprocessor(),
                model=unfitted,
                threshold_meta=frozen_meta,
                evaluate_test=True,
            )

        with pytest.raises(RuntimeError, match="must be calibrated and frozen"):
            load_and_transform_test_partition(
                raw_data_path=dummy_csv,
                indices_dir=tmp_path,
                split_manifest=dummy_man,
                preprocessor=IdentityPreprocessor(),
                model=fitted_autoencoder,
                threshold_meta={"threshold": 0.5, "threshold_frozen": False},
                evaluate_test=True,
            )

        mock_read_csv.assert_not_called()


def test_run_pipeline_evaluates_test_strictly_after_fit_and_threshold_freeze(tmp_path, rng):
    fixture = _build_real_preprocessor_e2e_fixture(tmp_path, rng)
    out_dir = tmp_path / "artifacts_eval_order"
    rep_dir = tmp_path / "reports_eval_order"
    args = _make_real_prep_args(fixture, out_dir, rep_dir)
    args.evaluate_test = True

    events: list[Any] = []
    real_load_parts = load_and_transform_partitions
    real_load_test = load_and_transform_test_partition
    real_fit = fit_model
    real_cal = calibrate_threshold
    real_verify_lock = verify_test_evaluation_lock

    def spy_load_parts(*p_args, **p_kwargs):
        events.append(
            (
                "load_partitions",
                p_kwargs.get("include_test"),
                p_kwargs.get("partitions"),
            )
        )
        return real_load_parts(*p_args, **p_kwargs)

    def spy_fit(*p_args, **p_kwargs):
        events.append("fit_model")
        return real_fit(*p_args, **p_kwargs)

    def spy_cal(*p_args, **p_kwargs):
        events.append("calibrate_threshold")
        return real_cal(*p_args, **p_kwargs)

    def spy_verify_lock(*p_args, **p_kwargs):
        events.append("verify_test_evaluation_lock")
        return real_verify_lock(*p_args, **p_kwargs)

    def spy_load_test(*p_args, **p_kwargs):
        events.append("load_and_transform_test_partition")
        return real_load_test(*p_args, **p_kwargs)

    with (
        mock.patch(
            "scripts.train_autoencoder.load_and_transform_partitions", side_effect=spy_load_parts
        ),
        mock.patch("scripts.train_autoencoder.fit_model", side_effect=spy_fit),
        mock.patch("scripts.train_autoencoder.calibrate_threshold", side_effect=spy_cal),
        mock.patch(
            "scripts.train_autoencoder.verify_test_evaluation_lock", side_effect=spy_verify_lock
        ),
        mock.patch(
            "scripts.train_autoencoder.load_and_transform_test_partition",
            side_effect=spy_load_test,
        ),
    ):
        exit_code = run_pipeline(args)

    assert exit_code == 0
    assert events[0] == ("load_partitions", False, None)
    idx_initial = 0
    idx_fit = events.index("fit_model")
    idx_cal = events.index("calibrate_threshold")
    idx_lock = events.index("verify_test_evaluation_lock")
    idx_test_loader = events.index("load_and_transform_test_partition")
    idx_test_stream = events.index(("load_partitions", True, ("test",)))

    assert idx_initial < idx_fit < idx_cal < idx_lock < idx_test_loader < idx_test_stream

    manifest = json.loads((out_dir / "autoencoder_manifest.json").read_text(encoding="utf-8"))
    assert manifest["test_lock"]["test_evaluated"] is True
    assert manifest["test_lock"]["test_rows_materialized"] == 20
    assert manifest["test_lock"]["test_loaded_after_model_fit_and_threshold_freeze"] is True
    assert manifest["test_lock"]["threshold_frozen_before_test_eval"] is True


def test_run_pipeline_with_evaluate_test_disabled_never_calls_test_loader(tmp_path, rng):
    fixture = _build_real_preprocessor_e2e_fixture(tmp_path, rng)
    out_dir = tmp_path / "artifacts_locked"
    rep_dir = tmp_path / "reports_locked"
    args = _make_real_prep_args(fixture, out_dir, rep_dir)
    args.evaluate_test = False

    requested_partitions: list[str] = []
    real_load_idx = load_partition_indices

    def spy_load_idx(split_manifest, indices_dir, partition_name, max_rows=None):
        requested_partitions.append(partition_name)
        return real_load_idx(split_manifest, indices_dir, partition_name, max_rows=max_rows)

    with (
        mock.patch("scripts.train_autoencoder.load_partition_indices", side_effect=spy_load_idx),
        mock.patch(
            "scripts.train_autoencoder.load_and_transform_test_partition"
        ) as mock_test_loader,
    ):
        assert run_pipeline(args) == 0

    mock_test_loader.assert_not_called()
    assert "test" not in requested_partitions


def test_run_pipeline_evaluate_test_invariance_with_poisoned_test_rows(tmp_path):
    """Even with --evaluate-test=True, poisoning Test rows must not alter weights or threshold."""
    clean_dir = tmp_path / "eval_clean"
    poison_dir = tmp_path / "eval_poison"
    clean_dir.mkdir()
    poison_dir.mkdir()

    def _run_eval(base_dir: Path, poison_offset: int):
        local_rng = np.random.default_rng(11)
        fixture = _build_real_preprocessor_e2e_fixture(base_dir, local_rng)
        if poison_offset != 0:
            df = pd.read_csv(fixture["csv_path"])
            test_mask = np.isin(
                np.arange(len(df)),
                np.concatenate([np.arange(70, 80), np.arange(110, 120)]),
            )
            df.loc[test_mask, list(ML_FEATURE_COLUMNS)] += poison_offset
            df.to_csv(fixture["csv_path"], index=False)
            new_sha = sha256_file(fixture["csv_path"])
            fixture["data_man_path"].write_text(
                json.dumps({"files": [{"file": "data/NF-UNSW-NB15-v3.csv", "sha256": new_sha}]}),
                encoding="utf-8",
            )
            split_obj = json.loads(fixture["split_man_path"].read_text(encoding="utf-8"))
            split_obj["dataset_sha256"] = new_sha
            fixture["split_man_path"].write_text(json.dumps(split_obj), encoding="utf-8")
            train_idx = np.concatenate([np.arange(0, 50), np.arange(80, 90)])
            prep = TrainOnlyPreprocessor(
                config=PreprocessingConfig(scaler_type="standard", add_missing_indicators=False),
                dataset_sha256=new_sha,
                split_manifest_sha256=sha256_file(fixture["split_man_path"]),
                split_protocol_version=SPLIT_PROTOCOL_VERSION,
            )
            prep.fit(df.iloc[train_idx][list(ML_FEATURE_COLUMNS)])
            prep.save(fixture["prep_path"], manifest_path=fixture["prep_man_path"])

        out_dir = base_dir / "out"
        rep_dir = base_dir / "rep"
        args = _make_real_prep_args(fixture, out_dir, rep_dir)
        args.evaluate_test = True
        assert run_pipeline(args) == 0
        return load_verified_autoencoder(
            out_dir / "autoencoder_model.joblib",
            out_dir / "autoencoder_manifest.json",
            require_complete_provenance=True,
        )

    m_clean, man_clean = _run_eval(clean_dir, 0)
    m_poison, man_poison = _run_eval(poison_dir, 1000)

    assert man_clean["threshold"] == pytest.approx(man_poison["threshold"], rel=0.0, abs=0.0)
    for w_clean, w_poison in zip(m_clean.coefs_, m_poison.coefs_, strict=True):
        np.testing.assert_array_equal(w_clean, w_poison)
