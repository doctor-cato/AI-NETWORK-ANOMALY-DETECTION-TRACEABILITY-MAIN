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
"""

import gzip
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ALL_COLUMNS,
    ML_FEATURE_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.models.autoencoder import (
    build_model,
    fit_model,
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
    load_verified_autoencoder,
    run_pipeline,
    save_artifacts,
    sha256_file,
    verify_saved_model,
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
    man = tmp_path / "split.json"
    man.write_text(json.dumps({"partitions": {"train": {}}}))
    res = check_split_manifest(manifest_path=man, indices_dir=tmp_path)
    assert res["status"] == "BLOCKED"
    assert "missing partition" in res["message"]


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
    assert res["empirical_val_fpr"] <= 0.06


def test_calibrate_threshold_supervised_best_f1():
    # Benign low scores, attacks high scores
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
    # 2 unknown attacks with extreme scores
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
    assert res["tnr"] == 3 / 4

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

    # 3. Create partition indices
    # Train: 0-79 (80 rows), Validation: 80-119 (40 rows), Test: 120-149 (30 rows)
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()

    train_idx = np.arange(0, 80)
    val_idx = np.arange(80, 120)
    test_idx = np.arange(120, 150)

    train_idx_path = indices_dir / "train_indices.csv.gz"
    val_idx_path = indices_dir / "validation_indices.csv.gz"
    test_idx_path = indices_dir / "test_indices.csv.gz"

    with gzip.open(train_idx_path, "wt") as fh:
        for idx in train_idx:
            fh.write(f"{idx}\n")
    with gzip.open(val_idx_path, "wt") as fh:
        for idx in val_idx:
            fh.write(f"{idx}\n")
    with gzip.open(test_idx_path, "wt") as fh:
        for idx in test_idx:
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
    import argparse

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
