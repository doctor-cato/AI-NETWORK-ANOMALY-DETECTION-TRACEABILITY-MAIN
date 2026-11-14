"""Unit tests for Random Forest Test Evaluation (Issue #12) and Error Analysis (Issue #13)."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd
import pytest
from sklearn.exceptions import NotFittedError

from network_anomaly.data.nf_unsw_nb15_v3 import (
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.evaluation import (
    CANONICAL_DECISION_THRESHOLD,
    analyze_classification_boundary,
    analyze_feature_error_patterns,
    check_test_evaluation_prerequisites,
    compile_data_limitations_summary,
    compute_attack_category_breakdown,
    compute_metrics,
    compute_ranked_attack_category_errors,
    evaluate_random_forest_on_test,
    extract_fp_fn_samples,
    run_full_error_analysis_from_evaluation,
    stream_test_partition_data,
)
from network_anomaly.models.random_forest import (
    RandomForestBaselineConfig,
    RandomForestModel,
    create_rf_baseline_protocol,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _make_synthetic_feature_df(n_rows: int = 40, seed: int = 42) -> pd.DataFrame:
    """Create a valid 47-column DataFrame matching ML_FEATURE_COLUMNS."""
    rng = np.random.default_rng(seed)
    data: Dict[str, Any] = {}
    for col in ML_FEATURE_COLUMNS:
        if col in CATEGORICAL_CODED_COLUMNS:
            data[col] = rng.integers(1, 10, size=n_rows).astype(np.float64)
        else:
            data[col] = rng.uniform(1.0, 500.0, size=n_rows).astype(np.float64)
    return pd.DataFrame(data, columns=list(ML_FEATURE_COLUMNS))


# ==============================================================================
# 1. RANDOM FOREST MODEL HARDENING TESTS (Schema, Target, Metadata, Config)
# ==============================================================================


def test_rf_model_metadata_preserved_across_init_save_load(tmp_path: Path) -> None:
    """Verify metadata is preserved in __init__, save(), and load()."""
    init_meta = {"author": "Minh Khuong", "issue": 12}
    model = RandomForestModel(metadata=init_meta)
    assert model.metadata == init_meta

    X = _make_synthetic_feature_df(24, seed=7)
    y = np.array([0] * 12 + [1] * 12, dtype=np.int64)
    model.fit(X, y)

    artifact_path = tmp_path / "rf_meta_test.joblib"
    save_meta = {"evaluation_stage": "test_lock_verified"}
    sha = model.save(artifact_path, metadata=save_meta)
    assert len(sha) == 64

    loaded = RandomForestModel.load(artifact_path)
    assert loaded.is_fitted
    assert loaded.metadata["author"] == "Minh Khuong"
    assert loaded.metadata["issue"] == 12
    assert loaded.metadata["evaluation_stage"] == "test_lock_verified"


def test_rf_model_rejects_conflicting_config_and_protocol() -> None:
    """Verify passing conflicting config and protocol to __init__ raises ValueError."""
    proto = create_rf_baseline_protocol()
    conflicting_cfg = RandomForestBaselineConfig(
        n_estimators=50,
        max_depth=8,
        is_canonical_baseline=False,
        configuration_id="rf-custom-conflict",
    )
    with pytest.raises(ValueError, match="conflicts with protocol"):
        RandomForestModel(config=conflicting_cfg, protocol=proto)

    with pytest.raises(ValueError, match="conflicts with protocol"):
        RandomForestModel(
            config={
                "n_estimators": 50,
                "max_depth": 8,
                "is_canonical_baseline": False,
                "configuration_id": "rf-custom-conflict",
            },
            protocol=proto,
        )


def test_rf_model_feature_and_target_validation_in_fit_predict_proba() -> None:
    """Verify strict feature and target validation across fit, predict, and predict_proba."""
    model = RandomForestModel()
    X_valid = _make_synthetic_feature_df(20, seed=11)
    y_valid = np.array([0] * 10 + [1] * 10, dtype=np.int64)

    # Unfitted predict / predict_proba raises NotFittedError first
    with pytest.raises(NotFittedError):
        model.predict(X_valid)
    with pytest.raises(NotFittedError):
        model.predict_proba(X_valid)

    # Reject NaN or Inf in X during fit
    X_nan = X_valid.copy()
    X_nan.iloc[0, 0] = np.nan
    with pytest.raises(ValueError, match="NaN or infinite"):
        model.fit(X_nan, y_valid)

    X_inf = X_valid.copy()
    X_inf.iloc[1, 2] = np.inf
    with pytest.raises(ValueError, match="NaN or infinite"):
        model.fit(X_inf, y_valid)

    # Reject forbidden columns (Label, Attack, Trace metadata)
    X_with_label = X_valid.copy()
    X_with_label["Label"] = y_valid
    with pytest.raises(ValueError, match="forbidden"):
        model.fit(X_with_label, y_valid)

    # Reject invalid targets (booleans, length mismatch, invalid numbers, NaN)
    with pytest.raises(ValueError, match="booleans/None not allowed"):
        model.fit(X_valid, [True, False] * 10)
    with pytest.raises(ValueError, match="does not match"):
        model.fit(X_valid, y_valid[:5])
    with pytest.raises(ValueError, match="Invalid numeric target"):
        model.fit(X_valid, [0] * 19 + [2])

    # Fit on valid data, then test predict / predict_proba schema validation
    model.fit(X_valid, y_valid)
    preds = model.predict(X_valid)
    probas = model.predict_proba(X_valid)
    assert preds.shape == (20,)
    assert probas.shape == (20, 2)

    # Wrong column order or count on predict / predict_proba must fail
    X_reordered = X_valid[list(reversed(ML_FEATURE_COLUMNS))]
    with pytest.raises(ValueError):
        model.predict(X_reordered)
    with pytest.raises(ValueError):
        model.predict_proba(X_reordered)

    # NaN on predict / predict_proba must fail
    with pytest.raises(ValueError, match="NaN or infinite"):
        model.predict(X_nan)
    with pytest.raises(ValueError, match="NaN or infinite"):
        model.predict_proba(X_inf)


# ==============================================================================
# 2. METRICS MODULE HARDENING TESTS
# ==============================================================================


def test_compute_metrics_complete_fields_and_input_validation() -> None:
    """Verify compute_metrics returns all required metrics and rejects invalid inputs."""
    y_true = [0, 0, 0, 0, 1, 1, 1, 1]
    y_pred = [0, 0, 0, 1, 1, 1, 1, 0]  # TN=3, FP=1, TP=3, FN=1

    m = compute_metrics(y_true, y_pred)
    assert m["accuracy"] == pytest.approx(6.0 / 8.0)
    assert m["precision"] == pytest.approx(3.0 / 4.0)
    assert m["recall"] == pytest.approx(3.0 / 4.0)
    assert m["f1"] == pytest.approx(3.0 / 4.0)
    assert m["macro_f1"] == pytest.approx(3.0 / 4.0)
    assert m["weighted_f1"] == pytest.approx(3.0 / 4.0)
    assert m["false_positive_rate"] == pytest.approx(1.0 / 4.0)
    assert m["fpr"] == pytest.approx(1.0 / 4.0)
    assert m["true_negative_rate"] == pytest.approx(3.0 / 4.0)
    assert m["tnr"] == pytest.approx(3.0 / 4.0)
    assert m["confusion_matrix"] == [[3, 1], [1, 3]]
    assert m["confusion_matrix_labeled"] == {"tn": 3, "fp": 1, "fn": 1, "tp": 3}

    # Never silently ignore invalid labels when labels=[0, 1] is explicitly passed
    with pytest.raises(ValueError, match="unexpected labels"):
        compute_metrics([0, 1, 99], [0, 1, 1], labels=[0, 1])

    # Reject booleans, None, NaN, empty, 2D arrays, string passed as sequence
    with pytest.raises(ValueError, match="None/bool not allowed"):
        compute_metrics([True, False], [1, 0])
    with pytest.raises(ValueError, match="None/bool not allowed"):
        compute_metrics([0, None], [0, 1])
    with pytest.raises(ValueError, match="non-finite"):
        compute_metrics([0.0, float("nan")], [0.0, 1.0])
    with pytest.raises(ValueError, match="must not be empty"):
        compute_metrics([], [])
    with pytest.raises(ValueError, match="1D"):
        compute_metrics([[0, 1]], [[0, 1]])
    with pytest.raises(ValueError, match="1D sequence"):
        compute_metrics("0101", "0101")


def test_attack_category_breakdown_contradiction_and_expected_categories() -> None:
    """Verify per-attack-category breakdown validates y_true vs Attack
    and handles 0-count classes."""
    y_true = [0, 0, 1, 1, 1]
    y_pred = [0, 1, 1, 0, 1]
    categories = ["Benign", "Benign", "Exploits", "Exploits", "DoS"]

    brk = compute_attack_category_breakdown(
        y_true,
        y_pred,
        categories,
        expected_categories=["Benign", "Exploits", "DoS", "Worms"],
    )
    assert "detected" not in brk["Benign"]
    assert brk["Benign"]["total"] == 2
    assert brk["Benign"]["false_positive"] == 1
    assert brk["Benign"]["true_negative"] == 1
    assert brk["Benign"]["false_positive_rate"] == pytest.approx(0.5)

    assert brk["Exploits"]["total"] == 2
    assert brk["Exploits"]["detected"] == 1
    assert brk["Exploits"]["missed"] == 1
    assert brk["Exploits"]["detection_rate"] == pytest.approx(0.5)
    assert brk["Exploits"]["false_negative_rate"] == pytest.approx(0.5)

    assert brk["Worms"]["total"] == 0
    assert brk["Worms"]["detected"] == 0
    assert brk["Worms"]["missed"] == 0
    assert brk["Worms"]["detection_rate"] == 0.0
    assert brk["Worms"]["false_negative_rate"] == 0.0

    # Contradiction: Benign with y_true=1 must fail
    with pytest.raises(ValueError, match="Contradictory ground truth"):
        compute_attack_category_breakdown([1, 1], [1, 1], ["Benign", "Exploits"])

    # Contradiction: Attack category with y_true=0 must fail
    with pytest.raises(ValueError, match="Contradictory ground truth"):
        compute_attack_category_breakdown([0, 1], [0, 1], ["Exploits", "Exploits"])


# ==============================================================================
# 3. TEST EVALUATION & ERROR ANALYSIS END-TO-END SYNTHETIC PIPELINE TESTS
# ==============================================================================


def _build_synthetic_evaluation_fixture(tmp_path: Path) -> Dict[str, Any]:
    """Create a complete, hash-verified synthetic dataset, split, preprocessor, and RF model."""
    n_total = 60
    X_all = _make_synthetic_feature_df(n_total, seed=101)
    # Inject strong signal in IN_BYTES and OUT_BYTES for Attack rows
    labels = np.array([0] * 40 + [1] * 20, dtype=np.int64)
    attacks = (
        ["Benign"] * 40
        + ["Exploits"] * 8
        + ["Fuzzers"] * 5
        + ["Generic"] * 4
        + ["Reconnaissance"] * 2
        + ["Worms"] * 1
    )
    X_all.loc[labels == 1, "IN_BYTES"] += 5000.0
    X_all.loc[labels == 1, "OUT_BYTES"] += 5000.0

    full_df = X_all.copy()
    full_df["IPV4_SRC_ADDR"] = [f"10.0.0.{i % 250}" for i in range(n_total)]
    full_df["L4_SRC_PORT"] = 10000 + np.arange(n_total)
    full_df["IPV4_DST_ADDR"] = "192.168.1.1"
    full_df["L4_DST_PORT"] = 80
    full_df["FLOW_START_MILLISECONDS"] = 1700000000000 + np.arange(n_total) * 100
    full_df["FLOW_END_MILLISECONDS"] = 1700000000050 + np.arange(n_total) * 100
    full_df["Label"] = labels
    full_df["Attack"] = attacks

    dataset_csv = tmp_path / "synthetic_nf_unsw_nb15_v3.csv"
    full_df.to_csv(dataset_csv, index=False)
    ds_sha = _sha256_file(dataset_csv)

    # Disjoint Train (30), Val (10), Test (20) indices
    train_idx = [i for i in range(0, 20)] + [i for i in range(40, 50)]
    val_idx = [i for i in range(20, 26)] + [i for i in range(50, 54)]
    test_idx = [i for i in range(26, 40)] + [i for i in range(54, 60)]

    def _write_idx_gz(p: Path, idxs: list[int]) -> str:
        with gzip.open(p, "wt", encoding="utf-8", newline="") as f:
            f.write("source_row_index\n")
            for idx_v in idxs:
                f.write(f"{idx_v}\n")
        return _sha256_file(p)

    train_idx_path = tmp_path / "train_indices.csv.gz"
    val_idx_path = tmp_path / "validation_indices.csv.gz"
    test_idx_path = tmp_path / "test_indices.csv.gz"

    train_sha = _write_idx_gz(train_idx_path, train_idx)
    val_sha = _write_idx_gz(val_idx_path, val_idx)
    test_sha = _write_idx_gz(test_idx_path, test_idx)

    split_manifest_path = tmp_path / "split_manifest.json"
    split_manifest = {
        "dataset_sha256": ds_sha,
        "total_source_rows": n_total,
        "dataset_row_count": n_total,
        "partitions": {
            "train": {"row_count": len(train_idx), "index_sha256": train_sha},
            "validation": {"row_count": len(val_idx), "index_sha256": val_sha},
            "test": {
                "row_count": len(test_idx),
                "index_sha256": test_sha,
                "label_distribution": {"0": 14, "1": 6},
                "attack_distribution": {
                    "Benign": 14,
                    "Generic": 1,
                    "Reconnaissance": 2,
                    "Worms": 1,
                    "Exploits": 1,
                    "Fuzzers": 1,
                },
            },
        },
    }
    split_manifest_path.write_text(json.dumps(split_manifest, indent=2), encoding="utf-8")
    sm_sha = _sha256_file(split_manifest_path)

    # Fit TrainOnlyPreprocessor exclusively on Train rows
    X_train_raw = full_df.iloc[train_idx][list(ML_FEATURE_COLUMNS)].reset_index(drop=True)
    y_train = full_df.iloc[train_idx]["Label"].to_numpy(dtype=np.int64)

    preprocessor = TrainOnlyPreprocessor(
        dataset_sha256=ds_sha,
        split_manifest_sha256=sm_sha,
    )
    X_train_trans = preprocessor.fit_transform(X_train_raw)
    prep_artifact_path = tmp_path / "preprocessor.joblib"
    prep_manifest_path = tmp_path / "preprocessing_manifest.json"
    prep_sha = preprocessor.save(prep_artifact_path, manifest_path=prep_manifest_path)

    # Fit canonical RandomForestModel on transformed Train data
    protocol = create_rf_baseline_protocol()
    model = RandomForestModel(protocol=protocol)
    model.fit(X_train_trans, y_train)
    model_artifact_path = tmp_path / "random_forest_baseline.joblib"
    model_sha = model.save(model_artifact_path, metadata={"run_id": "synthetic-rf-test"})

    model_manifest_path = tmp_path / "random_forest_manifest.json"
    model_manifest = {
        "model_artifact_sha256": model_sha,
        "dataset_sha256": ds_sha,
        "split_manifest_sha256": sm_sha,
        "preprocessor_artifact_sha256": prep_sha,
        "protocol_version": protocol.protocol_version,
        "configuration_id": model.config.configuration_id,
        "is_canonical_baseline": model.config.is_canonical_baseline,
        "feature_contract_version": protocol.feature_contract_version,
        "selected_features": list(protocol.selected_features),
        "hyperparameters": model.config.to_dict(),
        "provenance_complete": True,
        "environment": {"git_commit": "905da0d"},
    }
    model_manifest_path.write_text(json.dumps(model_manifest, indent=2), encoding="utf-8")

    return {
        "dataset_csv": dataset_csv,
        "split_manifest": split_manifest_path,
        "train_indices": train_idx_path,
        "val_indices": val_idx_path,
        "test_indices": test_idx_path,
        "prep_manifest": prep_manifest_path,
        "prep_artifact": prep_artifact_path,
        "model_manifest": model_manifest_path,
        "model_artifact": model_artifact_path,
        "expected_test_indices": test_idx,
    }


def test_stream_test_partition_data_and_isolation_checks(tmp_path: Path) -> None:
    """Verify streaming Test partition loads exact indices, excludes forbidden cols,
    and rejects leakage."""
    fx = _build_synthetic_evaluation_fixture(tmp_path)

    test_data = stream_test_partition_data(
        dataset_csv_path=fx["dataset_csv"],
        test_indices_path=fx["test_indices"],
        train_indices_path=fx["train_indices"],
        val_indices_path=fx["val_indices"],
    )
    assert test_data.num_rows == 20
    assert list(test_data.X_test_raw.columns) == list(ML_FEATURE_COLUMNS)
    assert "Label" not in test_data.X_test_raw.columns
    assert "Attack" not in test_data.X_test_raw.columns
    for trace_col in TRACE_METADATA_COLUMNS:
        assert trace_col not in test_data.X_test_raw.columns
    assert list(test_data.row_indices) == fx["expected_test_indices"]
    assert test_data.trace_metadata is not None
    assert len(test_data.trace_metadata) == 20

    # Overlapping Train and Test indices must raise ValueError (data leakage protection)
    with pytest.raises(ValueError, match="Data leakage error"):
        stream_test_partition_data(
            dataset_csv_path=fx["dataset_csv"],
            test_indices_path=fx["test_indices"],
            train_indices_path=fx["test_indices"],
        )


def test_end_to_end_test_evaluation_and_artifact_generation(tmp_path: Path) -> None:
    """Verify evaluate_random_forest_on_test generates all 5 required artifacts
    and blocks overwrite."""
    fx = _build_synthetic_evaluation_fixture(tmp_path)
    out_dir = tmp_path / "eval_out"

    prereq = check_test_evaluation_prerequisites(
        dataset_csv_path=fx["dataset_csv"],
        split_manifest_path=fx["split_manifest"],
        test_indices_path=fx["test_indices"],
        train_indices_path=fx["train_indices"],
        val_indices_path=fx["val_indices"],
        preprocessing_manifest_path=fx["prep_manifest"],
        preprocessor_artifact_path=fx["prep_artifact"],
        model_manifest_path=fx["model_manifest"],
        model_artifact_path=fx["model_artifact"],
        fail_closed=True,
    )
    assert prereq.ready is True
    assert prereq.status == "READY"

    res = evaluate_random_forest_on_test(
        dataset_csv_path=fx["dataset_csv"],
        split_manifest_path=fx["split_manifest"],
        test_indices_path=fx["test_indices"],
        train_indices_path=fx["train_indices"],
        val_indices_path=fx["val_indices"],
        preprocessing_manifest_path=fx["prep_manifest"],
        preprocessor_artifact_path=fx["prep_artifact"],
        model_manifest_path=fx["model_manifest"],
        model_artifact_path=fx["model_artifact"],
        output_dir=out_dir,
        run_id="synthetic-run-001",
    )

    # Verify all 5 required evaluation artifacts exist and are non-empty
    expected_files = [
        "metrics.json",
        "confusion_matrix.csv",
        "confusion_matrix.png",
        "predictions.csv",
        "evaluation_metadata.json",
    ]
    for fname in expected_files:
        fpath = out_dir / fname
        assert fpath.exists(), f"Missing artifact: {fname}"
        assert fpath.stat().st_size > 0

    # Verify PNG header signature
    png_bytes = (out_dir / "confusion_matrix.png").read_bytes()
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")

    # Verify predictions.csv row count and columns
    preds_df = pd.read_csv(out_dir / "predictions.csv")
    assert len(preds_df) == 20
    assert list(preds_df.columns) == [
        "row_index",
        "y_true",
        "y_pred",
        "prob_benign",
        "prob_attack",
        "attack_category",
        "outcome",
    ]

    # Verify evaluation_metadata.json test-lock compliance flags
    meta_json = json.loads((out_dir / "evaluation_metadata.json").read_text(encoding="utf-8"))
    assert meta_json["partition"] == "test"
    assert meta_json["decision_threshold"] == CANONICAL_DECISION_THRESHOLD
    assert meta_json["test_lock_compliance"] == {
        "model_retrained_on_test": False,
        "preprocessor_refitted_on_test": False,
        "hyperparameters_tuned_on_test": False,
        "threshold_tuned_on_test": False,
        "train_validation_disjoint_verified": True,
    }

    # Verify overwrite protection when allow_overwrite=False
    with pytest.raises(FileExistsError):
        evaluate_random_forest_on_test(
            dataset_csv_path=fx["dataset_csv"],
            split_manifest_path=fx["split_manifest"],
            test_indices_path=fx["test_indices"],
            train_indices_path=fx["train_indices"],
            val_indices_path=fx["val_indices"],
            preprocessing_manifest_path=fx["prep_manifest"],
            preprocessor_artifact_path=fx["prep_artifact"],
            model_manifest_path=fx["model_manifest"],
            model_artifact_path=fx["model_artifact"],
            output_dir=out_dir,
            run_id="synthetic-run-001",
            allow_overwrite=False,
        )

    # Run full Issue #13 error analysis on evaluation result
    report_md_path = tmp_path / "error_analysis_report.md"
    analysis_out = run_full_error_analysis_from_evaluation(
        evaluation_result=res,
        feature_importances=np.full(len(ML_FEATURE_COLUMNS), 1.0 / len(ML_FEATURE_COLUMNS)),
        report_path=report_md_path,
    )
    assert report_md_path.exists()
    md_text = report_md_path.read_text(encoding="utf-8")
    assert "EXPERIMENTALLY VALIDATED ON HELD-OUT TEST SET" not in md_text
    assert "REAL-DATA PROVENANCE NOT VERIFIED" in md_text
    assert "## 1. Executive Summary" in md_text
    assert "## 14. Recommendations for Future Work" in md_text
    assert "fp_fn_summary" in analysis_out
    assert "ranked_attack_categories" in analysis_out
    assert "boundary_analysis" in analysis_out


def test_error_analysis_fp_fn_ranking_and_boundary_functions() -> None:
    """Verify FP/FN sample extraction, attack category ranking by FN, and boundary analysis."""
    X = _make_synthetic_feature_df(10, seed=55)
    y_true = [0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
    y_pred = [0, 0, 1, 1, 1, 0, 0, 0, 1, 0]  # 2 FP, 4 FN (3 Exploits FN, 1 Worms FN)
    prob_attack = [0.05, 0.12, 0.85, 0.60, 0.92, 0.42, 0.15, 0.38, 0.88, 0.10]
    attack_cats = [
        "Benign",
        "Benign",
        "Benign",
        "Benign",
        "Exploits",
        "Exploits",
        "Exploits",
        "Exploits",
        "Worms",
        "Worms",
    ]

    fp_fn = extract_fp_fn_samples(
        X=X,
        y_true=y_true,
        y_pred=y_pred,
        prob_attack=prob_attack,
        attack_categories=attack_cats,
    )
    assert fp_fn["false_positives"]["count"] == 2
    assert fp_fn["false_positives"]["false_positive_rate"] == pytest.approx(0.5)
    assert fp_fn["false_negatives"]["count"] == 4
    assert fp_fn["false_negatives"]["false_negative_rate"] == pytest.approx(4.0 / 6.0)
    assert fp_fn["false_negatives"]["counts_by_attack_category"] == {"Exploits": 3, "Worms": 1}

    ranked = compute_ranked_attack_category_errors(
        y_true=y_true,
        y_pred=y_pred,
        attack_categories=attack_cats,
        expected_categories=["Benign", "Exploits", "Worms", "DoS"],
    )
    cats_order = [c["attack_category"] for c in ranked["ranked_attack_categories"]]
    assert cats_order == ["Exploits", "Worms", "DoS"]
    assert ranked["ranked_attack_categories"][0]["missed"] == 3
    assert ranked["ranked_attack_categories"][1]["missed"] == 1
    assert ranked["ranked_attack_categories"][2]["missed"] == 0

    feat_patterns = analyze_feature_error_patterns(
        X=X,
        y_true=y_true,
        y_pred=y_pred,
        feature_importances=np.linspace(0.01, 0.05, len(ML_FEATURE_COLUMNS)),
    )
    assert len(feat_patterns["global_feature_importance"]) == 15
    assert len(feat_patterns["misclassified_feature_patterns"]["fp_vs_tn_top_shifts"]) == 15
    assert len(feat_patterns["misclassified_feature_patterns"]["fn_vs_tp_top_shifts"]) == 15
    assert len(feat_patterns["error_hypotheses"]) >= 4

    boundary = analyze_classification_boundary(
        y_true=y_true,
        y_pred=y_pred,
        prob_attack=prob_attack,
        uncertainty_band=(0.35, 0.65),
    )
    assert boundary["decision_threshold"] == 0.5
    assert boundary["threshold_tuned_on_test"] is False
    assert boundary["samples_in_uncertainty_band"] == 3  # 0.60, 0.42, 0.38
    assert boundary["high_confidence_errors"]["fp_prob_ge_0_80"] == 1  # 0.85
    assert boundary["high_confidence_errors"]["fn_prob_le_0_20"] == 2  # 0.15, 0.10


def test_fail_closed_prerequisites_when_binaries_missing(tmp_path: Path) -> None:
    """Verify check_test_evaluation_prerequisites blocks fail-closed when
    binary files are absent."""
    missing_csv = tmp_path / "nonexistent.csv"
    status = check_test_evaluation_prerequisites(
        dataset_csv_path=missing_csv,
        fail_closed=False,
    )
    assert status.ready is False
    assert status.status == "BLOCKED"
    assert any("dataset_csv" in item for item in status.missing_artifacts)

    with pytest.raises(FileNotFoundError, match="fail-closed"):
        check_test_evaluation_prerequisites(
            dataset_csv_path=missing_csv,
            fail_closed=True,
        )

    limitations = compile_data_limitations_summary()
    assert limitations["class_imbalance"]["test_total_rows"] == 345953
    assert limitations["rare_attack_classes"]["rare_categories_in_test"]["Worms"] == 36
    assert limitations["feature_overlap_ambiguity"]["overlapping_unique_feature_keys"] is None
    assert limitations["evidence_status"] == "NOT VERIFIED"


def test_compute_metrics_single_label_binary_expands_confusion_matrix() -> None:
    """F5 regression: single-class binary labels still yield 2x2 confusion_matrix matching tn/fp/fn/tp."""
    for single_label in ([1], [0]):
        metrics = compute_metrics([0, 1], [1, 1], labels=single_label)
        cm = metrics["confusion_matrix"]
        labeled = metrics["confusion_matrix_labeled"]
        assert cm == [[0, 1], [0, 1]]
        assert sum(sum(row) for row in cm) == sum(labeled.values()) == 2
        assert labeled == {"tn": 0, "fp": 1, "fn": 0, "tp": 1}
        assert metrics["false_positive_rate"] == 1.0

    str_metrics = compute_metrics(["Benign", "Attack"], ["Attack", "Attack"], labels=["Attack"])
    assert str_metrics["confusion_matrix"] == [[0, 1], [0, 1]]

    with pytest.raises(ValueError, match="Unsupported single-class binary label"):
        compute_metrics(["weird"], ["weird"], labels=["weird"])
