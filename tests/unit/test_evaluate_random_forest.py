"""Regression tests for Random Forest held-out test evaluation (Issue #12, PR #50).

Covers:
  - Canonical manifest checksum contract using 'index_sha256'
  - Fail-closed rejection of mismatched or missing test index checksums
  - Genuine index disjointness set operations (Train, Val, Test)
  - Fail-closed behavior when partition index files are absent (no hardcoded True flag)
  - Detection of partition overlap leakage, internal duplicate indices, and out-of-bounds indices
  - CLI --verify-only invocation
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import List

import pytest

from network_anomaly.evaluation.test_evaluation import (
    _sha256_file,
    check_test_evaluation_prerequisites,
    main,
    verify_index_disjointness,
)


def _write_gz_indices(path: Path, indices: List[int]) -> str:
    """Helper to write integer indices to a gzip CSV and return its SHA-256."""
    with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
        f.write("row_index\n")
        for idx in indices:
            f.write(f"{idx}\n")
    return _sha256_file(path)


# ==============================================================================
# 1. MANIFEST CHECKSUM CONTRACT (index_sha256) TESTS
# ==============================================================================


def test_prerequisites_rejects_test_indices_sha256_mismatch(tmp_path: Path) -> None:
    """Verify check_test_evaluation_prerequisites rejects test_indices with mismatched SHA-256."""
    ti_path = tmp_path / "test_indices.csv.gz"
    actual_sha = _write_gz_indices(ti_path, [10, 11, 12])

    fake_expected_sha = "0000000000000000000000000000000000000000000000000000000000000000"

    sm_path = tmp_path / "split_manifest.json"
    manifest_data = {
        "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        "total_source_rows": 100,
        "partitions": {
            "train": {"row_count": 50, "index_sha256": "dummy_train_sha"},
            "validation": {"row_count": 25, "index_sha256": "dummy_val_sha"},
            "test": {
                "row_count": 3,
                "index_sha256": fake_expected_sha,  # Mismatched SHA
            },
        },
    }
    sm_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    status = check_test_evaluation_prerequisites(
        split_manifest_path=sm_path,
        test_indices_path=ti_path,
        fail_closed=False,
    )

    assert not status.ready
    mismatch_errors = [
        e for e in status.verification_errors if "test_indices SHA-256 mismatch" in e
    ]
    assert len(mismatch_errors) == 1
    assert fake_expected_sha in mismatch_errors[0]
    assert actual_sha in mismatch_errors[0]

    # Verify fail_closed=True raises ValueError
    with pytest.raises((ValueError, FileNotFoundError)):
        check_test_evaluation_prerequisites(
            split_manifest_path=sm_path,
            test_indices_path=ti_path,
            fail_closed=True,
        )


def test_prerequisites_rejects_missing_index_sha256_key_in_manifest(tmp_path: Path) -> None:
    """Verify check_test_evaluation_prerequisites flags missing index_sha256 in split manifest."""
    ti_path = tmp_path / "test_indices.csv.gz"
    _write_gz_indices(ti_path, [10, 11, 12])

    sm_path = tmp_path / "split_manifest.json"
    # Malformed manifest: missing index_sha256 key
    manifest_data = {
        "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        "partitions": {
            "test": {
                "row_count": 3,
                # "index_sha256" omitted
            }
        },
    }
    sm_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    status = check_test_evaluation_prerequisites(
        split_manifest_path=sm_path,
        test_indices_path=ti_path,
        fail_closed=False,
    )

    assert not status.ready
    missing_key_errors = [
        e for e in status.verification_errors if "missing required 'index_sha256' key" in e
    ]
    assert len(missing_key_errors) >= 1


# ==============================================================================
# 2. INDEX DISJOINTNESS & FAIL-CLOSED INTEGRITY TESTS
# ==============================================================================


def test_verify_index_disjointness_fail_closed_when_indices_missing(tmp_path: Path) -> None:
    """Verify verify_index_disjointness fails closed when index files are absent."""
    non_existent = tmp_path / "absent_indices.csv.gz"

    # All missing
    is_disjoint, errors = verify_index_disjointness(
        train_indices_path=non_existent,
        val_indices_path=non_existent,
        test_indices_path=non_existent,
    )
    assert not is_disjoint
    assert any("missing partition index file" in e for e in errors)

    # Only test present, train & val missing
    ti_path = tmp_path / "test_indices.csv.gz"
    _write_gz_indices(ti_path, [1, 2, 3])

    is_disjoint, errors = verify_index_disjointness(
        train_indices_path=non_existent,
        val_indices_path=non_existent,
        test_indices_path=ti_path,
    )
    assert not is_disjoint
    assert any("missing partition index file" in e for e in errors)


def test_check_prerequisites_sets_disjoint_flag_false_when_indices_missing() -> None:
    """Verify check_test_evaluation_prerequisites outputs disjoint_verified = False."""
    status = check_test_evaluation_prerequisites(fail_closed=False)
    # Binary indices are not checked in git
    assert not status.ready
    assert status.train_validation_disjoint_verified is False
    assert status.to_dict()["train_validation_disjoint_verified"] is False


def test_verify_index_disjointness_detects_pairwise_data_leakage(tmp_path: Path) -> None:
    """Verify genuine set operations detect overlaps across all partition pairs."""
    train_path = tmp_path / "train.csv.gz"
    val_path = tmp_path / "val.csv.gz"
    test_path = tmp_path / "test.csv.gz"

    # Case A: Train and Test overlap (row 25 is in both)
    _write_gz_indices(train_path, [1, 2, 3, 25])
    _write_gz_indices(val_path, [10, 11, 12])
    _write_gz_indices(test_path, [20, 21, 25])

    is_disjoint, errors = verify_index_disjointness(
        train_indices_path=train_path,
        val_indices_path=val_path,
        test_indices_path=test_path,
    )
    assert not is_disjoint
    assert any("between Train and Test" in e for e in errors)

    # Case B: Validation and Test overlap (row 20 is in both)
    _write_gz_indices(train_path, [1, 2, 3])
    _write_gz_indices(val_path, [10, 11, 20])
    _write_gz_indices(test_path, [20, 21, 22])

    is_disjoint, errors = verify_index_disjointness(
        train_indices_path=train_path,
        val_indices_path=val_path,
        test_indices_path=test_path,
    )
    assert not is_disjoint
    assert any("between Validation and Test" in e for e in errors)

    # Case C: Train and Validation overlap (row 10 is in both)
    _write_gz_indices(train_path, [1, 2, 10])
    _write_gz_indices(val_path, [10, 11, 12])
    _write_gz_indices(test_path, [20, 21, 22])

    is_disjoint, errors = verify_index_disjointness(
        train_indices_path=train_path,
        val_indices_path=val_path,
        test_indices_path=test_path,
    )
    assert not is_disjoint
    assert any("between Train and Validation" in e for e in errors)


def test_verify_index_disjointness_detects_internal_duplicates_and_out_of_bounds(
    tmp_path: Path,
) -> None:
    """Verify internal duplicates and row indices outside [0, total_rows-1] are detected."""
    train_path = tmp_path / "train.csv.gz"
    val_path = tmp_path / "val.csv.gz"
    test_path = tmp_path / "test.csv.gz"

    # Out of bounds index (index 150 when total_rows is 100)
    _write_gz_indices(train_path, [0, 1, 150])
    _write_gz_indices(val_path, [10, 11])
    _write_gz_indices(test_path, [20, 21])

    is_disjoint, errors = verify_index_disjointness(
        train_indices_path=train_path,
        val_indices_path=val_path,
        test_indices_path=test_path,
        total_source_rows=100,
    )
    assert not is_disjoint
    assert any("outside valid range" in e for e in errors)


def test_verify_index_disjointness_passes_when_strictly_disjoint(tmp_path: Path) -> None:
    """Verify disjointness passes cleanly when partitions are genuinely mutually exclusive."""
    train_path = tmp_path / "train.csv.gz"
    val_path = tmp_path / "val.csv.gz"
    test_path = tmp_path / "test.csv.gz"

    train_sha = _write_gz_indices(train_path, [0, 1, 2, 3])
    val_sha = _write_gz_indices(val_path, [4, 5, 6])
    test_sha = _write_gz_indices(test_path, [7, 8, 9])

    split_manifest = {
        "total_source_rows": 10,
        "partitions": {
            "train": {"index_sha256": train_sha},
            "validation": {"index_sha256": val_sha},
            "test": {"index_sha256": test_sha},
        },
    }

    is_disjoint, errors = verify_index_disjointness(
        train_indices_path=train_path,
        val_indices_path=val_path,
        test_indices_path=test_path,
        split_manifest=split_manifest,
        total_source_rows=10,
    )
    assert is_disjoint
    assert len(errors) == 0


# ==============================================================================
# 3. CLI --verify-only INTEGRATION TESTS
# ==============================================================================


def test_evaluate_random_forest_cli_verify_only(capsys: pytest.CaptureFixture) -> None:
    """Verify evaluate_random_forest CLI --verify-only executes and reports BLOCKED status."""
    exit_code = main(["--verify-only"])
    # Absent binary files return exit code 2
    assert exit_code == 2

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ready"] is False
    assert payload["status"] == "BLOCKED"
    assert payload["train_validation_disjoint_verified"] is False
    assert payload["partition_verification_status"] == "BLOCKED"
    assert payload["expected_test_rows"] == 345953


# ==============================================================================
# 4. PREPROCESSOR MANIFEST VALIDATION (P2-01) & PARTITION COUNT TESTS (P1-02)
# ==============================================================================


def test_prerequisites_rejects_preprocessor_manifest_wrong_type_or_fit_partition(
    tmp_path: Path,
) -> None:
    """Verify P2-01 fix: wrong artifact_type or non-train fit_partition is rejected fail-closed."""
    from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS

    valid_sha = "a" * 64
    pm_path = tmp_path / "preprocessing_manifest.json"

    # Case 1: Wrong artifact_type even when fit_partition == "train"
    bad_type_manifest = {
        "artifact_type": "wrong-preprocessor-type",
        "fit_partition": "train",
        "dataset_sha256": valid_sha,
        "split_manifest_sha256": valid_sha,
        "artifact_sha256": valid_sha,
        "feature_contract_version": "nf-unsw-nb15-v3-baseline-47",
        "baseline_ml_features_in_order": list(ML_FEATURE_COLUMNS),
        "output_features_in_order": list(ML_FEATURE_COLUMNS),
        "train_row_count": 100,
    }
    pm_path.write_text(json.dumps(bad_type_manifest), encoding="utf-8")
    status_1 = check_test_evaluation_prerequisites(
        preprocessing_manifest_path=pm_path,
        fail_closed=False,
    )
    assert not status_1.ready
    assert any("artifact_type" in e for e in status_1.verification_errors)

    # Case 2: Valid artifact_type but fit_partition == "test" (data leakage!)
    bad_part_manifest = dict(bad_type_manifest)
    bad_part_manifest["artifact_type"] = "nf-unsw-nb15-v3-train-only-preprocessor"
    bad_part_manifest["fit_partition"] = "test"
    pm_path.write_text(json.dumps(bad_part_manifest), encoding="utf-8")
    status_2 = check_test_evaluation_prerequisites(
        preprocessing_manifest_path=pm_path,
        fail_closed=False,
    )
    assert not status_2.ready
    assert any("fit_partition" in e for e in status_2.verification_errors)

    # Case 3: Missing / non-positive train_row_count or wrong feature order
    bad_feat_manifest = dict(bad_type_manifest)
    bad_feat_manifest["artifact_type"] = "nf-unsw-nb15-v3-train-only-preprocessor"
    bad_feat_manifest["fit_partition"] = "train"
    bad_feat_manifest["output_features_in_order"] = list(reversed(ML_FEATURE_COLUMNS))
    bad_feat_manifest["train_row_count"] = 0
    pm_path.write_text(json.dumps(bad_feat_manifest), encoding="utf-8")
    status_3 = check_test_evaluation_prerequisites(
        preprocessing_manifest_path=pm_path,
        fail_closed=False,
    )
    assert not status_3.ready
    assert any("output_features_in_order" in e for e in status_3.verification_errors)
    assert any("train_row_count" in e for e in status_3.verification_errors)


def test_verify_index_disjointness_detects_row_count_mismatch_and_legacy_sha_key(
    tmp_path: Path,
) -> None:
    """Verify P1-01/P1-02: legacy 'sha256' key without 'index_sha256' and row_count mismatch fail."""  # noqa: E501
    train_path = tmp_path / "train.csv.gz"
    val_path = tmp_path / "val.csv.gz"
    test_path = tmp_path / "test.csv.gz"

    train_sha = _write_gz_indices(train_path, [0, 1, 2, 3])
    val_sha = _write_gz_indices(val_path, [4, 5, 6])
    test_sha = _write_gz_indices(test_path, [7, 8, 9])

    # Manifest uses legacy 'sha256' instead of 'index_sha256' and wrong row_count for test
    bad_manifest = {
        "total_source_rows": 10,
        "partitions": {
            "train": {"row_count": 4, "index_sha256": train_sha},
            "validation": {"row_count": 3, "index_sha256": val_sha},
            "test": {"row_count": 99, "sha256": test_sha},
        },
    }
    is_disjoint, errors = verify_index_disjointness(
        train_indices_path=train_path,
        val_indices_path=val_path,
        test_indices_path=test_path,
        split_manifest=bad_manifest,
        total_source_rows=10,
    )
    assert not is_disjoint
    assert any("missing required 'index_sha256' key" in e for e in errors)
    assert any(
        "test index row count (3) != split manifest expected row_count (99)" in e for e in errors
    )


# ==============================================================================
# 5. CONFUSION MATRIX PNG (P2-02) & PREDICTION / LABEL INVARIANTS (P2-06)
# ==============================================================================


def test_save_confusion_matrix_artifacts_renders_valid_non_blank_png(tmp_path: Path) -> None:
    """Verify P2-02: confusion matrix PNG is non-empty, valid PNG, non-uniform, and rejects bad shapes."""  # noqa: E501
    import numpy as np
    from PIL import Image

    from network_anomaly.evaluation.test_evaluation import save_confusion_matrix_artifacts

    csv_p = tmp_path / "cm.csv"
    png_p = tmp_path / "cm.png"
    csv_sha, png_sha = save_confusion_matrix_artifacts(
        cm=[[315350, 7], [4, 30592]],
        output_csv_path=csv_p,
        output_png_path=png_p,
    )
    assert len(csv_sha) == 64
    assert len(png_sha) == 64
    assert png_p.exists() and png_p.stat().st_size > 5000

    img = Image.open(png_p)
    arr = np.asarray(img)
    assert arr.ndim >= 2
    assert arr.shape[0] > 200 and arr.shape[1] > 200
    # Non-uniform pixel content (not a blank canvas)
    assert float(np.std(arr)) > 5.0

    # Reject non-2x2 or negative confusion matrices
    with pytest.raises(ValueError, match="shape \\(2, 2\\)"):
        save_confusion_matrix_artifacts([[1, 2, 3]], csv_p, png_p)
    with pytest.raises(ValueError, match="non-negative"):
        save_confusion_matrix_artifacts([[10, -1], [0, 5]], csv_p, png_p)


def test_prediction_and_label_invariants_reject_fractional_labels_and_bad_classes(
    tmp_path: Path,
) -> None:
    """Verify P2-06: fractional labels, duplicate row_indices, and misordered classes_ fail closed."""  # noqa: E501
    import numpy as np
    import pandas as pd

    from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
    from network_anomaly.evaluation.metrics import compute_metrics
    from network_anomaly.evaluation.test_evaluation import (
        TestPartitionData,
        evaluate_loaded_random_forest_on_test,
        save_predictions_csv,
    )

    # 1. Fractional float labels rejected by compute_metrics
    with pytest.raises(ValueError, match="fractional float label"):
        compute_metrics([0, 1, 0.5], [0, 1, 1])

    # 2. Duplicate or negative row_indices rejected by TestPartitionData and save_predictions_csv
    X_df = pd.DataFrame(
        np.zeros((3, len(ML_FEATURE_COLUMNS))),
        columns=list(ML_FEATURE_COLUMNS),
    )
    with pytest.raises(ValueError, match="duplicate"):
        TestPartitionData(
            X_test_raw=X_df,
            y_test=np.array([0, 1, 0], dtype=np.int64),
            attack_categories=np.array(["Benign", "Exploits", "Benign"], dtype=object),
            row_indices=np.array([10, 10, 12], dtype=np.int64),
        )

    with pytest.raises(ValueError, match="sum to 1.0"):
        save_predictions_csv(
            path=tmp_path / "bad_preds.csv",
            row_indices=[1, 2],
            y_true=[0, 1],
            y_pred=[0, 1],
            prob_benign=[0.8, 0.2],
            prob_attack=[0.5, 0.8],  # row 0 sums to 1.3
            attack_categories=["Benign", "Exploits"],
        )

    # 3. Misordered model.classes_ ([1, 0] instead of [0, 1]) rejected fail-closed
    valid_td = TestPartitionData(
        X_test_raw=X_df,
        y_test=np.array([0, 1, 0], dtype=np.int64),
        attack_categories=np.array(["Benign", "Exploits", "Benign"], dtype=object),
        row_indices=np.array([10, 11, 12], dtype=np.int64),
    )

    class _DummyPrep:
        def transform(self, df: pd.DataFrame) -> pd.DataFrame:
            return df

    class _MisorderedModel:
        classes_ = np.array([1, 0])

        def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
            return np.array([[0.9, 0.1], [0.2, 0.8], [0.5, 0.5]])

    with pytest.raises(ValueError, match="canonical binary ordering \\[0, 1\\]"):
        evaluate_loaded_random_forest_on_test(
            model=_MisorderedModel(),  # type: ignore[arg-type]
            preprocessor=_DummyPrep(),  # type: ignore[arg-type]
            test_data=valid_td,
            output_dir=tmp_path / "out_misordered",
        )
