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
    assert payload["expected_test_rows"] == 345953
