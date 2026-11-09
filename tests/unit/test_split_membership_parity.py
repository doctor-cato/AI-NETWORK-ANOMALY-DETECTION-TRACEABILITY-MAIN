"""Unit tests for split membership parity audit (PR #40 / Issue #31 Finding F03)."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.audit_split_membership_parity import (
    CANONICAL_OCT_SPLIT_HASHES,
    audit_split_membership_parity,
    main,
)


def test_audit_split_membership_parity_on_runtime_manifest(tmp_path: Path):
    """Verify audit_split_membership_parity correctly classifies protocol and byte status."""
    runtime_manifest = {
        "dataset_name": "NF-UNSW-NB15-v3",
        "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        "split_protocol_version": "nf-unsw-nb15-v3-chronological-group-purged-v1",
        "random_seed": 42,
        "total_source_rows": 2365424,
        "partitions": {
            "train": {"row_count": 1655797, "index_sha256": "30ed493e" + "0" * 56},
            "purged_train_val_gap": {"row_count": 9443, "index_sha256": "94d4eb9d" + "0" * 56},
            "validation": {"row_count": 345371, "index_sha256": "a3e4470c" + "0" * 56},
            "purged_val_test_gap": {"row_count": 8860, "index_sha256": "244f4831" + "0" * 56},
            "test": {"row_count": 345953, "index_sha256": "90219f75" + "0" * 56},
        },
    }
    manifest_path = tmp_path / "split_manifest.json"
    manifest_path.write_text(json.dumps(runtime_manifest), encoding="utf-8")

    evidence = audit_split_membership_parity(manifest_path)

    assert evidence["status"]["protocol_equivalence"] == "VERIFIED"
    assert evidence["status"]["artifact_byte_equivalence"] == "DIFFERENT"
    assert evidence["status"]["membership_equivalence"] == "NOT_VERIFIED"
    assert evidence["test_isolation"]["test_partition_accessed"] is False
    assert evidence["test_isolation"]["test_rows_loaded"] == 0


def test_audit_split_membership_parity_detects_row_count_mismatch(tmp_path: Path):
    """Verify that row count discrepancy marks protocol equivalence FAIL."""
    runtime_manifest = {
        "dataset_name": "NF-UNSW-NB15-v3",
        "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        "split_protocol_version": "nf-unsw-nb15-v3-chronological-group-purged-v1",
        "random_seed": 42,
        "total_source_rows": 2365424,
        "partitions": {
            "train": {"row_count": 1000, "index_sha256": "0" * 64},  # Mismatched row count
            "purged_train_val_gap": {"row_count": 9443, "index_sha256": "0" * 64},
            "validation": {"row_count": 345371, "index_sha256": "0" * 64},
            "purged_val_test_gap": {"row_count": 8860, "index_sha256": "0" * 64},
            "test": {"row_count": 345953, "index_sha256": "0" * 64},
        },
    }
    manifest_path = tmp_path / "split_manifest.json"
    manifest_path.write_text(json.dumps(runtime_manifest), encoding="utf-8")

    evidence = audit_split_membership_parity(manifest_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"


def test_audit_split_membership_cli_and_report_rendering(tmp_path: Path):
    """Verify CLI exit code and markdown report generation."""
    runtime_manifest = {
        "dataset_name": "NF-UNSW-NB15-v3",
        "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        "split_protocol_version": "nf-unsw-nb15-v3-chronological-group-purged-v1",
        "random_seed": 42,
        "total_source_rows": 2365424,
        "partitions": CANONICAL_OCT_SPLIT_HASHES["partitions"],
    }
    manifest_path = tmp_path / "split_manifest.json"
    manifest_path.write_text(json.dumps(runtime_manifest), encoding="utf-8")
    report_path = tmp_path / "report.md"

    rc = main(["--runtime-manifest", str(manifest_path), "--output-report", str(report_path)])
    assert rc == 0
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "Protocol Equivalence" in content
    assert "Membership Equivalence" in content
