"""Unit and regression tests for split membership parity audit (PR #40 / Issue #31 Finding F03).

Verifies protocol equivalence checks, tamper detection, evidentiary boundaries,
and runtime test-lock isolation verification.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from scripts.audit_split_membership_parity import (
    CANONICAL_OCT_SPLIT_REFERENCE,
    audit_split_membership_parity,
    main,
)


def _build_valid_runtime_manifest() -> dict:
    """Build a valid runtime split manifest matching canonical protocol reference."""
    manifest = copy.deepcopy(CANONICAL_OCT_SPLIT_REFERENCE)
    manifest["generated_at_utc"] = "2026-11-08T14:48:35.123456+00:00"
    # Runtime index files have divergent Nov hashes
    manifest["partitions"]["train"]["index_sha256"] = "30ed493e" + "0" * 56
    manifest["partitions"]["purged_train_val_gap"]["index_sha256"] = "94d4eb9d" + "0" * 56
    manifest["partitions"]["validation"]["index_sha256"] = "a3e4470c" + "0" * 56
    manifest["partitions"]["purged_val_test_gap"]["index_sha256"] = "244f4831" + "0" * 56
    manifest["partitions"]["test"]["index_sha256"] = "90219f75" + "0" * 56
    return manifest


def _build_valid_training_manifest() -> dict:
    """Build a mock model training manifest recording verified test-lock isolation."""
    return {
        "run_id": "xgb-baseline-1794151507",
        "test_lock_audit": {
            "test_partition_accessed": False,
            "test_rows_loaded": 0,
            "test_indices_loaded": False,
        },
        "split_provenance": {
            "test_partition_accessed": False,
            "test_rows_loaded": 0,
        },
    }


def test_audit_passes_valid_runtime_manifest(tmp_path: Path):
    """Verify that a valid runtime manifest achieves VERIFIED protocol equivalence."""
    m_data = _build_valid_runtime_manifest()
    m_path = tmp_path / "valid_split_manifest.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    t_data = _build_valid_training_manifest()
    t_path = tmp_path / "training_manifest.json"
    t_path.write_text(json.dumps(t_data), encoding="utf-8")

    evidence = audit_split_membership_parity(
        runtime_manifest_path=m_path,
        training_manifest_path=t_path,
    )

    assert evidence["status"]["protocol_equivalence"] == "VERIFIED"
    assert evidence["status"]["artifact_byte_equivalence"] == "DIFFERENT"
    assert evidence["status"]["membership_equivalence"] == "NOT_VERIFIED"
    assert evidence["protocol_discrepancies"] == []

    # Verify measured runtime evidence
    m_ev = evidence["test_isolation"]["measured_runtime_evidence"]
    assert m_ev["status"] == "VERIFIED_FROM_RUN_MANIFEST"
    assert m_ev["training_run_id"] == "xgb-baseline-1794151507"
    assert m_ev["test_partition_accessed"] is False
    assert m_ev["test_rows_loaded"] == 0

    # Verify hash divergence analysis is unproven hypothesis
    assert evidence["cause_of_hash_divergence"]["status"] == "UNPROVEN_HYPOTHESIS"


def test_audit_fails_on_tampered_dataset_name(tmp_path: Path):
    """Verify protocol equivalence fails when dataset_name is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["dataset_name"] = "TAMPERED-DATASET-NAME"
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("dataset_name mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_dataset_sha256(tmp_path: Path):
    """Verify protocol equivalence fails when dataset_sha256 is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["dataset_sha256"] = "0" * 64
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("dataset_sha256 mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_split_protocol_version(tmp_path: Path):
    """Verify protocol equivalence fails when split_protocol_version is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["split_protocol_version"] = "tampered-protocol-v2"
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("split_protocol_version mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_random_seed(tmp_path: Path):
    """Verify protocol equivalence fails when random_seed is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["random_seed"] = 9999
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("random_seed mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_total_rows(tmp_path: Path):
    """Verify protocol equivalence fails when total_source_rows is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["total_source_rows"] = 1000000
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("total_source_rows mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_split_policy_boundaries(tmp_path: Path):
    """Verify protocol equivalence fails when temporal boundaries are altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["split_policy"]["boundaries"]["t_val_start_epoch_ms"] += 1000
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("temporal boundaries mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_purge_gap(tmp_path: Path):
    """Verify protocol equivalence fails when purge gap is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["split_policy"]["purge_gap_milliseconds"] = 60000
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("purge_gap_milliseconds mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_partition_row_count(tmp_path: Path):
    """Verify protocol equivalence fails when any partition row count is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["partitions"]["train"]["row_count"] -= 1
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("row count mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_partition_time_coverage(tmp_path: Path):
    """Verify protocol equivalence fails when partition time coverage is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["partitions"]["validation"]["time_coverage"]["max_epoch_ms"] -= 500
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("time coverage mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_partition_label_distribution(tmp_path: Path):
    """Verify protocol equivalence fails when label distribution is altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["partitions"]["train"]["label_distribution"]["1"] += 1
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any("label distribution mismatch" in d for d in evidence["protocol_discrepancies"])


def test_audit_fails_on_tampered_partition_attack_distribution(tmp_path: Path):
    """Verify protocol equivalence fails when attack category counts are altered."""
    m_data = _build_valid_runtime_manifest()
    m_data["partitions"]["train"]["attack_distribution"]["Exploits"] += 10
    m_path = tmp_path / "tampered.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["protocol_equivalence"] == "FAIL"
    assert any(
        "attack category distribution mismatch" in d for d in evidence["protocol_discrepancies"]
    )


def test_audit_missing_canonical_index_files_remains_not_verified(tmp_path: Path):
    """Verify membership equivalence remains strictly NOT_VERIFIED in absence of canonical files."""
    m_data = _build_valid_runtime_manifest()
    m_path = tmp_path / "valid.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    evidence = audit_split_membership_parity(m_path)
    assert evidence["status"]["membership_equivalence"] == "NOT_VERIFIED"
    assert (
        "Matching row counts and distributions do NOT constitute proof"
        in evidence["membership_rationale"]
    )


def test_audit_distinguishes_runtime_measured_from_declared_policy(tmp_path: Path):
    """Verify that absence of training manifest records NOT_EVALUATED for runtime behavior."""
    m_data = _build_valid_runtime_manifest()
    m_path = tmp_path / "valid.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")

    non_existent_training_manifest = tmp_path / "does_not_exist.json"
    evidence = audit_split_membership_parity(
        runtime_manifest_path=m_path,
        training_manifest_path=non_existent_training_manifest,
    )

    # Contract requirement remains defined
    contract = evidence["test_isolation"]["declared_policy_contract"]
    assert contract["test_partition_accessed"] is False
    assert contract["test_rows_loaded"] == 0

    # Measured evidence records NOT_EVALUATED
    measured = evidence["test_isolation"]["measured_runtime_evidence"]
    assert measured["status"] == "NOT_EVALUATED_IN_THIS_AUDIT"


def test_audit_cli_strict_membership_fails_on_not_verified(tmp_path: Path):
    """Verify CLI exit code is 1 when --strict-membership is set and membership is NOT_VERIFIED."""
    m_data = _build_valid_runtime_manifest()
    m_path = tmp_path / "valid.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")
    report_path = tmp_path / "report.md"

    rc = main(
        [
            "--runtime-manifest",
            str(m_path),
            "--output-report",
            str(report_path),
            "--strict-membership",
        ]
    )
    assert rc == 1


def test_audit_cli_fails_on_protocol_discrepancy(tmp_path: Path):
    """Verify CLI exit code is 1 when protocol equivalence fails."""
    m_data = _build_valid_runtime_manifest()
    m_data["dataset_name"] = "BAD-NAME"
    m_path = tmp_path / "bad.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")
    report_path = tmp_path / "report.md"

    rc = main(["--runtime-manifest", str(m_path), "--output-report", str(report_path)])
    assert rc == 1


def test_audit_cli_passes_on_valid_manifest_without_strict_membership(tmp_path: Path):
    """Verify CLI exit code is 0 when protocol is verified and strict membership is off."""
    m_data = _build_valid_runtime_manifest()
    m_path = tmp_path / "valid.json"
    m_path.write_text(json.dumps(m_data), encoding="utf-8")
    report_path = tmp_path / "report.md"

    rc = main(["--runtime-manifest", str(m_path), "--output-report", str(report_path)])
    assert rc == 0
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "Protocol Equivalence" in content
    assert "Membership Equivalence" in content
    assert "UNPROVEN_HYPOTHESIS" in content
