"""Unit tests for Manifest Provenance Reconciliation (Issue #55).

Verifies:
1. Historical artifact manifest preservation in reports/models/random_forest_manifest.json.
2. Dynamic Hash-Chain Verification in scripts/train_random_forest.py avoiding false-positive
   static hash mismatches on dynamic metadata.
3. Fail-closed validation on semantic, structural, and cryptographic prerequisite failures.
4. Parity and consistency of canonical pins between train_random_forest.py and train_xgboost.py.
5. Exit code and error reporting of --verify-only CLI execution.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from network_anomaly.config import PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.data.split import SPLIT_MANIFEST_SCHEMA_VERSION
from network_anomaly.preprocessing import FEATURE_CONTRACT_VERSION
from network_anomaly.preprocessing.pipeline import EXPECTED_DATASET_SHA256
from scripts.train_random_forest import (
    EXPECTED_TEST_ROWS,
    EXPECTED_TRAIN_ROWS,
    EXPECTED_VAL_ROWS,
    check_prerequisites,
)

# =========================================================================
# 1. Historical Manifest Evidence Preservation Tests
# =========================================================================


def test_random_forest_historical_manifest_preservation():
    """Verify that reports/models/random_forest_manifest.json preserves original run provenance."""
    rf_manifest_path = PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
    assert rf_manifest_path.is_file(), "Historical Random Forest manifest file must exist!"

    manifest = json.loads(rf_manifest_path.read_text(encoding="utf-8"))

    # Pinned run provenance
    assert manifest["run_id"] == "rf-baseline-1794068628"
    assert manifest["model_type"] == "RandomForest"
    assert manifest["task"] == "binary_classification"
    assert manifest["target"] == "Label"
    assert manifest["positive_class"] == "Attack"
    assert manifest["class_mapping"] == {"0": "Benign", "1": "Attack"}
    assert manifest["feature_contract_version"] == FEATURE_CONTRACT_VERSION
    assert len(manifest["selected_features"]) == len(ML_FEATURE_COLUMNS)
    assert manifest["selected_features"] == list(ML_FEATURE_COLUMNS)

    # Immutable dataset hash pin
    assert manifest["dataset_sha256"] == EXPECTED_DATASET_SHA256

    # Historical hash references must be intact and authentic
    assert "split_manifest_sha256" in manifest
    assert "preprocessor_artifact_sha256" in manifest
    assert "preprocessor_manifest_sha256" in manifest
    assert manifest["provenance_status"] == "VERIFIED"


# =========================================================================
# 2. Dynamic Hash-Chain Verification Tests
# =========================================================================


def test_train_rf_prerequisites_no_spurious_manifest_mismatches(tmp_path: Path):
    """Verify that check_prerequisites does not report false mismatches for updated manifests."""
    split_manifest_path = (
        PROJECT_ROOT / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
    )
    preprocessor_manifest_path = (
        PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )
    non_existent_csv = tmp_path / "non_existent.csv"
    non_existent_indices = tmp_path / "splits"
    non_existent_prep = tmp_path / "preprocessor.joblib"

    audit = check_prerequisites(
        dataset_path=non_existent_csv,
        split_manifest_path=split_manifest_path,
        indices_dir=non_existent_indices,
        preprocessor_artifact_path=non_existent_prep,
        preprocessor_manifest_path=preprocessor_manifest_path,
    )

    assert audit["status"] == "BLOCKED"
    missing = audit["missing_prerequisites"]

    # Must NOT report static hash mismatch on existing split or preprocessor manifest
    for msg in missing:
        assert "Split manifest SHA-256 mismatch" not in msg
        assert "Preprocessor companion manifest SHA-256 mismatch" not in msg
        assert "Preprocessor manifest artifact SHA-256 mismatch" not in msg

    # Split manifest structure itself must PASS audit
    sm_finding = audit["findings"].get("split_manifest", {})
    assert sm_finding.get("status") == "PASS"


def test_train_rf_prerequisites_fails_on_corrupt_split_manifest(tmp_path: Path):
    """Verify check_prerequisites fails closed when split manifest has invalid dataset SHA-256."""
    corrupt_split_manifest = tmp_path / "corrupt_split_manifest.json"
    valid_split_manifest = (
        PROJECT_ROOT / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
    )
    sm_data = json.loads(valid_split_manifest.read_text(encoding="utf-8"))

    # Corrupt dataset hash
    sm_data["dataset_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
    corrupt_split_manifest.write_text(json.dumps(sm_data), encoding="utf-8")

    preprocessor_manifest_path = (
        PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )

    audit = check_prerequisites(
        dataset_path=tmp_path / "missing.csv",
        split_manifest_path=corrupt_split_manifest,
        indices_dir=tmp_path / "splits",
        preprocessor_artifact_path=tmp_path / "missing.joblib",
        preprocessor_manifest_path=preprocessor_manifest_path,
    )

    assert audit["status"] == "BLOCKED"
    missing_msgs = " ".join(audit["missing_prerequisites"])
    assert "Split manifest dataset_sha256 does not match" in missing_msgs


def test_train_rf_prerequisites_fails_on_corrupt_manifest_schema(tmp_path: Path):
    """Verify check_prerequisites fails closed when split manifest schema version is wrong."""
    corrupt_split_manifest = tmp_path / "wrong_schema_split_manifest.json"
    valid_split_manifest = (
        PROJECT_ROOT / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
    )
    sm_data = json.loads(valid_split_manifest.read_text(encoding="utf-8"))
    sm_data["manifest_schema_version"] = 999
    corrupt_split_manifest.write_text(json.dumps(sm_data), encoding="utf-8")

    audit = check_prerequisites(
        dataset_path=tmp_path / "missing.csv",
        split_manifest_path=corrupt_split_manifest,
        indices_dir=tmp_path / "splits",
        preprocessor_artifact_path=tmp_path / "missing.joblib",
        preprocessor_manifest_path=PROJECT_ROOT
        / "reports"
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessing_manifest.json",
    )

    missing_msgs = " ".join(audit["missing_prerequisites"])
    assert f"manifest_schema_version must be {SPLIT_MANIFEST_SCHEMA_VERSION}" in missing_msgs


def test_train_rf_prerequisites_fails_on_corrupt_audit_status(tmp_path: Path):
    """Verify check_prerequisites fails closed when split leakage audit is not PASS."""
    corrupt_split_manifest = tmp_path / "leakage_failed_split_manifest.json"
    valid_split_manifest = (
        PROJECT_ROOT / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
    )
    sm_data = json.loads(valid_split_manifest.read_text(encoding="utf-8"))
    sm_data["audit_summary"]["status"] = "FAIL"
    corrupt_split_manifest.write_text(json.dumps(sm_data), encoding="utf-8")

    audit = check_prerequisites(
        dataset_path=tmp_path / "missing.csv",
        split_manifest_path=corrupt_split_manifest,
        indices_dir=tmp_path / "splits",
        preprocessor_artifact_path=tmp_path / "missing.joblib",
        preprocessor_manifest_path=PROJECT_ROOT
        / "reports"
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessing_manifest.json",
    )

    missing_msgs = " ".join(audit["missing_prerequisites"])
    assert "leakage audit_summary.status is not 'PASS'" in missing_msgs


# =========================================================================
# 3. Canonical Parity Between RF and XGBoost
# =========================================================================


def test_canonical_pins_parity():
    """Verify that train_random_forest.py and train_xgboost.py share identical canonical pins."""
    import scripts.train_xgboost as train_xgb

    assert EXPECTED_TRAIN_ROWS == train_xgb.EXPECTED_TRAIN_ROWS == 1655797
    assert EXPECTED_VAL_ROWS == train_xgb.EXPECTED_VAL_ROWS == 345371
    assert EXPECTED_TEST_ROWS == train_xgb.EXPECTED_TEST_ROWS == 345953
    assert EXPECTED_DATASET_SHA256 == train_xgb.EXPECTED_DATASET_SHA256

    # Verify both scripts share identical canonical pins
    import scripts.train_random_forest as train_rf

    assert train_rf.EXPECTED_DATASET_SHA256 == train_xgb.EXPECTED_DATASET_SHA256
    assert train_rf.EXPECTED_TRAIN_ROWS == train_xgb.EXPECTED_TRAIN_ROWS
    assert train_rf.EXPECTED_VAL_ROWS == train_xgb.EXPECTED_VAL_ROWS
    assert train_rf.EXPECTED_TEST_ROWS == train_xgb.EXPECTED_TEST_ROWS


# =========================================================================
# 4. CLI --verify-only Execution Tests
# =========================================================================


def test_train_rf_verify_only_cli_execution():
    """Verify train_random_forest.py --verify-only fails closed on missing data only."""
    res = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "train_random_forest.py"), "--verify-only"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )

    # Must exit with code 1 due to missing raw binary data (Issue #10 fail-closed rule)
    assert res.returncode == 1
    assert "[BLOCKER DETECTED] Prerequisite verification failed!" in res.stdout

    # Must identify missing raw files
    assert "Raw dataset CSV not found" in res.stdout
    assert "Train partition indices not found" in res.stdout
    assert "Validation partition indices not found" in res.stdout
    assert "Preprocessor artifact not found" in res.stdout

    # Must NOT report static hash mismatch for split manifest or preprocessor manifest
    assert "Split manifest SHA-256 mismatch" not in res.stdout
    assert "Preprocessor companion manifest SHA-256 mismatch" not in res.stdout
    assert "Preprocessor manifest artifact SHA-256 mismatch" not in res.stdout
