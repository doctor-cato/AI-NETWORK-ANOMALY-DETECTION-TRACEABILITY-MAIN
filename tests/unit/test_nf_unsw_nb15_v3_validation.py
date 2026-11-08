"""Synthetic validator fixtures; a PASS here is not real-data validation evidence."""

import csv
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_data.py"
MANIFEST = ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json"


@pytest.fixture
def validator():
    spec = importlib.util.spec_from_file_location("validate_nf_unsw_v3", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def contract(validator):
    _manifest, columns, _entry = validator.load_contract(MANIFEST)
    return columns


def valid_row(columns, **changes):
    values = {column: "0" for column in columns}
    values.update(
        {
            "FLOW_START_MILLISECONDS": "1000",
            "FLOW_END_MILLISECONDS": "1002",
            "FLOW_DURATION_MILLISECONDS": "2",
            "IPV4_SRC_ADDR": "192.0.2.1",
            "L4_SRC_PORT": "12345",
            "IPV4_DST_ADDR": "198.51.100.2",
            "L4_DST_PORT": "443",
            "Label": "0",
            "Attack": "Benign",
        }
    )
    values.update(changes)
    return [values[column] for column in columns]


def write_csv(path, columns, rows, header=None):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(columns if header is None else header)
        writer.writerows(rows)


def test_valid_synthetic_csv_has_no_quality_findings(validator, contract, tmp_path):
    dataset = tmp_path / "valid.csv"
    write_csv(dataset, contract, [valid_row(contract)])

    report = validator.validate_csv(dataset, contract, 1, tmp_path)

    assert report["rows"] == 1
    assert report["issue_counts"] == {}


def test_status_semantics_separate_integrity_quality_and_ml_readiness(validator):
    status = validator.classify_dataset_status(
        {
            "missing:IN_BYTES": 2,
            "exact_duplicate_rows": 1,
            "invalid_label": 3,
        }
    )

    assert status["SOURCE_INTEGRITY"] == "FAIL"
    assert status["RAW_QUALITY"] == "FINDINGS_RECORDED"
    assert status["ML_READY"] == "BLOCKED"
    assert status["source_integrity_issues"] == {"invalid_label": 3}
    assert status["raw_quality_findings"] == {
        "missing:IN_BYTES": 2,
        "exact_duplicate_rows": 1,
    }


def test_clean_raw_status_still_does_not_claim_ml_readiness(validator):
    status = validator.classify_dataset_status({})

    assert status["SOURCE_INTEGRITY"] == "PASS"
    assert status["RAW_QUALITY"] == "PASS"
    assert status["ML_READY"] == "BLOCKED"


@pytest.mark.parametrize(
    ("changes", "issue"),
    [
        ({"Label": "2", "Attack": "Benign"}, "invalid_label"),
        ({"Label": "1", "Attack": "Benign"}, "label_attack_inconsistent"),
        ({"Label": "1", "Attack": "Unknown"}, "invalid_attack"),
        ({"FLOW_START_MILLISECONDS": "not-time"}, "invalid_numeric:FLOW_START_MILLISECONDS"),
        ({"FLOW_END_MILLISECONDS": "999"}, "end_before_start"),
        ({"L4_SRC_PORT": "70000"}, "invalid_port:L4_SRC_PORT"),
        ({"IPV4_SRC_ADDR": "not-an-ip"}, "invalid_ip:IPV4_SRC_ADDR"),
        ({"IN_BYTES": ""}, "missing:IN_BYTES"),
        ({"IN_BYTES": "inf"}, "positive_infinity:IN_BYTES"),
        ({"IN_BYTES": "-inf"}, "negative_infinity:IN_BYTES"),
        ({"IN_BYTES": "nan"}, "nan:IN_BYTES"),
        ({"IN_BYTES": "not-a-number"}, "invalid_numeric:IN_BYTES"),
        ({"IN_BYTES": "-1"}, "negative:IN_BYTES"),
    ],
)
def test_invalid_values_are_reported(validator, contract, tmp_path, changes, issue):
    dataset = tmp_path / "invalid.csv"
    write_csv(dataset, contract, [valid_row(contract, **changes)])

    report = validator.validate_csv(dataset, contract, 1, tmp_path)

    assert report["issue_counts"][issue] == 1
    assert report["example_line_numbers"][issue] == [2]


def test_schema_order_and_missing_column_are_rejected(validator, contract, tmp_path):
    dataset = tmp_path / "bad-schema.csv"
    write_csv(dataset, contract, [], header=contract[:-1])

    with pytest.raises(ValueError, match="schema or column ordering"):
        validator.validate_csv(dataset, contract, 0, tmp_path)


def test_wrong_width_is_reported(validator, contract, tmp_path):
    dataset = tmp_path / "wrong-width.csv"
    write_csv(dataset, contract, [valid_row(contract)[:-1]])

    report = validator.validate_csv(dataset, contract, 1, tmp_path)

    assert report["issue_counts"]["wrong_width"] == 1


def test_numeric_quality_aggregates_unique_rows_overlap_and_context(validator, contract, tmp_path):
    dataset = tmp_path / "quality.csv"
    rows = [
        valid_row(
            contract,
            SRC_TO_DST_SECOND_BYTES="",
            DST_TO_SRC_SECOND_BYTES="inf",
            FLOW_DURATION_MILLISECONDS="0",
            DURATION_IN="0",
            DURATION_OUT="1",
            IN_PKTS="0",
            OUT_PKTS="2",
            IN_BYTES="0",
            OUT_BYTES="10",
            PROTOCOL="6",
            Label="0",
            Attack="Benign",
        ),
        valid_row(
            contract,
            SRC_TO_DST_SECOND_BYTES="inf",
            FLOW_DURATION_MILLISECONDS="2",
            DURATION_IN="0.5",
            DURATION_OUT="2",
            PROTOCOL="17",
            Label="1",
            Attack="Analysis",
        ),
    ]
    write_csv(dataset, contract, rows)

    report = validator.validate_csv(dataset, contract, 2, tmp_path)
    analysis = report["numeric_quality_analysis"]

    assert analysis["affected_unique_rows"] == 2
    assert analysis["rows_with_one_finding"] == 1
    assert analysis["rows_with_multiple_findings"] == 1
    assert analysis["finding_type_counts"] == {
        "invalid_numeric": 0,
        "missing": 1,
        "nan": 0,
        "negative_infinity": 0,
        "positive_infinity": 2,
    }
    assert analysis["overlap_patterns"] == {
        "missing:SRC_TO_DST_SECOND_BYTES | positive_infinity:DST_TO_SRC_SECOND_BYTES": 1,
        "positive_infinity:SRC_TO_DST_SECOND_BYTES": 1,
    }
    destination = analysis["findings"]["positive_infinity:DST_TO_SRC_SECOND_BYTES"]
    assert destination["labels"] == {"0": 1}
    assert destination["attacks"] == {"Benign": 1}
    assert destination["protocols"] == {"6": 1}
    assert destination["duration_buckets"]["FLOW_DURATION_MILLISECONDS"] == {"zero": 1}
    assert destination["related_numeric_states"]["OUT_PKTS"] == {"positive": 1}


def test_duplicate_fingerprints_and_label_conflicts_are_disk_backed(validator, contract, tmp_path):
    first = valid_row(contract)
    exact = list(first)
    near = valid_row(
        contract,
        FLOW_START_MILLISECONDS="2000",
        FLOW_END_MILLISECONDS="2002",
        IPV4_SRC_ADDR="203.0.113.7",
        L4_SRC_PORT="23456",
    )
    conflict = valid_row(
        contract,
        FLOW_START_MILLISECONDS="3000",
        FLOW_END_MILLISECONDS="3002",
        IPV4_SRC_ADDR="198.51.100.77",
        L4_SRC_PORT="34567",
        Label="1",
        Attack="Worms",
    )
    malicious_analysis = valid_row(
        contract,
        FLOW_START_MILLISECONDS="4000",
        FLOW_END_MILLISECONDS="4002",
        IPV4_SRC_ADDR="203.0.113.20",
        L4_SRC_PORT="45678",
        IN_BYTES="9",
        Label="1",
        Attack="Analysis",
    )
    malicious_worms = valid_row(
        contract,
        FLOW_START_MILLISECONDS="5000",
        FLOW_END_MILLISECONDS="5002",
        IPV4_SRC_ADDR="203.0.113.21",
        L4_SRC_PORT="45679",
        IN_BYTES="9",
        Label="1",
        Attack="Worms",
    )
    dataset = tmp_path / "duplicates.csv"
    write_csv(
        dataset,
        [*contract],
        [first, exact, near, conflict, malicious_analysis, malicious_worms],
    )

    report = validator.validate_csv(dataset, contract, 6, tmp_path)

    assert report["issue_counts"]["exact_duplicate_rows"] == 1
    assert report["issue_counts"]["ml_feature_equivalent_duplicate_rows"] == 4
    assert report["issue_counts"]["behavioral_fingerprint_duplicate_rows"] == 4
    duplicate = report["duplicate_analysis"]
    assert duplicate["schema_version"] == "nf-unsw-nb15-v3-fingerprint-v1"
    assert duplicate["exact"]["duplicate_rows_by_label"] == {"0": 1}
    assert duplicate["ml_feature_equivalent"]["label_conflict_fingerprints"] == 1
    assert duplicate["ml_feature_equivalent"]["rows_in_label_conflict_fingerprints"] == 4
    assert duplicate["ml_feature_equivalent"]["benign_attack_conflict_fingerprints"] == 1
    assert duplicate["ml_feature_equivalent"]["multiple_attack_values_fingerprints"] == 2
    assert duplicate["ml_feature_equivalent"]["multiple_malicious_categories_fingerprints"] == 1
    assert duplicate["ml_feature_equivalent"]["attack_value_conflict_patterns"] == {
        "Benign | Worms": {"fingerprints": 1, "rows": 4},
        "Analysis | Worms": {"fingerprints": 1, "rows": 2},
    }
    assert duplicate["ml_feature_equivalent"]["rare_category_label_conflicts"]["Worms"] == {
        "fingerprints": 1,
        "rows": 4,
    }
    assert duplicate["ml_feature_equivalent"]["rare_category_multi_attack_fingerprints"] == {
        "Analysis": {"fingerprints": 1, "rows": 2},
        "Worms": {"fingerprints": 2, "rows": 6},
    }
    assert duplicate["behavioral_v1"]["automatic_removal_permitted"] is False
    assert duplicate["hypothetical_exact_dedup_keep_first"]["retained_by_label"] == {
        "0": 2,
        "1": 3,
    }
    assert duplicate["hypothetical_exact_dedup_keep_first"]["applied"] is False
    assert not list(tmp_path.glob("nf-unsw-v3-duplicates-*.sqlite3"))


def test_row_count_mismatch_is_reported(validator, contract, tmp_path):
    dataset = tmp_path / "count.csv"
    write_csv(dataset, contract, [valid_row(contract)])

    report = validator.validate_csv(dataset, contract, 2, tmp_path)

    assert report["issue_counts"]["row_count_mismatch"] == 1


def test_validation_does_not_mutate_source_csv(validator, contract, tmp_path):
    dataset = tmp_path / "immutable.csv"
    write_csv(dataset, contract, [valid_row(contract, IN_BYTES="inf")])
    before = hashlib.sha256(dataset.read_bytes()).hexdigest()

    validator.validate_csv(dataset, contract, 1, tmp_path)

    after = hashlib.sha256(dataset.read_bytes()).hexdigest()
    assert after == before


def test_default_absent_is_skipped_but_ml_ready_remains_blocked(
    validator, monkeypatch, tmp_path, capsys
):
    missing = tmp_path / "missing.csv"
    monkeypatch.setattr(validator, "DATASET_PATH", missing)

    assert validator.main([]) == 0
    output = capsys.readouterr().out
    assert "SOURCE_INTEGRITY: SKIPPED" in output
    assert "RAW_QUALITY: NOT VERIFIED" in output
    assert "ML_READY: BLOCKED" in output


def test_corrupt_explicit_dataset_uses_integrity_failure_exit_code(validator, tmp_path, capsys):
    dataset = tmp_path / "corrupt.csv"
    dataset.write_bytes(b"not-the-pinned-dataset")

    assert validator.main(["--dataset", str(dataset)]) == 2
    output = capsys.readouterr().out
    assert "SOURCE_INTEGRITY: FAIL" in output
    assert "RAW_QUALITY: NOT EVALUATED" in output
    assert "ML_READY: BLOCKED" in output


def test_manifest_dataset_hash_verification_detects_tamper(validator, tmp_path):
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entry = next(item for item in payload["files"] if item.get("role") == "dataset")
    dataset = tmp_path / "dataset.csv"
    dataset.write_bytes(b"tampered")

    with pytest.raises(ValueError, match="size mismatch"):
        validator.verify_dataset_bytes(dataset, entry)


def test_report_cannot_overwrite_dataset_or_manifest(validator, tmp_path):
    dataset = tmp_path / "dataset.csv"
    dataset.touch()

    with pytest.raises(ValueError, match="must not overwrite"):
        validator.refuse_unsafe_report(dataset, (dataset, MANIFEST))


def test_atomic_report_replaces_previous_report(validator, tmp_path):
    report = tmp_path / "report.json"
    report.write_text("old", encoding="utf-8")

    validator.write_report(report, {"status": "PASS"})

    assert json.loads(report.read_text(encoding="utf-8")) == {"status": "PASS"}
    assert not list(tmp_path.glob("*.partial"))
