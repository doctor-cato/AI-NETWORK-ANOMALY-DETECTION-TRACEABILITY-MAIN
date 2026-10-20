"""Synthetic validator fixtures; a PASS here is not real-data validation evidence."""

import csv
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
        ({"IN_BYTES": "inf"}, "non_finite:IN_BYTES"),
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


def test_duplicate_and_near_duplicate_are_disk_backed(validator, contract, tmp_path):
    first = valid_row(contract)
    exact = list(first)
    near = valid_row(
        contract,
        FLOW_START_MILLISECONDS="2000",
        FLOW_END_MILLISECONDS="2002",
        IPV4_SRC_ADDR="203.0.113.7",
        L4_SRC_PORT="23456",
    )
    dataset = tmp_path / "duplicates.csv"
    write_csv(dataset, contract, [first, exact, near])

    report = validator.validate_csv(dataset, contract, 3, tmp_path)

    assert report["issue_counts"]["exact_duplicate_rows"] == 1
    assert report["issue_counts"]["near_duplicate_rows"] == 2
    assert not list(tmp_path.glob("nf-unsw-v3-duplicates-*.sqlite3"))


def test_row_count_mismatch_is_reported(validator, contract, tmp_path):
    dataset = tmp_path / "count.csv"
    write_csv(dataset, contract, [valid_row(contract)])

    report = validator.validate_csv(dataset, contract, 2, tmp_path)

    assert report["issue_counts"]["row_count_mismatch"] == 1


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
