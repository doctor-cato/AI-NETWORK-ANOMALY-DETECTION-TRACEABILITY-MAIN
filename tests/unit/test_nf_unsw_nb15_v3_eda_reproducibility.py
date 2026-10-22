"""Synthetic-fixture tests for the EDA reproducibility evidence and comparison.

The fixtures are small synthetic CSVs. A PASS proves the behaviour of the
evidence and comparison code only; it is never evidence about the real dataset.
"""

import csv
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EDA_SCRIPT = REPOSITORY_ROOT / "scripts" / "eda_nf_unsw_nb15_v3.py"
REPRODUCIBILITY_SCRIPT = REPOSITORY_ROOT / "scripts" / "verify_eda_reproducibility.py"
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from network_anomaly.data.nf_unsw_nb15_v3 import ALL_COLUMNS  # noqa: E402
from network_anomaly.eda.evidence import (  # noqa: E402
    EXCLUDED_COMPARISON_PATHS,
    collect_differences,
    compare_evidence,
    compare_summaries,
)

CSV_FILE_NAME = "data/NF-UNSW-NB15-v3.csv"


def load_script(path: Path, name: str):
    """Load a repository script as a module for in-process testing."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_fixture(path: Path, rows: int = 12) -> Path:
    """Write a small synthetic CSV that follows the 55-column contract."""
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(ALL_COLUMNS))
        writer.writeheader()
        for index in range(rows):
            row = {column: "1" for column in ALL_COLUMNS}
            row.update(
                FLOW_START_MILLISECONDS=str(1421927376907 + index * 1000),
                FLOW_END_MILLISECONDS=str(1421927376907 + index * 1000 + 500),
                IPV4_SRC_ADDR="10.0.0.1",
                IPV4_DST_ADDR="10.0.0.2",
                L4_SRC_PORT="1234",
                L4_DST_PORT="80",
                PROTOCOL="6",
                L7_PROTO="0.0",
                IN_BYTES="1000",
                IN_PKTS="10",
                OUT_BYTES="2000",
                OUT_PKTS="20",
                FLOW_DURATION_MILLISECONDS="500",
                DURATION_IN="500",
                DURATION_OUT="500",
                SRC_TO_DST_SECOND_BYTES="2000",
                DST_TO_SRC_SECOND_BYTES="4000",
                SRC_TO_DST_AVG_THROUGHPUT="4000",
                DST_TO_SRC_AVG_THROUGHPUT="8000",
                Label="0",
                Attack="Benign",
            )
            if index % 4 == 1:
                row.update(
                    Label="1",
                    Attack="Worms",
                    FLOW_DURATION_MILLISECONDS="0",
                    DURATION_IN="0",
                    DURATION_OUT="0",
                    SRC_TO_DST_SECOND_BYTES="",
                    DST_TO_SRC_SECOND_BYTES="inf",
                )
            writer.writerow(row)
    return path


def write_manifest(path: Path, dataset: Path, rows: int) -> Path:
    """Write a synthetic manifest that pins the fixture bytes."""
    digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
    manifest = {
        "schema_version": 1,
        "dataset": "NF-UNSW-NB15-v3",
        "official_source": {"doi": "10.48610/6E0EDA1"},
        "files": [
            {
                "file": CSV_FILE_NAME,
                "role": "dataset",
                "size_bytes": dataset.stat().st_size,
                "sha256": digest,
                "expected_rows": rows,
            }
        ],
        "schema": {
            "feature_count": 53,
            "target_count": 2,
            "column_count": 55,
            "columns_in_order": list(ALL_COLUMNS),
            "binary_target": "Label",
            "multiclass_target": "Attack",
        },
    }
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def synthetic_dataset(tmp_path):
    """Return a synthetic dataset and a matching synthetic manifest."""
    dataset = write_fixture(tmp_path / "fixture.csv", rows=12)
    manifest = write_manifest(tmp_path / "manifest.json", dataset, rows=12)
    return dataset, manifest


def test_two_runs_produce_identical_summaries(synthetic_dataset, tmp_path):
    dataset, manifest = synthetic_dataset
    module = load_script(REPRODUCIBILITY_SCRIPT, "verify_eda_reproducibility")
    exit_code = module.main(
        [
            "--dataset",
            str(dataset),
            "--manifest",
            str(manifest),
            "--output-dir",
            str(tmp_path / "evidence"),
            "--figure-root",
            str(tmp_path / "figures"),
            "--sample-size",
            "6",
            "--chunk-size",
            "5",
        ]
    )
    assert exit_code == 0
    comparison = json.loads(
        (tmp_path / "evidence" / "reproducibility_comparison.json").read_text(encoding="utf-8")
    )
    assert comparison["overall"] == "PASS"
    assert comparison["summaries"]["overall"] == "PASS"
    assert comparison["evidence"]["overall"] == "PASS"
    assert comparison["summaries"]["differences"] == []
    for row in comparison["summaries"]["metrics"]:
        assert row["status"] == "PASS"
    assert (tmp_path / "evidence" / "reproducibility_comparison.md").is_file()
    report = (tmp_path / "evidence" / "reproducibility_comparison.md").read_text(encoding="utf-8")
    assert "Overall result: PASS" in report
    assert "Per-metric result on the deterministic summary content" in report


def test_each_run_bundle_is_retrievable(synthetic_dataset, tmp_path):
    dataset, manifest = synthetic_dataset
    module = load_script(REPRODUCIBILITY_SCRIPT, "verify_eda_reproducibility")
    assert (
        module.main(
            [
                "--dataset",
                str(dataset),
                "--manifest",
                str(manifest),
                "--output-dir",
                str(tmp_path / "evidence"),
                "--figure-root",
                str(tmp_path / "figures"),
                "--sample-size",
                "6",
                "--chunk-size",
                "5",
            ]
        )
        == 0
    )
    for label in ("run-1", "run-2"):
        bundle = tmp_path / "evidence" / label
        for name in (
            "eda_summary.json",
            "eda_report.md",
            "stdout.log",
            "stderr.log",
            "run_metadata.json",
        ):
            assert (bundle / name).is_file(), f"{label}/{name} is missing"
        metadata = json.loads((bundle / "run_metadata.json").read_text(encoding="utf-8"))
        for field in (
            "command",
            "exit_code",
            "started_at_utc",
            "finished_at_utc",
            "duration_seconds",
            "git",
            "environment",
            "dataset",
            "manifest_verification",
            "key_aggregates",
            "summary_artifact",
            "report_artifact",
        ):
            assert field in metadata, f"{label} metadata misses {field}"
        assert metadata["exit_code"] == 0
        assert metadata["dataset"]["sha256"]
        assert metadata["manifest_verification"]["sha256_matches"] is True
        assert metadata["manifest_verification"]["row_count_matches"] is True
        assert metadata["key_aggregates"]["rows"] == 12
        assert (
            metadata["summary_artifact"]["sha256"]
            == hashlib.sha256((bundle / "eda_summary.json").read_bytes()).hexdigest()
        )
        assert "EDA: COMPLETE" in (bundle / "stdout.log").read_text(encoding="utf-8")
        assert "ML_READY: BLOCKED" in (bundle / "stdout.log").read_text(encoding="utf-8")


def test_comparison_reports_a_deterministic_difference():
    left = {"rows": 10, "label_counts": {"0": 8, "1": 2}, "quantiles": {"IN_BYTES": {"p50": 5.0}}}
    right = {"rows": 10, "label_counts": {"0": 7, "1": 3}, "quantiles": {"IN_BYTES": {"p50": 5.0}}}
    comparison = compare_summaries(left, right)
    assert comparison["overall"] == "FAIL"
    statuses = {row["metric"]: row["status"] for row in comparison["metrics"]}
    assert statuses["label_counts"] == "FAIL"
    assert statuses["rows"] == "PASS"
    assert statuses["quantiles"] == "PASS"
    assert {item["path"] for item in comparison["differences"]} == {
        "label_counts.0",
        "label_counts.1",
    }


def test_comparison_ignores_the_allowed_metadata():
    left = {"rows": 10, "generated_at_utc": "2026-10-22T07:00:00+00:00"}
    right = {"rows": 10, "generated_at_utc": "2026-10-22T08:00:00+00:00"}
    assert compare_summaries(left, right)["overall"] == "PASS"
    assert "generated_at_utc" in EXCLUDED_COMPARISON_PATHS
    assert collect_differences(left, right) == []


def test_evidence_comparison_ignores_timestamps_and_labels():
    left = {
        "label": "run-1",
        "started_at_utc": "2026-10-22T07:00:00+00:00",
        "finished_at_utc": "2026-10-22T07:01:00+00:00",
        "duration_seconds": 60.0,
        "command": "python scripts/eda_nf_unsw_nb15_v3.py",
        "exit_code": 0,
        "git": {"head": "abc"},
        "dataset": {"sha256": "d" * 64},
    }
    right = dict(left)
    right.update(
        {
            "label": "run-2",
            "started_at_utc": "2026-10-22T08:00:00+00:00",
            "finished_at_utc": "2026-10-22T08:01:00+00:00",
            "duration_seconds": 61.0,
        }
    )
    comparison = compare_evidence(left, right)
    assert comparison["overall"] == "PASS"
    assert comparison["differences"] == []
    right["dataset"] = {"sha256": "e" * 64}
    assert compare_evidence(left, right)["overall"] == "FAIL"


def test_evidence_bundle_records_the_key_aggregates(synthetic_dataset, tmp_path):
    dataset, manifest = synthetic_dataset
    module = load_script(REPRODUCIBILITY_SCRIPT, "verify_eda_reproducibility")
    assert (
        module.main(
            [
                "--dataset",
                str(dataset),
                "--manifest",
                str(manifest),
                "--output-dir",
                str(tmp_path / "evidence"),
                "--figure-root",
                str(tmp_path / "figures"),
                "--sample-size",
                "6",
                "--chunk-size",
                "5",
            ]
        )
        == 0
    )
    metadata = json.loads(
        (tmp_path / "evidence" / "run-1" / "run_metadata.json").read_text(encoding="utf-8")
    )
    aggregates = metadata["key_aggregates"]
    assert aggregates["rows"] == 12
    assert aggregates["label_counts"]["0"] == 9
    assert aggregates["label_counts"]["1"] == 3
    assert aggregates["duplicates"]["exact_full_row"]["duplicate_rows"] == 0
    assert "SRC_TO_DST_SECOND_BYTES" in aggregates["non_finite_by_column"]
    assert aggregates["readiness"]["ML_READY"] == "BLOCKED"
    assert aggregates["leakage_boundary"]["target_columns_in_baseline_x"] is False
    assert metadata["environment"]["python_version"]
    assert metadata["git"]["head"]


def test_reproducibility_check_is_skipped_without_raw_data(tmp_path, capsys):
    module = load_script(REPRODUCIBILITY_SCRIPT, "verify_eda_reproducibility")
    exit_code = module.main(
        [
            "--dataset",
            str(tmp_path / "absent.csv"),
            "--output-dir",
            str(tmp_path / "evidence"),
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 2
    assert "SKIPPED" in output
    assert not (tmp_path / "evidence" / "reproducibility_comparison.json").exists()


def test_eda_script_remains_usable_for_a_single_run(synthetic_dataset, tmp_path):
    dataset, manifest = synthetic_dataset
    module = load_script(EDA_SCRIPT, "eda_nf_unsw_nb15_v3")
    exit_code = module.main(
        [
            "--dataset",
            str(dataset),
            "--manifest",
            str(manifest),
            "--summary",
            str(tmp_path / "summary.json"),
            "--report",
            str(tmp_path / "report.md"),
            "--figures",
            str(tmp_path / "figures"),
            "--sample-size",
            "6",
            "--chunk-size",
            "5",
        ]
    )
    assert exit_code == 0
    document = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert document["rows"] == 12
    assert document["readiness"]["ML_READY"] == "BLOCKED"
