"""Synthetic-fixture tests for the NF-UNSW-NB15-v3 exploratory analysis.

Every fixture here is a small synthetic CSV. A PASS proves the behaviour of the
EDA code only; it is never evidence about the real dataset.
"""

import csv
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "eda_nf_unsw_nb15_v3.py"
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    ALL_COLUMNS,
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
    validate_semantic_column_roles,
)
from network_anomaly.eda import (  # noqa: E402
    DatasetProfiler,
    render_figures,
    render_report,
)


def load_script_module():
    """Load the EDA CLI script as a module for in-process testing."""
    spec = importlib.util.spec_from_file_location("eda_nf_unsw_nb15_v3", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def base_row(index, **changes):
    """Return one synthetic row that follows the 55-column contract."""
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
    row.update(changes)
    return row


def write_fixture(path, rows):
    """Write the synthetic rows as a CSV that follows the published column order."""
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(ALL_COLUMNS))
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture
def fixture_csv(tmp_path):
    """A synthetic dataset that contains every quality case the EDA must separate."""
    rows = []
    for index in range(30):
        row = base_row(index)
        if index == 1:
            row.update(
                Label="1",
                Attack="Worms",
                FLOW_DURATION_MILLISECONDS="0",
                DURATION_IN="0",
                DURATION_OUT="0",
                SRC_TO_DST_SECOND_BYTES="",
                DST_TO_SRC_SECOND_BYTES="inf",
                SRC_TO_DST_AVG_THROUGHPUT="inf",
                DST_TO_SRC_AVG_THROUGHPUT="inf",
            )
        if index == 2:
            row.update(SRC_TO_DST_SECOND_BYTES="nan", DST_TO_SRC_SECOND_BYTES="-inf")
        if index == 3:
            row.update(Label="1", Attack="DoS", IN_BYTES="not-a-number")
        if index == 4:
            row.update(Label="1", Attack="Fuzzers", IN_BYTES="5000")
        rows.append(row)
    rows.append(dict(rows[0]))
    rows.append(dict(rows[6]))
    return write_fixture(tmp_path / "fixture.csv", rows)


def test_contract_roles_cover_the_baseline_exactly():
    assert validate_semantic_column_roles() is True
    assert len(ML_FEATURE_COLUMNS) == 47
    assert len(QUANTITATIVE_ML_COLUMNS) + len(CATEGORICAL_CODED_COLUMNS) == 47
    assert not set(TARGET_COLUMNS) & set(ML_FEATURE_COLUMNS)
    assert not set(TRACE_METADATA_COLUMNS) & set(ML_FEATURE_COLUMNS)
    validate_feature_selection(ML_FEATURE_COLUMNS)


def test_profile_counts_rows_labels_and_categories(fixture_csv):
    profiler = DatasetProfiler(columns=ALL_COLUMNS, expected_rows=32, chunk_size=8, sample_size=16)
    summary = profiler.profile(fixture_csv)
    assert summary["rows"] == 32
    assert summary["row_count_matches_manifest"] is True
    assert summary["label_counts"] == {"0": 29, "1": 3}
    assert summary["attack_counts"]["Worms"] == 1
    assert summary["attack_counts"]["Benign"] == 29


def test_profile_separates_token_classes(fixture_csv):
    profiler = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16)
    summary = profiler.profile(fixture_csv)
    rate = summary["numeric_statistics"]["SRC_TO_DST_SECOND_BYTES"]["token_counts"]
    assert rate["blank"] == 1
    assert rate["nan_literal"] == 1
    assert rate["positive_infinity"] == 0
    assert rate["invalid_numeric"] == 0
    throughput = summary["numeric_statistics"]["DST_TO_SRC_SECOND_BYTES"]["token_counts"]
    assert throughput["positive_infinity"] == 1
    assert throughput["negative_infinity"] == 1
    invalid = summary["numeric_statistics"]["IN_BYTES"]["token_counts"]["invalid_numeric"]
    assert invalid == 1


def test_profile_reports_zero_duration_and_non_finite_association(fixture_csv):
    profiler = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16)
    summary = profiler.profile(fixture_csv)
    population = summary["duration_throughput"]["population"]
    assert population["duration_zero=True,rate_non_finite=True,throughput_non_finite=True"] == 1
    assert population["duration_zero=False,rate_non_finite=True,throughput_non_finite=False"] == 1
    assert population["duration_zero=False,rate_non_finite=False,throughput_non_finite=False"] == 30
    assert summary["duration_throughput"]["rate_columns"] == [
        "SRC_TO_DST_SECOND_BYTES",
        "DST_TO_SRC_SECOND_BYTES",
    ]


def test_profile_detects_duplicates_without_removing_rows(fixture_csv):
    profiler = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16)
    summary = profiler.profile(fixture_csv)
    duplicates = summary["duplicates"]
    assert duplicates["exact_full_row"]["duplicate_rows"] == 2
    assert duplicates["ml_feature_equivalent"]["duplicate_rows"] >= 2
    assert duplicates["automatic_removal_permitted"] is False
    assert summary["rows"] == 32


def test_profile_is_deterministic_across_chunk_sizes(fixture_csv):
    first = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16, seed=42)
    second = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=5, sample_size=16, seed=42)
    summary_first = first.profile(fixture_csv)
    summary_second = second.profile(fixture_csv)
    for key in ("rows", "label_counts", "attack_counts", "quantiles", "duplicates"):
        assert summary_first[key] == summary_second[key]
    assert summary_first["sample_statistics"] == summary_second["sample_statistics"]
    for column, values in summary_first["numeric_statistics"].items():
        other = summary_second["numeric_statistics"][column]
        for key in ("finite_count", "zero_count", "unavailable_count", "token_counts"):
            assert values[key] == other[key]
        assert values["mean"] == pytest.approx(other["mean"], rel=1e-9, abs=1e-9)


def test_quantiles_match_an_explicit_population_computation(fixture_csv):
    profiler = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16)
    summary = profiler.profile(fixture_csv)
    with fixture_csv.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        values = sorted(
            float(row["IN_BYTES"]) for row in reader if row["IN_BYTES"] != "not-a-number"
        )
    import numpy as np

    expected = np.quantile(np.array(values, dtype="float64"), [0.25, 0.5, 0.75])
    assert summary["quantiles"]["IN_BYTES"]["p25"] == pytest.approx(float(expected[0]))
    assert summary["quantiles"]["IN_BYTES"]["p50"] == pytest.approx(float(expected[1]))
    assert summary["quantiles"]["IN_BYTES"]["p75"] == pytest.approx(float(expected[2]))


def test_sample_is_seeded_and_reported(fixture_csv):
    profiler = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16, seed=7)
    summary = profiler.profile(fixture_csv)
    assert summary["sample"]["seed"] == 7
    assert summary["sample"]["size"] == 16
    assert summary["sample"]["method"].startswith("reservoir sampling")
    assert "IPV4_SRC_ADDR" not in summary["sample"]["columns"]


def test_correlation_matrix_is_square_and_bounded(fixture_csv):
    profiler = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16)
    summary = profiler.profile(fixture_csv)
    payload = summary["correlations"]["pearson_complete_cases"]
    assert len(payload["columns"]) == len(QUANTITATIVE_ML_COLUMNS)
    assert len(payload["matrix"]) == len(payload["columns"])
    for row in payload["matrix"]:
        for value in row:
            if value is not None:
                assert -1.0001 <= value <= 1.0001
    for column in CATEGORICAL_CODED_COLUMNS:
        assert column not in payload["columns"]


def test_figures_render_in_a_headless_environment(fixture_csv, tmp_path):
    os.environ.setdefault("MPLBACKEND", "Agg")
    profiler = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16)
    summary = profiler.profile(fixture_csv)
    figures = render_figures(summary, profiler.sample, tmp_path / "figures")
    assert len(figures) == 12
    for figure in figures:
        path = tmp_path / "figures" / figure["file"]
        assert path.is_file()
        assert path.stat().st_size > 0
        assert figure["caption"]
        assert figure["evidence"]


def test_report_contains_the_required_sections(fixture_csv, tmp_path):
    profiler = DatasetProfiler(columns=ALL_COLUMNS, chunk_size=8, sample_size=16)
    summary = profiler.profile(fixture_csv)
    figures = render_figures(summary, profiler.sample, tmp_path / "figures")
    context = {
        "dataset": {
            "path": "data/raw/fixture.csv",
            "sha256": "0" * 64,
            "size_bytes": 1,
            "manifest": "data/NF_UNSW_NB15_V3_MANIFEST.json",
        },
        "readiness": {
            "SOURCE_INTEGRITY": "PASS",
            "RAW_QUALITY": "FINDINGS_RECORDED",
            "ML_READY": "BLOCKED",
            "ml_readiness_blockers": ["real split and leakage audit are NOT VERIFIED"],
        },
        "leakage_boundary": {
            "split_manifest": {
                "present": False,
                "path": "data/processed/split.json",
                "status": "PENDING ISSUE #7",
                "detail": "No verified split manifest exists.",
            },
            "permitted_now": ["profiling"],
            "not_permitted_now": ["selecting features"],
            "train_dependent_recommendations": "PENDING ISSUE #7",
            "target_columns_in_baseline_x": False,
            "metadata_columns_in_baseline_x": False,
        },
        "evidence_basis": {
            "inherited_rows": 32,
            "recomputed_rows": 32,
            "rows_agreement": "MATCH",
            "inherited_benign": 29,
            "recomputed_benign": 29,
            "inherited_attack": 3,
            "recomputed_attack": 3,
            "labels_agreement": "MATCH",
            "inherited_exact_duplicates": 2,
            "recomputed_exact_duplicates": 2,
            "inherited_repeated_rows": 2,
            "recomputed_repeated_rows": 2,
            "duplicates_agreement": "MATCH",
        },
        "environment": "pytest",
    }
    report = render_report(summary, figures, context)
    for heading in (
        "## 1. Scope, evidence basis and reproduction",
        "## 2. Dataset overview",
        "## 3. Target distribution",
        "## 4. Data quality",
        "## 5. Feature distributions",
        "## 6. Relationships and visualisations",
        "## 7. Leakage-safe EDA boundary",
        "## 8. Readiness gates",
        "## 9. Limitations",
    ):
        assert heading in report
    assert "PENDING ISSUE #7" in report
    assert "ML_READY" in report


def test_cli_skips_when_the_raw_package_is_absent(tmp_path, capsys):
    module = load_script_module()
    exit_code = module.main(
        [
            "--dataset",
            str(tmp_path / "absent.csv"),
            "--summary",
            str(tmp_path / "summary.json"),
            "--report",
            str(tmp_path / "report.md"),
            "--figures",
            str(tmp_path / "figures"),
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "SKIPPED" in output
    assert "ML_READY: BLOCKED" in output
    assert not (tmp_path / "summary.json").exists()


def test_cli_writes_summary_report_and_figures(fixture_csv, tmp_path):
    module = load_script_module()
    summary_path = tmp_path / "summary.json"
    report_path = tmp_path / "report.md"
    figures_path = tmp_path / "figures"
    exit_code = module.main(
        [
            "--dataset",
            str(fixture_csv),
            "--summary",
            str(summary_path),
            "--report",
            str(report_path),
            "--figures",
            str(figures_path),
            "--no-byte-verification",
        ]
    )
    assert exit_code == 0
    document = json.loads(summary_path.read_text(encoding="utf-8"))
    assert document["rows"] == 32
    assert document["readiness"]["ML_READY"] == "BLOCKED"
    assert document["readiness"]["SOURCE_INTEGRITY"] == "NOT VERIFIED"
    assert document["leakage_boundary"]["split_manifest"]["status"] == "PENDING ISSUE #7"
    assert document["leakage_boundary"]["target_columns_in_baseline_x"] is False
    assert document["leakage_boundary"]["metadata_columns_in_baseline_x"] is False
    assert "## 4. Data quality" in report_path.read_text(encoding="utf-8")
    assert list(figures_path.glob("*.png"))


def test_cli_does_not_modify_the_source_file(fixture_csv, tmp_path):
    module = load_script_module()
    before = hashlib.sha256(fixture_csv.read_bytes()).hexdigest()
    module.main(
        [
            "--dataset",
            str(fixture_csv),
            "--summary",
            str(tmp_path / "summary.json"),
            "--report",
            str(tmp_path / "report.md"),
            "--figures",
            str(tmp_path / "figures"),
            "--no-byte-verification",
        ]
    )
    after = hashlib.sha256(fixture_csv.read_bytes()).hexdigest()
    assert before == after


def test_cli_runs_as_a_subprocess_and_reports_the_gates(fixture_csv, tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--dataset",
            str(fixture_csv),
            "--summary",
            str(tmp_path / "summary.json"),
            "--report",
            str(tmp_path / "report.md"),
            "--figures",
            str(tmp_path / "figures"),
            "--no-byte-verification",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "ML_READY: BLOCKED" in result.stdout
    assert (tmp_path / "summary.json").is_file()
