"""Synthetic CSV fixtures for validation; these are not UNSW-NB15 experiments."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "validate_data.py"


@pytest.fixture
def validator(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("validate_data", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "DATA_RAW", tmp_path)
    return module


@pytest.mark.parametrize("name", ["UNSW-NB15.csv", "UNSW-NB15_training_set.csv"])
def test_default_discovery_checks_actual_file(validator, tmp_path, capsys, name):
    (tmp_path / name).write_text("label,proto\n0,tcp\n", encoding="utf-8")
    assert validator.main([]) == 0
    output = capsys.readouterr().out
    assert f"FOUND: {name}" in output
    assert "SKIPPED" not in output


def test_default_checks_both_files_and_fails_if_one_is_invalid(validator, tmp_path, capsys):
    (tmp_path / "UNSW-NB15.csv").write_text("label,proto\n0,tcp\n", encoding="utf-8")
    (tmp_path / "UNSW-NB15_training_set.csv").write_text("not-csv\n", encoding="utf-8")
    assert validator.main([]) == 1
    output = capsys.readouterr().out
    assert "FOUND: UNSW-NB15.csv" in output
    assert "ERROR: UNSW-NB15_training_set.csv" in output


def test_missing_optional_dataset_is_explicit_skip(validator, capsys):
    assert validator.main([]) == 0
    assert "SKIPPED" in capsys.readouterr().out


def test_explicit_missing_file_fails(validator, capsys):
    assert validator.main(["--file", "missing.csv"]) == 1
    assert "ERROR" in capsys.readouterr().out


@pytest.mark.parametrize("content", [
    "", "not-a-csv\n", "label,unrelated\n0,x\n", "proto,unrelated\ntcp,x\n",
    "label,proto\n", "label,proto\n0,tcp,extra\n", "label,proto\n0\n",
    'label,proto\n0,"unterminated\n', "label,proto,proto\n0,tcp,tcp\n",
    "label,proto,\n0,tcp,x\n",
])
def test_invalid_csv_fails(validator, tmp_path, capsys, content):
    (tmp_path / "invalid.csv").write_text(content, encoding="utf-8")
    assert validator.main(["--file", "invalid.csv"]) == 1
    output = capsys.readouterr().out
    assert "ERROR" in output
    assert "checks passed" not in output


def test_csv_bom_quoted_fields_and_extra_features_are_supported(validator, tmp_path):
    (tmp_path / "valid.csv").write_text(
        'label,proto,service\n0,tcp,"a,b"\n1,udp,dns\n', encoding="utf-8-sig"
    )
    assert validator.main(["--file", "valid.csv"]) == 0


def test_invalid_encoding_fails(validator, tmp_path, capsys):
    (tmp_path / "invalid.csv").write_bytes(b"label,proto\n0,\xff\n")
    assert validator.main(["--file", "invalid.csv"]) == 1
    assert "ERROR" in capsys.readouterr().out


@pytest.mark.parametrize("content, expected", [("label,proto\n0,tcp\n", 0), ("not-csv", 1)])
def test_cli_exit_status(tmp_path, content, expected):
    target = tmp_path / "input.csv"
    target.write_text(content, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--file", str(target)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
