"""Exit-code contract for scripts/run_experiments.py.

Guards the M0 rule that a planned-but-unimplemented step must never look like a
successful run. No dataset is needed; no training is performed.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "run_experiments.py"
SCRIPTS_DIR = SCRIPT.parent


@pytest.fixture
def runner(monkeypatch):
    """In-process runner module with a controllable validator."""
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    spec = importlib.util.spec_from_file_location("run_experiments", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("step", ["baseline", "evaluate", "inference"])
def test_unimplemented_step_never_reports_success(step):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--step", step],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "NOT IMPLEMENTED" in result.stdout


def test_unknown_step_is_rejected():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--step", "train"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "invalid choice" in result.stderr


def test_check_data_exit_code_is_the_validator_exit_code(runner, monkeypatch):
    calls = []

    def fake_main(argv):
        calls.append(argv)
        return 1

    monkeypatch.setattr(runner.validate_data, "main", fake_main)
    assert runner.main(["--step", "check-data"]) == 1
    assert calls == [[]]


def test_check_data_without_dataset_is_an_intentional_skip(runner, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(runner.validate_data, "DATA_RAW", tmp_path)
    assert runner.main(["--step", "check-data"]) == 0
    assert "SKIPPED" in capsys.readouterr().out


def test_check_data_with_invalid_dataset_fails(runner, monkeypatch, tmp_path):
    (tmp_path / "UNSW-NB15.csv").write_text("not-csv\n", encoding="utf-8")
    monkeypatch.setattr(runner.validate_data, "DATA_RAW", tmp_path)
    assert runner.main(["--step", "check-data"]) == 1
