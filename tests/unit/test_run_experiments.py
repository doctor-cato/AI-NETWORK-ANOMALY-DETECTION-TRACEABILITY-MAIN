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
EXIT_USAGE = 2  # argparse default for a bad command line
EXIT_NOT_IMPLEMENTED = 3


def fake_validator(exit_code):
    """Stand-in for the validate_data module that records how it was called."""
    calls = []

    def main(argv):
        calls.append(argv)
        return exit_code

    module = type("FakeValidateData", (), {"main": staticmethod(main)})
    module.calls = calls
    return module


@pytest.fixture
def runner(monkeypatch):
    """In-process runner module, loadable even when network_anomaly is absent."""
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    spec = importlib.util.spec_from_file_location("run_experiments", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, check=False, cwd=cwd,
    )


@pytest.mark.parametrize("step", ["baseline", "evaluate", "inference"])
def test_unimplemented_step_never_reports_success(step):
    result = run_cli("--step", step)
    assert result.returncode == EXIT_NOT_IMPLEMENTED, result.stdout + result.stderr
    assert "NOT IMPLEMENTED" in result.stdout


@pytest.mark.parametrize("step", ["baseline", "evaluate", "inference"])
def test_unimplemented_step_is_independent_of_working_directory(step, tmp_path):
    """Reporting an unimplemented step must not depend on cwd or relative layout."""
    result = run_cli("--step", step, cwd=str(tmp_path))
    assert result.returncode == EXIT_NOT_IMPLEMENTED, result.stdout + result.stderr


def test_usage_error_has_a_different_exit_code_than_not_implemented():
    """A typo in --step must not be mistaken for a planned step."""
    result = run_cli("--step", "train")
    assert result.returncode == EXIT_USAGE, result.stdout + result.stderr
    assert "invalid choice" in result.stderr
    assert result.returncode != EXIT_NOT_IMPLEMENTED


@pytest.mark.parametrize("argv", [[], ["--step", "check-data"]])
@pytest.mark.parametrize("exit_code", [0, 1])
def test_check_data_delegates_to_validator_and_forwards_its_exit_code(
    runner, monkeypatch, argv, exit_code, capsys
):
    validator = fake_validator(exit_code)
    monkeypatch.setitem(sys.modules, "validate_data", validator)
    assert runner.main(argv) == exit_code
    assert validator.calls == [[]]
    assert "delegating to scripts/validate_data.py" in capsys.readouterr().out


def test_check_data_without_dataset_is_an_intentional_skip(runner, monkeypatch, tmp_path, capsys):
    import validate_data

    monkeypatch.setattr(validate_data, "DATA_RAW", tmp_path)
    assert runner.main(["--step", "check-data"]) == 0
    assert "SKIPPED" in capsys.readouterr().out


def test_check_data_with_invalid_dataset_fails(runner, monkeypatch, tmp_path):
    (tmp_path / "UNSW-NB15.csv").write_text("not-csv\n", encoding="utf-8")
    import validate_data

    monkeypatch.setattr(validate_data, "DATA_RAW", tmp_path)
    assert runner.main(["--step", "check-data"]) == 1
