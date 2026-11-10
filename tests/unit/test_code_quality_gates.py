"""Code quality and style compliance regression test suite (Issue #37).

Verifies that all codebase targets adhere strictly to project style, formatting,
and linting quality gates:
1. Zero Ruff lint violations across scoped production and test Python files.
2. Zero Black formatting diffs across scoped source directories.
3. Clean git diff whitespace and formatting sanity checks.
"""

from __future__ import annotations

import subprocess
import sys

from network_anomaly.config import PROJECT_ROOT

SCOPED_FILES = [
    "src/network_anomaly/__init__.py",
    "src/network_anomaly/visualization/plots.py",
    "scripts/check_environment.py",
    "src/network_anomaly/api/__init__.py",
    "src/network_anomaly/api/client.py",
    "src/network_anomaly/api/db.py",
    "src/network_anomaly/api/errors.py",
    "src/network_anomaly/api/main.py",
    "src/network_anomaly/api/repositories.py",
    "src/network_anomaly/api/schemas.py",
    "src/network_anomaly/api/service.py",
    "tests/unit/test_api_endpoints.py",
    "tests/unit/test_api_service.py",
    "tests/unit/test_api_persistence.py",
    "tests/unit/test_api_security.py",
]


def test_scoped_ruff_zero_violations():
    """Verify zero Ruff lint violations across all scoped Track E files."""
    existing_files = [f for f in SCOPED_FILES if (PROJECT_ROOT / f).is_file()]
    cmd = [sys.executable, "-m", "ruff", "check"] + existing_files
    res = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Ruff violations found:\n{res.stdout}\n{res.stderr}"


def test_scoped_black_zero_diff():
    """Verify zero Black formatting diffs across scoped directories and files."""
    existing_files = [f for f in SCOPED_FILES if (PROJECT_ROOT / f).is_file()]
    cmd = [sys.executable, "-m", "black", "--check"] + existing_files
    res = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Black formatting diffs found:\n{res.stdout}\n{res.stderr}"


def test_scoped_git_diff_check_clean():
    """Verify git diff --check reports zero whitespace or formatting anomalies on scoped files."""
    existing_files = [f for f in SCOPED_FILES if (PROJECT_ROOT / f).is_file()]
    cmd = ["git", "diff", "--check", "--"] + existing_files
    res = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"git diff --check reported errors:\n{res.stdout}\n{res.stderr}"
