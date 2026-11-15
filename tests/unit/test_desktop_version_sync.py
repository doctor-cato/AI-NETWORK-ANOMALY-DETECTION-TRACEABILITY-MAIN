"""Unit tests for M6 desktop version consistency and SemVer tag verification."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from network_anomaly.config import PROJECT_ROOT
from scripts.check_desktop_version import (
    collect_backend_api_versions,
    collect_desktop_versions,
    set_desktop_version,
    validate_semver,
    verify_desktop_version,
)


def _copy_version_tree(dst_root: Path) -> None:
    files = [
        Path("desktop/src-tauri/Cargo.toml"),
        Path("desktop/src-tauri/Cargo.lock"),
        Path("desktop/package.json"),
        Path("desktop/package-lock.json"),
        Path("desktop/src-tauri/tauri.conf.json"),
        Path("pyproject.toml"),
        Path("src/network_anomaly/__init__.py"),
        Path("src/network_anomaly/api/main.py"),
    ]
    for rel in files:
        target = dst_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / rel, target)


def test_repo_desktop_version_is_0_6_0_and_api_version_is_0_1_0():
    desktop_versions = collect_desktop_versions(PROJECT_ROOT)
    assert set(desktop_versions.values()) == {"0.6.0"}

    backend_versions = collect_backend_api_versions(PROJECT_ROOT)
    assert set(backend_versions.values()) == {"0.1.0"}

    ok, msg = verify_desktop_version(
        root=PROJECT_ROOT,
        expected_version="0.6.0",
        expected_tag="v0.6.0",
    )
    assert ok is True, msg


def test_semver_validation_and_set_version_supports_beta_and_stable(tmp_path: Path):
    validate_semver("0.6.0")
    validate_semver("0.6.0-beta.1")
    with pytest.raises(ValueError, match="Invalid SemVer"):
        validate_semver("v0.6.0")

    _copy_version_tree(tmp_path)

    # Set to 0.6.0-beta.1
    updated_beta = set_desktop_version("0.6.0-beta.1", root=tmp_path)
    assert set(updated_beta.values()) == {"0.6.0-beta.1"}
    ok_beta, msg_beta = verify_desktop_version(
        root=tmp_path,
        expected_version="0.6.0-beta.1",
        expected_tag="refs/tags/v0.6.0-beta.1",
    )
    assert ok_beta is True, msg_beta

    # Set back to 0.6.0 and verify mismatch detection
    set_desktop_version("0.6.0", root=tmp_path)
    ok_mismatch, msg_mismatch = verify_desktop_version(
        root=tmp_path,
        expected_tag="v0.6.0-beta.1",
        allow_prerelease_tag_on_base=False,
    )
    assert ok_mismatch is False
    assert "does not match Git tag" in msg_mismatch

    # Allow prerelease tag on matching base version when flag is enabled
    ok_base, msg_base = verify_desktop_version(
        root=tmp_path,
        expected_tag="v0.6.0-beta.1",
        allow_prerelease_tag_on_base=True,
    )
    assert ok_base is True, msg_base

    # Detect drift when one file has a different version
    tauri_conf = tmp_path / "desktop" / "src-tauri" / "tauri.conf.json"
    tauri_conf.write_text(
        tauri_conf.read_text(encoding="utf-8").replace('"0.6.0"', '"0.1.0"'),
        encoding="utf-8",
    )
    ok_drift, msg_drift = verify_desktop_version(root=tmp_path)
    assert ok_drift is False
    assert "Desktop version mismatch" in msg_drift
