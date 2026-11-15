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

    # Set back to 0.6.0 and verify strict 1-to-1 mismatch rejection for beta tag on 0.6.0 binary (F-04)
    set_desktop_version("0.6.0", root=tmp_path)
    ok_mismatch, msg_mismatch = verify_desktop_version(
        root=tmp_path,
        expected_tag="v0.6.0-beta.1",
    )
    assert ok_mismatch is False
    assert "does not match Git tag" in msg_mismatch

    # Detect drift when one file has a different version
    tauri_conf = tmp_path / "desktop" / "src-tauri" / "tauri.conf.json"
    tauri_conf.write_text(
        tauri_conf.read_text(encoding="utf-8").replace('"0.6.0"', '"0.1.0"'),
        encoding="utf-8",
    )
    ok_drift, msg_drift = verify_desktop_version(root=tmp_path)
    assert ok_drift is False
    assert "Desktop version mismatch" in msg_drift


def test_release_workflow_enforces_main_ancestry_for_beta_and_strict_semver():
    """F-03/F-04 regression: release.yml must gate all tags (beta+stable) on main & strict version."""
    release_yml = (PROJECT_ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    assert "--allow-prerelease-tag-on-base" not in release_yml
    assert "git merge-base --is-ancestor $tagCommit origin/main" in release_yml
    # Ensure merge-base ancestry check is NOT conditionally skipped for prerelease tags
    assert "if (-not $isPrerelease)" not in release_yml
    assert "gh release view $tagName" in release_yml
    assert "if: steps.meta.outputs.is_tag_push == 'true'" in release_yml
    assert "SHA256SUMS.txt" in release_yml
    assert "*_${desktopVer}_x64-setup.exe" in release_yml
    assert "\npermissions:\n  contents: read\n" in release_yml
    assert 'NETWORK_ANOMALY_REQUIRE_PYTHON_TEST: "1"' in release_yml
    ci_yml = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert 'NETWORK_ANOMALY_REQUIRE_PYTHON_TEST: "1"' in ci_yml

    # Check Python >= 3.11 and #27 DEFERRED documentation consistency (F-05/F-06)
    win_doc = (PROJECT_ROOT / "docs" / "WINDOWS_INSTALLATION.md").read_text(encoding="utf-8")
    rel_notes = (PROJECT_ROOT / "docs" / "releases" / "v0.6.0.md").read_text(encoding="utf-8")
    desktop_readme = (PROJECT_ROOT / "desktop" / "README.md").read_text(encoding="utf-8")
    assert ">= 3.10" not in win_doc
    assert ">= 3.10" not in rel_notes
    assert ">=3.10" not in desktop_readme
    assert ">= 3.11" in win_doc
    assert ">= 3.11" in rel_notes
    assert ">=3.11" in desktop_readme
    assert "| **#27** | **Artifact Provenance" not in rel_notes
    assert "Adaptive Rotation & Security Response" in rel_notes
    assert "DEFERRED" in rel_notes
