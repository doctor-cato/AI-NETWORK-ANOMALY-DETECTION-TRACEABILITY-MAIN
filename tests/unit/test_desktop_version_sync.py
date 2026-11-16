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


def test_repo_desktop_version_is_1_0_0_and_api_version_is_0_1_0():
    desktop_versions = collect_desktop_versions(PROJECT_ROOT)
    unique_versions = set(desktop_versions.values())
    assert len(unique_versions) == 1
    desktop_ver = next(iter(unique_versions))
    assert desktop_ver == "1.0.0" or desktop_ver.startswith("1.0.0-")

    backend_versions = collect_backend_api_versions(PROJECT_ROOT)
    assert set(backend_versions.values()) == {"0.1.0"}

    ok, msg = verify_desktop_version(
        root=PROJECT_ROOT,
        expected_version=desktop_ver,
        expected_tag=f"v{desktop_ver}",
    )
    assert ok is True, msg


def test_semver_validation_and_set_version_supports_beta_and_stable(tmp_path: Path):
    validate_semver("1.0.0")
    validate_semver("1.0.0-beta.1")
    with pytest.raises(ValueError, match="Invalid SemVer"):
        validate_semver("v1.0.0")

    _copy_version_tree(tmp_path)

    # Set to 1.0.0-beta.1
    updated_beta = set_desktop_version("1.0.0-beta.1", root=tmp_path)
    assert set(updated_beta.values()) == {"1.0.0-beta.1"}
    ok_beta, msg_beta = verify_desktop_version(
        root=tmp_path,
        expected_version="1.0.0-beta.1",
        expected_tag="refs/tags/v1.0.0-beta.1",
    )
    assert ok_beta is True, msg_beta

    # Set back to 1.0.0 and verify strict 1-to-1 mismatch rejection for beta tag on 1.0.0 binary (F-04)
    set_desktop_version("1.0.0", root=tmp_path)
    ok_mismatch, msg_mismatch = verify_desktop_version(
        root=tmp_path,
        expected_tag="v1.0.0-beta.1",
    )
    assert ok_mismatch is False
    assert "does not match Git tag" in msg_mismatch

    # Detect drift when one file has a different version
    tauri_conf = tmp_path / "desktop" / "src-tauri" / "tauri.conf.json"
    tauri_conf.write_text(
        tauri_conf.read_text(encoding="utf-8").replace('"1.0.0"', '"0.1.0"'),
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
    # Ensure Issue #71 + F-01/F-02/F-03 fail-closed standalone & anti-leakage gates exist in release.yml
    assert "--verify-nsis-only" not in release_yml
    assert "Swatinem/rust-cache" not in release_yml
    assert "--no-repo-root-env" in release_yml
    assert "--standalone-embedded" in release_yml
    assert "--require-standalone-embedded" in release_yml
    assert "--clean-machine-e2e" in release_yml
    assert "--require-clean-machine-e2e" in release_yml
    assert "--github-run-id" in release_yml
    assert "--verify-github-run" in release_yml
    assert "::add-mask::$bundleUrl" in release_yml
    assert "--require-clean-git" in release_yml
    assert "--expect-sidecar-sha256" in release_yml
    assert "--stage-embedded-dir" in release_yml
    assert "--verify-distribution-permission" in release_yml
    assert "--target-channel" in release_yml
    assert "--repo-private" in release_yml
    assert "--evidence-sha256-env" in release_yml
    assert "--require-evidence-hash" in release_yml
    assert "DISTRIBUTION_EVIDENCE_SHA256" in release_yml
    assert "steps.embedded.outputs.upload_allowed == 'true'" in release_yml
    assert "steps.embedded.outputs.public_release_allowed == 'true'" in release_yml
    assert 'gh api "repos/${{ github.repository }}"' in release_yml
    assert "if: always()" in release_yml
    assert "scripts/build_backend_sidecar.py" in release_yml
    assert "tauri.standalone.conf.json" in release_yml
    assert "NOTICE" in release_yml
    assert "THIRD_PARTY_NOTICES.md" in release_yml
    publish_section = release_yml.split("Publish GitHub Release", 1)[1]
    assert "requirements-runtime.txt" not in publish_section
    assert "scripts/windows_setup_runtime.ps1" not in release_yml
    assert "COMPANION_BUNDLE_SHA256.txt" not in release_yml
    assert "release_e2e_verification.json" in release_yml
    assert "--expect-commit" in release_yml
    assert "--expect-installer-sha256" in release_yml
    assert "--require-nsis-e2e" in release_yml
    assert "--require-demo-files" in release_yml
    assert "--install-bundle-url" in release_yml
    assert "--install-bundle-run-id" in release_yml
    assert "--expect-bundle-sha256" in release_yml
    assert "vars.MODEL_BUNDLE_URL" in release_yml
    assert "vars.MODEL_BUNDLE_SHA256" in release_yml
    assert "vars.MODEL_ARTIFACT_RUN_ID" in release_yml
    assert "vars.ALLOW_EMBEDDED_MODEL_REDISTRIBUTION" in release_yml
    assert "vars.COMPANION_BUNDLE_URL" in release_yml
    assert '$isPrerelease = "${{ steps.meta.outputs.is_prerelease }}" -eq "true"' in release_yml
    assert "gh release view $tagName" in release_yml
    assert "SHA256SUMS.txt" in release_yml
    assert "*_${desktopVer}_x64-setup.exe" in release_yml
    assert release_yml.count("$global:LASTEXITCODE = 0") >= 2
    assert "\npermissions:\n  contents: read\n" in release_yml
    assert "    permissions:\n      contents: write\n      actions: read\n" in release_yml
    assert 'NETWORK_ANOMALY_REQUIRE_PYTHON_TEST: "1"' in release_yml
    ci_yml = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert 'NETWORK_ANOMALY_REQUIRE_PYTHON_TEST: "1"' in ci_yml

    # Check v1.0.0 standalone documentation consistency (no end-user Python/Companion Bundle requirement)
    win_doc = (PROJECT_ROOT / "docs" / "WINDOWS_INSTALLATION.md").read_text(encoding="utf-8")
    rel_notes = (PROJECT_ROOT / "docs" / "releases" / "v1.0.0.md").read_text(encoding="utf-8")
    desktop_readme = (PROJECT_ROOT / "desktop" / "README.md").read_text(encoding="utf-8")
    assert ">= 3.10" not in win_doc
    assert ">= 3.10" not in rel_notes
    assert ">=3.10" not in desktop_readme
    assert "v1.0.0" in win_doc
    assert "v1.0.0" in rel_notes
    assert "v1.0.0" in desktop_readme
    assert "Companion Bundle" in rel_notes
    assert "Random Forest" in rel_notes
    assert "XGBoost" in rel_notes
    assert "Isolation Forest" in rel_notes
    assert "Autoencoder" in rel_notes
    assert "454104" in rel_notes
    assert "DISTRIBUTION_AUTHORIZATION.json" in rel_notes
    assert "non-commercial-academic-approved" not in release_yml
    assert "non-commercial-academic-approved" not in desktop_readme
    assert "non-commercial-academic-approved" not in rel_notes
