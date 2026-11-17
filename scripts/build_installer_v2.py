#!/usr/bin/env python3
"""Standalone Windows v2.0 Installer Orchestrator (Issue #148).

Automates verification and packaging of NetFlow Sentinel v2.0.0:
1. Toolchain & artifact readiness check (`--check-only` / `--dry-run`)
2. Standalone Python FastAPI + ML + v2 Crypto/Trace PyInstaller sidecar build
3. Svelte 5 + Vite frontend production bundle
4. Tauri 2 Windows x64 NSIS installer compilation and SHA-256 manifest generation
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DESKTOP_DIR = PROJECT_ROOT / "desktop"
TAURI_DIR = DESKTOP_DIR / "src-tauri"
DEFAULT_RELEASE_DIR = PROJECT_ROOT / "dist" / "release-assets"
TAURI_STANDALONE_CONF = TAURI_DIR / "tauri.standalone.conf.json"


def inspect_packaging_prerequisites(project_root: Path = PROJECT_ROOT) -> Dict[str, Any]:
    """Inspect local build toolchain and staged artifact readiness without mutating files."""
    desktop_dir = project_root / "desktop"
    tauri_dir = desktop_dir / "src-tauri"
    staged_bundle = tauri_dir / "staged_bundle"

    tools = {
        "python": sys.executable,
        "pyinstaller": importlib.util.find_spec("PyInstaller") is not None,
        "node": shutil.which("node") is not None,
        "npm": shutil.which("npm") is not None,
        "cargo": shutil.which("cargo") is not None,
        "rustc": shutil.which("rustc") is not None,
        "makensis": shutil.which("makensis") is not None,
    }

    required_files = {
        "run_api": (project_root / "scripts" / "run_api.py").is_file(),
        "build_backend_sidecar": (project_root / "scripts" / "build_backend_sidecar.py").is_file(),
        "tauri_conf": (tauri_dir / "tauri.conf.json").is_file(),
        "tauri_standalone_conf": (tauri_dir / "tauri.standalone.conf.json").is_file(),
        "package_json": (desktop_dir / "package.json").is_file(),
        "staged_bundle_manifest": (staged_bundle / "EMBEDDED_ARTIFACTS_MANIFEST.json").is_file(),
    }

    can_build_sidecar = bool(tools["pyinstaller"] and required_files["run_api"])
    can_build_frontend = bool(tools["node"] and tools["npm"] and required_files["package_json"])
    can_build_nsis = bool(
        can_build_sidecar
        and can_build_frontend
        and tools["cargo"]
        and tools["rustc"]
        and required_files["tauri_standalone_conf"]
    )

    return {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "project_root": str(project_root),
        "tools": tools,
        "required_files": required_files,
        "readiness": {
            "sidecar_build_ready": can_build_sidecar,
            "frontend_build_ready": can_build_frontend,
            "full_nsis_installer_ready": can_build_nsis,
            "staged_models_present": required_files["staged_bundle_manifest"],
        },
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            digest.update(chunk)
    return digest.hexdigest().lower()


def _run_cmd(cmd: List[str], cwd: Path, label: str) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd), check=False)  # noqa: S603
    if proc.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {proc.returncode}: {' '.join(cmd)}")


def build_installer_v2(
    *,
    output_dir: Path = DEFAULT_RELEASE_DIR,
    version_label: str = "2.0.0-pilot",
    check_only: bool = False,
    skip_nsis: bool = False,
) -> Dict[str, Any]:
    """Execute or validate the NetFlow Sentinel v2.0 standalone Windows installer build."""
    report = inspect_packaging_prerequisites(PROJECT_ROOT)
    if check_only:
        report["mode"] = "check_only"
        report["status"] = "READY" if report["readiness"]["frontend_build_ready"] else "PARTIAL"
        return report

    if not report["readiness"]["sidecar_build_ready"]:
        raise RuntimeError(
            "PyInstaller sidecar toolchain is unavailable. Install with: pip install -e '.[packaging]'"
        )
    if not report["readiness"]["frontend_build_ready"]:
        raise RuntimeError("Node.js / npm frontend toolchain is unavailable.")

    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    sidecar_meta_path = out_dir / "sidecar_build_v2.json"

    # Step 1: Build PyInstaller backend sidecar
    _run_cmd(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "build_backend_sidecar.py"),
            "--output-json",
            str(sidecar_meta_path),
        ],
        cwd=PROJECT_ROOT,
        label="PyInstaller v2 sidecar build",
    )

    # Step 2: Build Svelte frontend bundle
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    _run_cmd([npm_cmd, "--prefix", "desktop", "run", "build"], cwd=PROJECT_ROOT, label="Vite build")

    installer_dest: Optional[Path] = None
    installer_sha256: Optional[str] = None

    if not skip_nsis:
        if not report["readiness"]["full_nsis_installer_ready"]:
            raise RuntimeError(
                "Rust / Cargo toolchain is required to bundle the Tauri NSIS installer."
            )
        if not report["readiness"]["staged_models_present"]:
            raise RuntimeError(
                "Missing desktop/src-tauri/staged_bundle/EMBEDDED_ARTIFACTS_MANIFEST.json. "
                "Stage authorized model artifacts first via scripts/verify_companion_artifacts.py."
            )

        npx_cmd = "npx.cmd" if sys.platform == "win32" else "npx"
        _run_cmd(
            [
                npx_cmd,
                "tauri",
                "build",
                "--config",
                "src-tauri/tauri.standalone.conf.json",
                "--bundles",
                "nsis",
            ],
            cwd=DESKTOP_DIR,
            label="Tauri NSIS installer build",
        )

        nsis_dir = TAURI_DIR / "target" / "release" / "bundle" / "nsis"
        nsis_candidates = sorted(nsis_dir.glob("*_x64-setup.exe"))
        if not nsis_candidates:
            raise RuntimeError(f"No NSIS setup executable produced in {nsis_dir}")

        src_setup = nsis_candidates[-1]
        installer_dest = out_dir / f"NetFlow-Sentinel-v{version_label}-windows-x64-setup.exe"
        shutil.copy2(src_setup, installer_dest)
        installer_sha256 = _sha256_file(installer_dest)

        sums_file = out_dir / "SHA256SUMS.txt"
        sums_file.write_text(
            f"{installer_sha256}  {installer_dest.name}\n",
            encoding="ascii",
            newline="\n",
        )

    manifest = {
        "product": "NetFlow Sentinel v2.0",
        "version_label": version_label,
        "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "sidecar_metadata": str(sidecar_meta_path),
        "installer_path": str(installer_dest) if installer_dest else None,
        "installer_sha256": installer_sha256,
        "prerequisites": report,
        "status": "BUILT" if installer_dest else "SIDECAR_AND_FRONTEND_BUILT",
    }
    manifest_path = out_dir / "installer_v2_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build or validate NetFlow Sentinel v2.0 standalone Windows installer (#148)."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_RELEASE_DIR,
        help="Destination directory for staged installer assets.",
    )
    parser.add_argument(
        "--version-label",
        type=str,
        default="2.0.0-pilot",
        help="Asset filename label for staged Windows installer.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Inspect toolchain and artifact readiness without running a build.",
    )
    parser.add_argument(
        "--skip-nsis",
        action="store_true",
        help="Build sidecar and frontend bundle only without compiling NSIS.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional JSON output path for readiness/build report.",
    )
    args = parser.parse_args(argv)

    try:
        result = build_installer_v2(
            output_dir=args.output_dir,
            version_label=args.version_label,
            check_only=args.check_only,
            skip_nsis=args.skip_nsis,
        )
    except Exception as exc:
        sys.stderr.write(f"[INSTALLER V2 BUILD FAILED] {exc}\n")
        return 1

    rendered = json.dumps(result, indent=2)
    if args.output_json is not None:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
