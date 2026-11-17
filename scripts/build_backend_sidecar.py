#!/usr/bin/env python3
"""Build the standalone FastAPI + 4-model ML PyInstaller sidecar for Tauri 2.

Produces `desktop/src-tauri/binaries/netflow-sentinel-backend-x86_64-pc-windows-msvc.exe`
(or platform-specific target triple) with zero dependency on system Python or
source checkout at runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = PROJECT_ROOT / "scripts" / "run_api.py"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "desktop" / "src-tauri" / "binaries"
SIDECAR_BASENAME = "netflow-sentinel-backend"

EXCLUDED_MODULES = (
    "tkinter",
    "matplotlib",
    "seaborn",
    "torch",
    "torchvision",
    "torchaudio",
    "jupyter",
    "notebook",
    "IPython",
    "pytest",
    "black",
    "ruff",
    "mypy",
    "PIL",
    "scipy.tests",
    "numpy.tests",
    "pandas.tests",
    "sklearn.tests",
)

HIDDEN_IMPORTS = (
    "network_anomaly",
    "network_anomaly.api",
    "network_anomaly.api.main",
    "network_anomaly.api.service",
    "network_anomaly.api.db",
    "network_anomaly.api.repositories",
    "network_anomaly.api.schemas",
    "network_anomaly.api.errors",
    "network_anomaly.api.desktop_csv",
    "network_anomaly.api.response_policy",
    "network_anomaly.config",
    "network_anomaly.data",
    "network_anomaly.data.v2_schema",
    "network_anomaly.data.taxonomy",
    "network_anomaly.evaluation",
    "network_anomaly.evaluation.metrics",
    "network_anomaly.inference",
    "network_anomaly.inference.predict",
    "network_anomaly.ingestion",
    "network_anomaly.ingestion.compatibility",
    "network_anomaly.ingestion.gate",
    "network_anomaly.ingestion.ood",
    "network_anomaly.models",
    "network_anomaly.models.random_forest",
    "network_anomaly.models.xgboost_model",
    "network_anomaly.models.isolation_forest",
    "network_anomaly.models.autoencoder",
    "network_anomaly.preprocessing",
    "network_anomaly.preprocessing.pipeline",
    "network_anomaly.canonical",
    "network_anomaly.canonical.event",
    "network_anomaly.canonical.feature_contract",
    "network_anomaly.crypto",
    "network_anomaly.crypto.aead",
    "network_anomaly.crypto.encrypted_storage",
    "network_anomaly.crypto.key_manager",
    "network_anomaly.crypto.rotation",
    "network_anomaly.behavioral",
    "network_anomaly.behavioral.correlation",
    "network_anomaly.behavioral.sessionizer",
    "network_anomaly.behavioral.similarity",
    "network_anomaly.behavioral.vector",
    "network_anomaly.risk",
    "network_anomaly.risk.aggregation",
    "network_anomaly.risk.scoring",
    "network_anomaly.trace",
    "network_anomaly.trace.engine",
    "network_anomaly.trace.graph",
    "network_anomaly.trace.investigation",
    "network_anomaly.trace.timeline",
    "network_anomaly.telemetry",
    "network_anomaly.telemetry.collector",
    "network_anomaly.telemetry.log_tailer",
    "network_anomaly.telemetry.modes",
    "network_anomaly.telemetry.pcap_reader",
    "network_anomaly.streaming",
    "network_anomaly.streaming.alert_manager",
    "network_anomaly.streaming.feature_extractor",
    "network_anomaly.streaming.live_orchestrator",
    "network_anomaly.streaming.pipeline",
    "network_anomaly.streaming.realtime_inference",
    "network_anomaly.ml",
    "network_anomaly.ml.ood_gate",
    "network_anomaly.ml.threshold_calibration",
    "network_anomaly.pipeline",
    "network_anomaly.pipeline.multi_source",
    "network_anomaly.data.quality_gate",
    "network_anomaly.data.taxonomy",
    "network_anomaly.ingestion.adapters",
    "network_anomaly.ingestion.adapters.v2_adapter",
    "cryptography",
    "cryptography.hazmat.primitives.ciphers.aead",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "sklearn.ensemble._forest",
    "sklearn.ensemble._iforest",
    "sklearn.neural_network._multilayer_perceptron",
    "sklearn.impute",
    "sklearn.preprocessing",
    "sklearn.utils._cython_blas",
    "sklearn.neighbors._typedefs",
    "sklearn.tree._utils",
    "xgboost",
    "joblib",
)


def resolve_target_triple() -> str:
    """Resolve Rust/Tauri target triple for sidecar naming."""
    machine = platform.machine().lower()
    if os.name == "nt":
        if machine in {"amd64", "x86_64"}:
            return "x86_64-pc-windows-msvc"
        if machine in {"arm64", "aarch64"}:
            return "aarch64-pc-windows-msvc"
    if sys.platform == "darwin":
        return "aarch64-apple-darwin" if machine in {"arm64", "aarch64"} else "x86_64-apple-darwin"
    return "x86_64-unknown-linux-gnu"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            digest.update(chunk)
    return digest.hexdigest().lower()


def build_sidecar(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    target_triple: Optional[str] = None,
    clean: bool = True,
) -> Dict[str, object]:
    """Compile `scripts/run_api.py` into a standalone PyInstaller sidecar binary."""
    triple = (target_triple or resolve_target_triple()).strip()
    suffix = ".exe" if "windows" in triple else ""
    binary_name = f"{SIDECAR_BASENAME}-{triple}"
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    target_bin = out_dir / f"{binary_name}{suffix}"

    try:
        import PyInstaller.__main__ as pyinstaller_main  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "PyInstaller is required to build the standalone backend sidecar. "
            "Install with: pip install -e '.[packaging]'"
        ) from exc

    with tempfile.TemporaryDirectory(prefix="nf_pyinstaller_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        dist_dir = tmp_root / "dist"
        work_dir = tmp_root / "work"
        spec_dir = tmp_root / "spec"
        dist_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)
        spec_dir.mkdir(parents=True, exist_ok=True)

        cmd: List[str] = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--onefile",
            "--name",
            binary_name,
            "--distpath",
            str(dist_dir),
            "--workpath",
            str(work_dir),
            "--specpath",
            str(spec_dir),
            "--paths",
            str(PROJECT_ROOT / "src"),
            "--collect-data",
            "xgboost",
            "--collect-binaries",
            "xgboost",
            "--copy-metadata",
            "xgboost",
            "--copy-metadata",
            "scikit-learn",
            "--copy-metadata",
            "fastapi",
            "--copy-metadata",
            "pydantic",
        ]
        if clean:
            cmd.append("--clean")
        for mod in EXCLUDED_MODULES:
            cmd.extend(["--exclude-module", mod])
        for mod in HIDDEN_IMPORTS:
            cmd.extend(["--hidden-import", mod])
        cmd.append(str(ENTRYPOINT))

        proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=False)  # noqa: S603
        if proc.returncode != 0:
            raise RuntimeError(f"PyInstaller build failed with exit code {proc.returncode}.")

        built_bin = dist_dir / f"{binary_name}{suffix}"
        if not built_bin.is_file():
            raise RuntimeError(f"Expected PyInstaller output not found: {built_bin}")

        tmp_dest = target_bin.with_suffix(target_bin.suffix + ".tmp")
        shutil.copy2(built_bin, tmp_dest)
        tmp_dest.replace(target_bin)

    size_bytes = target_bin.stat().st_size
    sha256 = _sha256_file(target_bin)
    return {
        "status": "READY",
        "sidecar_path": str(target_bin),
        "target_triple": triple,
        "size_bytes": size_bytes,
        "sha256": sha256,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build NetFlow Sentinel standalone Python FastAPI + ML sidecar."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Destination directory for Tauri externalBin sidecar.",
    )
    parser.add_argument(
        "--target-triple",
        type=str,
        default=None,
        help="Explicit Rust target triple (defaults to host platform triple).",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Reuse PyInstaller cache if invoked repeatedly.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional output path to write sidecar build metadata JSON.",
    )
    args = parser.parse_args(argv)

    try:
        info = build_sidecar(
            output_dir=args.output_dir,
            target_triple=args.target_triple,
            clean=not args.no_clean,
        )
    except Exception as exc:
        sys.stderr.write(f"[SIDECAR BUILD FAILED] {exc}\n")
        return 1

    rendered = json.dumps(info, indent=2)
    if args.output_json is not None:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
