#!/usr/bin/env python3
"""Audit and stage NetFlow Sentinel v0.6.0 companion model artifacts on Windows.

Verifies SHA-256 digests and manifest linkage across the preprocessor, 4 verified
ML models (Random Forest, XGBoost, Isolation Forest, Autoencoder), and Validation
demo CSV bundle without copying or bundling raw NF-UNSW-NB15-v3 dataset files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOCAL_SRC = PROJECT_ROOT / "src"
if str(_LOCAL_SRC) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SRC))

from network_anomaly.inference.predict import (  # noqa: E402
    _sha256_file,
    load_verified_model,
    load_verified_preprocessor,
)

_TAURI_BUNDLE_MARKER_UNK = b"BUNDLE_TYPE_VAR_UNK"
_TAURI_BUNDLE_MARKER_NSS = b"BUNDLE_TYPE_VAR_NSS"

MODEL_SPECS: Dict[str, Tuple[Path, List[Path]]] = {
    "random_forest": (
        Path("artifacts/models/random_forest/random_forest_baseline.joblib"),
        [Path("reports/models/random_forest_manifest.json")],
    ),
    "xgboost": (
        Path("artifacts/models/xgboost/xgboost_baseline.joblib"),
        [
            Path("reports/models/xgboost_manifest.json"),
            Path("artifacts/models/xgboost/xgboost_manifest.json"),
        ],
    ),
    "isolation_forest": (
        Path("artifacts/models/isolation_forest/isolation_forest.joblib"),
        [
            Path("reports/models/isolation_forest_manifest.json"),
            Path("artifacts/models/isolation_forest/model_config.json"),
            Path("artifacts/models/isolation_forest/threshold.json"),
            Path("artifacts/models/isolation_forest/training_metadata.json"),
        ],
    ),
    "autoencoder": (
        Path("artifacts/models/autoencoder/autoencoder_model.joblib"),
        [
            Path("reports/models/autoencoder_manifest.json"),
            Path("artifacts/models/autoencoder/autoencoder_manifest.json"),
            Path("artifacts/models/autoencoder/model_config.json"),
            Path("artifacts/models/autoencoder/threshold.json"),
        ],
    ),
}

PREPROCESSOR_REL = Path("artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib")
PREPROCESSOR_MANIFEST_REL = Path(
    "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json"
)
SPLIT_MANIFEST_REL = Path("data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json")
DEMO_FILES_REL: Tuple[Path, ...] = (
    Path("data/demo/demo_flows.csv"),
    Path("data/demo/demo_labels.csv"),
    Path("data/demo/demo_manifest.json"),
)


def _select_existing_manifest(root: Path, candidates: List[Path]) -> Optional[Path]:
    for rel in candidates:
        candidate = root / rel
        if candidate.is_file():
            return candidate
    return root / candidates[0]


def verify_companion_artifacts(root: Path = PROJECT_ROOT) -> Dict[str, Any]:
    """Verify preprocessor, all 4 model bundles, and demo files fail-closed."""
    resolved_root = Path(root).resolve()
    prep_path = resolved_root / PREPROCESSOR_REL
    prep_manifest = resolved_root / PREPROCESSOR_MANIFEST_REL
    split_manifest = resolved_root / SPLIT_MANIFEST_REL

    staged_files: List[Path] = []
    prep_sha: Optional[str] = None
    prep_status: Dict[str, Any]

    try:
        _, prep_meta = load_verified_preprocessor(
            artifact_path=prep_path,
            manifest_path=prep_manifest,
            split_manifest_path=split_manifest if split_manifest.is_file() else None,
        )
        prep_sha = str(prep_meta.get("artifact_sha256") or _sha256_file(prep_path))
        prep_status = {
            "ready": True,
            "status": "READY",
            "path": PREPROCESSOR_REL.as_posix(),
            "sha256": prep_sha,
            "reason": None,
        }
        staged_files.extend([PREPROCESSOR_REL, PREPROCESSOR_MANIFEST_REL])
    except Exception as exc:
        prep_status = {
            "ready": False,
            "status": "BLOCKED / NOT READY",
            "path": PREPROCESSOR_REL.as_posix(),
            "sha256": None,
            "reason": str(exc),
        }

    models_status: Dict[str, Dict[str, Any]] = {}
    ready_models: List[str] = []

    for model_key, (model_rel, support_rels) in MODEL_SPECS.items():
        model_abs = resolved_root / model_rel
        manifest_abs = _select_existing_manifest(resolved_root, support_rels)
        if not prep_status["ready"] or prep_sha is None:
            models_status[model_key] = {
                "ready": False,
                "status": "BLOCKED / NOT READY",
                "path": model_rel.as_posix(),
                "sha256": None,
                "reason": "Preprocessor artifact is not verified.",
            }
            continue
        try:
            assert manifest_abs is not None
            _, model_meta = load_verified_model(
                model_artifact_path=model_abs,
                manifest_path=manifest_abs,
                expected_preprocessor_sha256=prep_sha,
            )
            ready_models.append(model_key)
            models_status[model_key] = {
                "ready": True,
                "status": "READY",
                "path": model_rel.as_posix(),
                "manifest_path": manifest_abs.relative_to(resolved_root).as_posix(),
                "sha256": model_meta.get("model_artifact_sha256") or _sha256_file(model_abs),
                "run_id": model_meta.get("run_id"),
                "reason": None,
            }
            staged_files.append(model_rel)
            for rel in support_rels:
                if (resolved_root / rel).is_file():
                    staged_files.append(rel)
        except Exception as exc:
            models_status[model_key] = {
                "ready": False,
                "status": "BLOCKED / NOT READY",
                "path": model_rel.as_posix(),
                "sha256": None,
                "reason": str(exc),
            }

    demo_status: Dict[str, Any] = {}
    demo_ready = True
    demo_error: Optional[str] = None
    for rel in DEMO_FILES_REL:
        abs_path = resolved_root / rel
        if abs_path.is_file():
            demo_status[rel.as_posix()] = {
                "present": True,
                "sha256": _sha256_file(abs_path),
                "size_bytes": abs_path.stat().st_size,
            }
            staged_files.append(rel)
        else:
            demo_ready = False
            demo_status[rel.as_posix()] = {"present": False, "sha256": None, "size_bytes": 0}

    if demo_ready:
        try:
            demo_manifest = json.loads(
                (resolved_root / "data/demo/demo_manifest.json").read_text(encoding="utf-8")
            )
            sampling = demo_manifest.get("sampling") or {}
            if sampling.get("partition") != "validation":
                raise ValueError(
                    f"demo_manifest sampling.partition must be 'validation', got {sampling.get('partition')!r}"
                )
            if (
                int(sampling.get("train_overlap_count", -1)) != 0
                or int(sampling.get("test_overlap_count", -1)) != 0
            ):
                raise ValueError("demo_manifest records non-zero train/test overlap")
            outputs = demo_manifest.get("outputs") or {}
            expected_flows_sha = (outputs.get("demo_flows_csv") or {}).get("sha256")
            expected_labels_sha = (outputs.get("demo_labels_csv") or {}).get("sha256")
            actual_flows_sha = demo_status["data/demo/demo_flows.csv"]["sha256"]
            actual_labels_sha = demo_status["data/demo/demo_labels.csv"]["sha256"]
            if not expected_flows_sha or actual_flows_sha != expected_flows_sha:
                raise ValueError("demo_flows.csv SHA-256 mismatch with demo_manifest.json")
            if not expected_labels_sha or actual_labels_sha != expected_labels_sha:
                raise ValueError("demo_labels.csv SHA-256 mismatch with demo_manifest.json")
            if split_manifest.is_file():
                expected_split_sha = demo_manifest.get("split_manifest_sha256")
                if expected_split_sha and expected_split_sha != _sha256_file(split_manifest):
                    raise ValueError(
                        "demo_manifest split_manifest_sha256 mismatch with split manifest"
                    )
        except Exception as exc:
            demo_ready = False
            demo_error = str(exc)

    all_four_ready = prep_status["ready"] and len(ready_models) == len(MODEL_SPECS) and demo_ready
    unique_staged = sorted({p.as_posix() for p in staged_files})

    return {
        "overall_status": "READY" if all_four_ready else "BLOCKED / NOT READY",
        "ready_models": ready_models,
        "preprocessor": prep_status,
        "models": models_status,
        "demo": demo_status,
        "demo_ready": demo_ready,
        "demo_verification_error": demo_error,
        "companion_files": unique_staged,
    }


def stage_companion_bundle(
    destination: Path,
    root: Path = PROJECT_ROOT,
) -> Dict[str, Any]:
    """Copy verified runtime companion artifacts (no raw dataset) + SHA256SUMS."""
    summary = verify_companion_artifacts(root=root)
    if summary["overall_status"] != "READY":
        raise RuntimeError(
            "Cannot stage companion bundle while artifacts are incomplete or unverified: "
            f"ready_models={summary['ready_models']}, demo_ready={summary['demo_ready']}"
        )

    resolved_root = Path(root).resolve()
    dest_dir = Path(destination).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    checksum_lines: List[str] = []
    for rel_str in summary["companion_files"]:
        src = resolved_root / rel_str
        dst = dest_dir / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        checksum = _sha256_file(dst)
        checksum_lines.append(f"{checksum}  {rel_str}")

    sums_path = dest_dir / "COMPANION_SHA256SUMS.txt"
    sums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    return {
        **summary,
        "destination": str(dest_dir),
        "checksums_file": str(sums_path),
        "staged_file_count": len(checksum_lines),
    }


def _find_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http_json(
    url: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    timeout: float = 15.0,
) -> Tuple[int, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - 127.0.0.1 only
        body = resp.read().decode("utf-8")
        return int(resp.status), json.loads(body)


def _start_api_process(
    resolved_root: Path,
    run_api_script: Path,
    db_path: Path,
    log_path: Path,
    env: Dict[str, str],
) -> Tuple[subprocess.Popen[str], str]:
    """Start loopback FastAPI on a free port with file-backed logs (no pipe deadlock)."""
    last_err: Optional[Exception] = None
    for _attempt in range(3):
        port = _find_free_loopback_port()
        base_url = f"http://127.0.0.1:{port}"
        log_fh = log_path.open("w", encoding="utf-8")
        try:
            proc = subprocess.Popen(  # noqa: S603 - explicit trusted local interpreter + script
                [
                    sys.executable,
                    str(run_api_script),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--db-path",
                    str(db_path),
                ],
                cwd=str(resolved_root),
                env=env,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                text=True,
            )
        finally:
            log_fh.close()

        deadline = time.monotonic() + 25.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                output = log_path.read_text(encoding="utf-8", errors="replace")
                last_err = RuntimeError(f"run_api.py exited early ({proc.returncode}): {output}")
                break
            try:
                status_code, _ = _http_json(f"{base_url}/api/v1/health", timeout=2.0)
                if status_code == 200:
                    return proc, base_url
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(0.25)
        else:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            last_err = RuntimeError("Timed out waiting for FastAPI /api/v1/health on 127.0.0.1.")

    assert last_err is not None
    raise last_err


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ACTION_COUNT_KEYS = ("NO_ACTION", "MONITOR", "INVESTIGATE", "ISOLATE_RECOMMENDED")


def _is_hex_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_HEX_RE.fullmatch(value))


def _is_strict_nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _read_json_dict(path: Path, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"Missing required {label}: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to parse {label} ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return data


def _parse_sha256_sums_file(sums_file: Path) -> Dict[str, str]:
    if not sums_file.is_file():
        raise RuntimeError(f"Checksums file not found: {sums_file}")
    sums: Dict[str, str] = {}
    for line_no, raw_line in enumerate(sums_file.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", line)
        if not match:
            raise RuntimeError(
                f"Malformed SHA-256 sums line {line_no} in {sums_file}: {raw_line!r}"
            )
        digest = match.group(1).lower()
        filename = match.group(2).strip()
        if not filename:
            raise RuntimeError(f"Empty filename on line {line_no} in {sums_file}")
        if filename in sums and sums[filename] != digest:
            raise RuntimeError(f"Conflicting checksum entries for {filename!r} in {sums_file}")
        sums[filename] = digest
    if not sums:
        raise RuntimeError(f"Checksums file contains no entries: {sums_file}")
    return sums


def _get_git_head_commit(resolved_root: Path) -> str:
    try:
        commit = subprocess.check_output(  # noqa: S603 - fixed local git command
            ["git", "rev-parse", "HEAD"],
            cwd=str(resolved_root),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception as exc:
        raise RuntimeError(
            f"Unable to determine git HEAD commit in {resolved_root} (fail-closed): {exc}"
        ) from exc
    normalized = commit.lower()
    if not _GIT_COMMIT_RE.fullmatch(normalized):
        raise RuntimeError(f"Invalid git HEAD commit hash {commit!r} (fail-closed).")
    return normalized


def _read_desktop_version(resolved_root: Path) -> str:
    pkg_path = resolved_root / "desktop/package.json"
    pkg = _read_json_dict(pkg_path, "desktop/package.json")
    version = pkg.get("version")
    if not isinstance(version, str) or not version.strip():
        raise RuntimeError(f"Missing valid 'version' in {pkg_path}")
    return version.strip()


def _resolve_manifest_preprocessor_sha256(tracked_manifest: Dict[str, Any]) -> Optional[str]:
    direct = tracked_manifest.get("preprocessor_artifact_sha256") or tracked_manifest.get(
        "preprocessor_sha256"
    )
    if isinstance(direct, str) and direct.strip():
        return direct.strip().lower()
    prep_prov = tracked_manifest.get("preprocessing_provenance")
    if isinstance(prep_prov, dict):
        nested = prep_prov.get("preprocessor_artifact_sha256")
        if isinstance(nested, str) and nested.strip():
            return nested.strip().lower()
    prov = tracked_manifest.get("provenance")
    if isinstance(prov, dict):
        prep = prov.get("preprocessor")
        if isinstance(prep, dict):
            nested = prep.get("artifact_sha256")
            if isinstance(nested, str) and nested.strip():
                return nested.strip().lower()
    return None


def verify_nsis_installer_e2e(
    installer_path: Path,
    root: Path = PROJECT_ROOT,
    sums_file: Optional[Path] = None,
    compiled_exe_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Verify NSIS installer checksum, silent clean-dir install, exe SHA-256 parity, and uninstall."""
    resolved_root = Path(root).resolve()
    installer = Path(installer_path)
    if not installer.is_file():
        raise RuntimeError(f"NSIS installer not found: {installer}")
    installer_size = installer.stat().st_size
    if installer_size < 1_000_000:
        raise RuntimeError(
            f"NSIS installer size too small ({installer_size} bytes < 1,000,000): {installer}"
        )
    installer_sha256 = _sha256_file(installer).lower()

    sums_file_verified = False
    if sums_file is not None:
        sums_map = _parse_sha256_sums_file(Path(sums_file))
        expected_installer_sha = sums_map.get(installer.name)
        if expected_installer_sha is None:
            raise RuntimeError(
                f"Installer {installer.name!r} missing from checksums file {sums_file}"
            )
        if expected_installer_sha != installer_sha256:
            raise RuntimeError(
                f"Installer SHA-256 mismatch against {sums_file}: "
                f"expected {expected_installer_sha}, got {installer_sha256}"
            )
        sums_file_verified = True

    if os.name != "nt":
        raise RuntimeError(
            "Clean Windows NSIS E2E verification requires Windows (os.name == 'nt')."
        )

    resolved_compiled: Optional[Path] = None
    if compiled_exe_path is not None:
        resolved_compiled = Path(compiled_exe_path)
        if not resolved_compiled.is_file():
            raise RuntimeError(f"Compiled desktop executable not found: {resolved_compiled}")
    else:
        default_compiled = (
            resolved_root / "desktop/src-tauri/target/release/netflow-sentinel-desktop.exe"
        )
        if default_compiled.is_file():
            resolved_compiled = default_compiled

    with tempfile.TemporaryDirectory(prefix="nf_nsis_", ignore_cleanup_errors=True) as tmp_dir:
        install_dir = Path(tmp_dir) / "CleanInstall"
        install_proc = subprocess.run(  # noqa: S603 - explicit local NSIS installer binary
            [str(installer.resolve()), "/S", "/NS", f"/D={install_dir}"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if install_proc.returncode != 0:
            raise RuntimeError(
                f"NSIS silent install failed (exit={install_proc.returncode}): "
                f"{install_proc.stderr or install_proc.stdout}"
            )

        installed_exe = install_dir / "netflow-sentinel-desktop.exe"
        uninstaller_exe = install_dir / "uninstall.exe"
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if (
                installed_exe.is_file()
                and installed_exe.stat().st_size >= 1_000_000
                and uninstaller_exe.is_file()
                and uninstaller_exe.stat().st_size > 0
            ):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(
                f"NSIS clean install did not materialize expected executables within 15s in {install_dir}"
            )

        installed_bytes = installed_exe.read_bytes()
        installed_exe_sha256 = hashlib.sha256(installed_bytes).hexdigest().lower()
        compiled_exe_sha256: Optional[str] = None
        normalized_compiled_exe_sha256: Optional[str] = None
        compiled_exe_sha256_match: Optional[bool] = None
        exe_parity_mode: Optional[str] = None
        if resolved_compiled is not None:
            compiled_bytes = resolved_compiled.read_bytes()
            compiled_exe_sha256 = hashlib.sha256(compiled_bytes).hexdigest().lower()
            if installed_exe_sha256 == compiled_exe_sha256:
                compiled_exe_sha256_match = True
                exe_parity_mode = "exact_sha256"
                normalized_compiled_exe_sha256 = compiled_exe_sha256
            elif (
                len(compiled_bytes) == len(installed_bytes)
                and compiled_bytes.count(_TAURI_BUNDLE_MARKER_UNK) == 1
                and installed_bytes.count(_TAURI_BUNDLE_MARKER_NSS) == 1
            ):
                normalized_bytes = compiled_bytes.replace(
                    _TAURI_BUNDLE_MARKER_UNK,
                    _TAURI_BUNDLE_MARKER_NSS,
                    1,
                )
                normalized_compiled_exe_sha256 = (
                    hashlib.sha256(normalized_bytes).hexdigest().lower()
                )
                compiled_exe_sha256_match = installed_exe_sha256 == normalized_compiled_exe_sha256
                exe_parity_mode = (
                    "tauri_nsis_bundle_marker_normalized"
                    if compiled_exe_sha256_match
                    else "mismatch"
                )
            else:
                compiled_exe_sha256_match = False
                exe_parity_mode = "mismatch"

            if not compiled_exe_sha256_match:
                raise RuntimeError(
                    "Installed desktop executable SHA-256 mismatch vs compiled target/release exe: "
                    f"{installed_exe_sha256} != {compiled_exe_sha256}"
                )

        uninstall_proc = subprocess.run(  # noqa: S603 - explicit NSIS uninstaller in temp dir
            [str(uninstaller_exe), "/S", f"_?={install_dir}"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if uninstall_proc.returncode != 0:
            raise RuntimeError(
                f"NSIS silent uninstall failed (exit={uninstall_proc.returncode}): "
                f"{uninstall_proc.stderr or uninstall_proc.stdout}"
            )
        time.sleep(0.1)

    return {
        "status": "PASS",
        "installer_filename": installer.name,
        "installer_sha256": installer_sha256,
        "installer_size_bytes": installer_size,
        "sums_file_verified": sums_file_verified,
        "installed_exe_sha256": installed_exe_sha256,
        "compiled_exe_sha256": compiled_exe_sha256,
        "normalized_compiled_exe_sha256": normalized_compiled_exe_sha256,
        "compiled_exe_sha256_match": compiled_exe_sha256_match,
        "exe_parity_mode": exe_parity_mode,
        "uninstaller_verified": True,
        "clean_install_verified": True,
    }


def run_four_model_e2e_verification(
    root: Path = PROJECT_ROOT,
    *,
    installer_path: Optional[Path] = None,
    sums_file: Optional[Path] = None,
    compiled_exe_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Fail-closed live loopback E2E verification across all 4 models on demo_flows.csv."""
    resolved_root = Path(root).resolve()
    summary = verify_companion_artifacts(root=resolved_root)
    if summary["overall_status"] != "READY":
        raise RuntimeError(
            "Mandatory 4-model E2E gate BLOCKED: companion artifacts incomplete or unverified "
            f"(ready_models={summary['ready_models']}, demo_ready={summary['demo_ready']}, "
            f"demo_error={summary.get('demo_verification_error')})."
        )

    source_commit = _get_git_head_commit(resolved_root)
    desktop_version = _read_desktop_version(resolved_root)
    split_manifest_path = resolved_root / SPLIT_MANIFEST_REL
    if not split_manifest_path.is_file():
        raise RuntimeError(f"Missing split manifest: {split_manifest_path}")
    split_manifest_sha256 = _sha256_file(split_manifest_path).lower()

    demo_flows = resolved_root / "data/demo/demo_flows.csv"
    demo_labels = resolved_root / "data/demo/demo_labels.csv"
    run_api_script = resolved_root / "scripts/run_api.py"
    if not run_api_script.is_file():
        raise RuntimeError(f"Missing server entrypoint: {run_api_script}")

    tmp_dir = tempfile.TemporaryDirectory(prefix="netflow_e2e_")
    db_path = Path(tmp_dir.name) / "e2e_verify.db"
    log_path = Path(tmp_dir.name) / "run_api.log"

    env = os.environ.copy()
    src_path = str(resolved_root / "src")
    existing_py = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{existing_py}" if existing_py else src_path

    proc: Optional[subprocess.Popen[str]] = None
    try:
        proc, base_url = _start_api_process(resolved_root, run_api_script, db_path, log_path, env)
        port = int(base_url.rsplit(":", 1)[1])

        _, models_payload = _http_json(f"{base_url}/api/v1/models", timeout=10.0)
        models_by_key = {item["model_key"]: item for item in models_payload}
        for key in MODEL_SPECS:
            entry = models_by_key.get(key)
            if not entry or not entry.get("ready") or entry.get("status") != "READY":
                raise RuntimeError(f"Model {key!r} is not READY in /api/v1/models: {entry}")

        expected_flows_sha = summary["demo"]["data/demo/demo_flows.csv"]["sha256"]
        expected_labels_sha = summary["demo"]["data/demo/demo_labels.csv"]["sha256"]
        expected_prep_sha = summary["preprocessor"]["sha256"]

        per_model_results: Dict[str, Any] = {}
        for key in MODEL_SPECS:
            _, az = _http_json(
                f"{base_url}/api/v1/csv/analyze",
                method="POST",
                payload={
                    "file_path": str(demo_flows),
                    "model_name": key,
                    "batch_size": 100,
                    "create_incidents": False,
                },
                timeout=30.0,
            )
            if az.get("inference_mode") != "verified_model":
                raise RuntimeError(
                    f"{key}: expected verified_model, got {az.get('inference_mode')}"
                )
            if az.get("file_sha256") != expected_flows_sha:
                raise RuntimeError(
                    f"{key}: analyze file_sha256 mismatch ({az.get('file_sha256')} != {expected_flows_sha})"
                )
            if az.get("preprocessor_sha256") != expected_prep_sha:
                raise RuntimeError(
                    f"{key}: analyze preprocessor_sha256 mismatch ({az.get('preprocessor_sha256')} != {expected_prep_sha})"
                )
            gate = az.get("compatibility_gate") or {}
            expected_compat = "MODEL_VALIDATED" if key == "random_forest" else "RESEARCH_ONLY"
            if (
                gate.get("source_id") != "source:nf-v3-canonical"
                or gate.get("provenance_verified") is not True
                or gate.get("compatibility_status") != expected_compat
            ):
                raise RuntimeError(f"{key}: unexpected compatibility_gate: {gate}")

            results = az.get("results") or []
            non_ood = [r for r in results if not r.get("is_ood_flagged")]
            ood_rows = [r for r in results if r.get("is_ood_flagged")]
            if az.get("total_rows") != 200 or len(non_ood) != 198 or len(ood_rows) != 2:
                raise RuntimeError(
                    f"{key}: unexpected OOD split total={az.get('total_rows')}, "
                    f"non_ood={len(non_ood)}, ood={len(ood_rows)}"
                )
            if key in ("random_forest", "xgboost"):
                if any(r.get("attack_probability") is None for r in non_ood):
                    raise RuntimeError(f"{key}: missing attack_probability on non-OOD rows")
            else:
                if any(r.get("attack_probability") is not None for r in results):
                    raise RuntimeError(f"{key}: unsupervised model leaked attack_probability")
                if any(r.get("raw_anomaly_score") is None for r in non_ood):
                    raise RuntimeError(f"{key}: missing raw_anomaly_score on non-OOD rows")

            _, ev = _http_json(
                f"{base_url}/api/v1/csv/evaluate",
                method="POST",
                payload={"labels_path": str(demo_labels), "predictions": results},
                timeout=15.0,
            )
            if ev.get("labels_sha256") != expected_labels_sha:
                raise RuntimeError(
                    f"{key}: evaluate labels_sha256 mismatch ({ev.get('labels_sha256')} != {expected_labels_sha})"
                )
            cm = ev["confusion_matrix"]
            if cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"] != 198 or ev.get("abstained_rows") != 2:
                raise RuntimeError(f"{key}: invalid confusion matrix coverage: {ev}")
            if key in ("random_forest", "xgboost") and (
                ev["f1"] < 0.99 or cm["tp"] != 100 or cm["tn"] != 98
            ):
                raise RuntimeError(f"{key}: unexpected supervised demo metrics: {ev}")
            if key == "isolation_forest" and (ev["f1"] < 0.80 or cm["tp"] < 80 or cm["tn"] < 80):
                raise RuntimeError(f"{key}: unexpected Isolation Forest demo metrics: {ev}")
            if key == "autoencoder" and (
                ev["f1"] < 0.15 or cm["tp"] < 10 or ev["false_positive_rate"] > 0.10
            ):
                raise RuntimeError(f"{key}: unexpected Autoencoder demo metrics: {ev}")

            _, sim = _http_json(
                f"{base_url}/api/v1/security/simulate-response",
                method="POST",
                payload={"analysis_id": az["analysis_id"], "dry_run": True},
                timeout=15.0,
            )
            if (
                sim.get("executed") is not False
                or sim.get("os_firewall_touched") is not False
                or sim.get("real_key_rotated") is not False
                or sim.get("provenance_verification") != "server_verified_analysis"
            ):
                raise RuntimeError(f"{key}: invalid Issue #27 dry-run provenance/flags: {sim}")

            ood_row_ids = {int(r["row_id"]) for r in ood_rows}
            for rec in sim.get("recommendations") or []:
                if int(rec["row_id"]) in ood_row_ids and (
                    rec.get("containment_allowed") is not False
                    or rec.get("action") == "ISOLATE_RECOMMENDED"
                ):
                    raise RuntimeError(f"{key}: OOD row received containment: {rec}")

            action_counts = sim.get("action_counts") or {}
            rot_decision = (sim.get("key_rotation_simulation") or {}).get("decision")
            if key == "random_forest":
                if int(action_counts.get("ISOLATE_RECOMMENDED", 0)) <= 0:
                    raise RuntimeError(
                        f"{key}: expected ISOLATE_RECOMMENDED > 0, got {action_counts}"
                    )
                if rot_decision != "SIMULATED_ROTATION_RECOMMENDED":
                    raise RuntimeError(
                        f"{key}: expected SIMULATED_ROTATION_RECOMMENDED, got {rot_decision}"
                    )
            else:
                if (
                    int(action_counts.get("ISOLATE_RECOMMENDED", 0)) != 0
                    or rot_decision != "HOLD_RESEARCH_ONLY_MODEL"
                ):
                    raise RuntimeError(
                        f"{key}: RESEARCH_ONLY model bypassed fail-closed gate: "
                        f"counts={action_counts}, rotation={rot_decision}"
                    )

            per_model_results[key] = {
                "analysis_id": az["analysis_id"],
                "run_id": az.get("run_id") or summary["models"][key].get("run_id"),
                "artifact_sha256": summary["models"][key]["sha256"],
                "preprocessor_sha256": az.get("preprocessor_sha256") or expected_prep_sha,
                "source_csv_sha256": az.get("file_sha256") or expected_flows_sha,
                "labels_sha256": ev.get("labels_sha256") or expected_labels_sha,
                "compatibility_status": gate["compatibility_status"],
                "inference_mode": az["inference_mode"],
                "total_rows": az["total_rows"],
                "evaluated_rows": az["evaluated_rows"],
                "abstained_rows": az["abstained_rows"],
                "confusion_matrix": cm,
                "accuracy": ev["accuracy"],
                "precision": ev["precision"],
                "recall": ev["recall"],
                "f1": ev["f1"],
                "fpr": ev["false_positive_rate"],
                "prediction_coverage": ev["prediction_coverage"],
                "dry_run_simulation_id": sim["simulation_id"],
                "dry_run_provenance": sim["provenance_verification"],
                "dry_run_action_counts": action_counts,
                "dry_run_rotation_decision": rot_decision,
            }

        # Verify client-supplied spoofing without analysis_id fails closed
        _, spoof_check = _http_json(
            f"{base_url}/api/v1/security/simulate-response",
            method="POST",
            payload={
                "model_key": "xgboost",
                "inference_mode": "verified_model",
                "compatibility_gate": {
                    "source_id": "source:nf-v3-canonical",
                    "provenance_verified": True,
                    "model_key": "xgboost",
                    "eligible": True,
                    "eligibility_status": "ELIGIBLE",
                    "compatibility_status": "MODEL_VALIDATED",
                },
                "results": [
                    {
                        "row_id": 1,
                        "row_index": 0,
                        "predicted_label": 1,
                        "predicted_class": "Attack",
                        "attack_probability": 0.99,
                        "raw_anomaly_score": 0.99,
                        "normalized_anomaly_score": 0.99,
                        "decision_threshold": 0.5,
                        "score_type": "attack_probability",
                        "score_direction": "higher_is_more_anomalous",
                        "risk_score": 99.0,
                        "risk_level": "CRITICAL",
                        "is_ood_flagged": False,
                    }
                ],
                "dry_run": True,
            },
            timeout=15.0,
        )
        if (
            spoof_check.get("provenance_verification") != "client_supplied_unverified"
            or spoof_check["recommendations"][0]["action"] != "INVESTIGATE"
            or spoof_check["recommendations"][0]["containment_allowed"] is not False
            or spoof_check["key_rotation_simulation"]["decision"] != "HOLD_UNVERIFIED_PROVENANCE"
        ):
            raise RuntimeError(f"Unverified client payload failed fail-closed check: {spoof_check}")

        report: Dict[str, Any] = {
            "e2e_status": "PASS",
            "host": "127.0.0.1",
            "port": port,
            "source_commit": source_commit,
            "desktop_version": desktop_version,
            "verify_script_sha256": _sha256_file(Path(__file__).resolve()),
            "split_manifest_sha256": split_manifest_sha256,
            "preprocessor_sha256": summary["preprocessor"]["sha256"],
            "demo_sha256": {rel: info["sha256"] for rel, info in summary["demo"].items()},
            "companion_status": summary["overall_status"],
            "ready_models": summary["ready_models"],
            "models": per_model_results,
            "client_spoof_fail_closed": {
                "provenance_verification": spoof_check["provenance_verification"],
                "critical_downgraded_action": spoof_check["recommendations"][0]["action"],
                "rotation_decision": spoof_check["key_rotation_simulation"]["decision"],
            },
        }
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        tmp_dir.cleanup()

    if installer_path is not None:
        report["nsis_e2e"] = verify_nsis_installer_e2e(
            installer_path=installer_path,
            root=resolved_root,
            sums_file=sums_file,
            compiled_exe_path=compiled_exe_path,
        )

    return report


def _validate_confusion_matrix_and_metrics(model_key: str, entry: Dict[str, Any]) -> None:
    if (
        type(entry.get("total_rows")) is not int
        or entry.get("total_rows") != 200
        or type(entry.get("evaluated_rows")) is not int
        or entry.get("evaluated_rows") != 198
        or type(entry.get("abstained_rows")) is not int
        or entry.get("abstained_rows") != 2
    ):
        raise RuntimeError(f"E2E attestation invalid row counts/OOD coverage for {model_key}")

    cm = entry.get("confusion_matrix")
    if not isinstance(cm, dict) or set(cm.keys()) != {"tn", "fp", "fn", "tp"}:
        raise RuntimeError(f"E2E attestation invalid confusion_matrix keys for {model_key}: {cm}")
    for field_name in ("tn", "fp", "fn", "tp"):
        if not _is_strict_nonneg_int(cm[field_name]):
            raise RuntimeError(
                f"E2E attestation confusion_matrix.{field_name} must be non-neg int for {model_key}"
            )

    tn, fp, fn, tp = cm["tn"], cm["fp"], cm["fn"], cm["tp"]
    if tn + fp + fn + tp != 198 or tn + fp != 98 or tp + fn != 100:
        raise RuntimeError(
            f"E2E attestation confusion_matrix counts do not match 98 benign + 100 attack for {model_key}: {cm}"
        )

    expected_metrics = {
        "accuracy": (tp + tn) / 198.0,
        "precision": tp / (tp + fp) if (tp + fp) > 0 else 0.0,
        "recall": tp / (tp + fn) if (tp + fn) > 0 else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
        "prediction_coverage": 198.0 / 200.0,
    }
    prec = expected_metrics["precision"]
    rec = expected_metrics["recall"]
    expected_metrics["f1"] = (2.0 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

    for metric_name, calc_val in expected_metrics.items():
        recorded = entry.get(metric_name)
        if not _is_finite_number(recorded):
            raise RuntimeError(
                f"E2E attestation non-finite or missing metric {metric_name!r} for {model_key}: {recorded!r}"
            )
        if abs(float(recorded) - calc_val) > 1e-5:
            raise RuntimeError(
                f"E2E attestation metric inconsistency for {model_key}.{metric_name}: "
                f"recorded={recorded}, recalculated={calc_val}"
            )

    f1_val = float(entry["f1"])
    fpr_val = float(entry["fpr"])
    if model_key in ("random_forest", "xgboost"):
        if tp != 100 or tn != 98 or fp != 0 or fn != 0 or f1_val < 0.99:
            raise RuntimeError(
                f"E2E attestation {model_key} failed supervised threshold gate: cm={cm}, f1={f1_val}"
            )
    elif model_key == "isolation_forest":
        if f1_val < 0.80 or tp < 80 or tn < 80:
            raise RuntimeError(
                f"E2E attestation isolation_forest failed threshold gate: cm={cm}, f1={f1_val}"
            )
    elif model_key == "autoencoder":
        if f1_val < 0.15 or tp < 10 or fpr_val > 0.10:
            raise RuntimeError(
                f"E2E attestation autoencoder failed threshold gate: cm={cm}, f1={f1_val}, fpr={fpr_val}"
            )


def _validate_dry_run_gate(model_key: str, entry: Dict[str, Any]) -> None:
    if entry.get("dry_run_provenance") != "server_verified_analysis":
        raise RuntimeError(f"E2E attestation invalid dry-run provenance for {model_key}")
    action_counts = entry.get("dry_run_action_counts")
    if not isinstance(action_counts, dict) or set(action_counts.keys()) != set(_ACTION_COUNT_KEYS):
        raise RuntimeError(
            f"E2E attestation invalid dry_run_action_counts keys for {model_key}: {action_counts}"
        )
    for act_key in _ACTION_COUNT_KEYS:
        if not _is_strict_nonneg_int(action_counts[act_key]):
            raise RuntimeError(
                f"E2E attestation invalid action count {act_key} for {model_key}: {action_counts}"
            )
    if sum(action_counts.values()) != 200:
        raise RuntimeError(
            f"E2E attestation dry_run_action_counts sum != 200 for {model_key}: {action_counts}"
        )

    compat = entry.get("compatibility_status")
    rot = entry.get("dry_run_rotation_decision")
    if model_key == "random_forest":
        if (
            compat != "MODEL_VALIDATED"
            or rot != "SIMULATED_ROTATION_RECOMMENDED"
            or action_counts["ISOLATE_RECOMMENDED"] <= 0
        ):
            raise RuntimeError(
                f"E2E attestation invalid validated containment/rotation gate for {model_key}"
            )
    else:
        if (
            compat != "RESEARCH_ONLY"
            or rot != "HOLD_RESEARCH_ONLY_MODEL"
            or action_counts["ISOLATE_RECOMMENDED"] != 0
        ):
            raise RuntimeError(
                f"E2E attestation RESEARCH_ONLY containment bypass detected for {model_key}"
            )


def verify_e2e_attestation(
    attestation_path: Path,
    root: Path = PROJECT_ROOT,
    *,
    expect_commit: Optional[str] = None,
    expect_installer_sha256: Optional[str] = None,
    require_nsis_e2e: bool = False,
) -> Dict[str, Any]:
    """Verify a 4-model E2E attestation JSON against tracked manifests, commit, demo, and NSIS E2E."""
    resolved_root = Path(root).resolve()
    report = _read_json_dict(Path(attestation_path), "E2E attestation JSON")
    if report.get("e2e_status") != "PASS" or report.get("companion_status") != "READY":
        raise RuntimeError(f"E2E attestation did not record PASS/READY: {attestation_path}")

    expected_models_order = list(MODEL_SPECS.keys())
    if report.get("ready_models") != expected_models_order:
        raise RuntimeError(
            f"E2E attestation ready_models must equal {expected_models_order}, got {report.get('ready_models')!r}"
        )
    models_report = report.get("models")
    if not isinstance(models_report, dict) or set(models_report.keys()) != set(MODEL_SPECS.keys()):
        raise RuntimeError(f"E2E attestation models keys must equal {expected_models_order}")

    actual_script_sha = _sha256_file(
        resolved_root / "scripts/verify_companion_artifacts.py"
    ).lower()
    if report.get("verify_script_sha256") != actual_script_sha:
        raise RuntimeError(
            "E2E attestation is stale: scripts/verify_companion_artifacts.py SHA-256 changed "
            f"({report.get('verify_script_sha256')} != {actual_script_sha})."
        )

    source_commit = report.get("source_commit")
    if not isinstance(source_commit, str) or not _GIT_COMMIT_RE.fullmatch(source_commit):
        raise RuntimeError(
            f"E2E attestation missing or invalid 40-char source_commit: {source_commit!r}"
        )
    if (resolved_root / ".git").exists():
        cat_proc = subprocess.run(  # noqa: S603 - fixed local git object existence check
            ["git", "cat-file", "-e", f"{source_commit}^{{commit}}"],
            cwd=str(resolved_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if cat_proc.returncode != 0:
            raise RuntimeError(
                f"E2E attestation source_commit {source_commit!r} is not a valid commit in {resolved_root}"
            )
    if expect_commit is not None:
        normalized_expect_commit = expect_commit.strip().lower()
        if source_commit != normalized_expect_commit:
            raise RuntimeError(
                f"E2E attestation source_commit mismatch: expected {normalized_expect_commit}, got {source_commit}"
            )

    desktop_version = report.get("desktop_version")
    if not isinstance(desktop_version, str) or not desktop_version.strip():
        raise RuntimeError(f"E2E attestation missing desktop_version: {desktop_version!r}")
    pkg_json_path = resolved_root / "desktop/package.json"
    if pkg_json_path.is_file():
        expected_desktop_version = _read_desktop_version(resolved_root)
        if desktop_version != expected_desktop_version:
            raise RuntimeError(
                f"E2E attestation desktop_version mismatch: {desktop_version!r} != {expected_desktop_version!r}"
            )

    split_manifest_path = resolved_root / SPLIT_MANIFEST_REL
    if not split_manifest_path.is_file():
        raise RuntimeError(f"Missing tracked split manifest: {split_manifest_path}")
    actual_split_sha = _sha256_file(split_manifest_path).lower()
    if report.get("split_manifest_sha256") != actual_split_sha:
        raise RuntimeError(
            "E2E attestation split_manifest_sha256 mismatch with tracked split manifest."
        )

    expected_demo_keys = {p.as_posix() for p in DEMO_FILES_REL}
    demo_sha256 = report.get("demo_sha256")
    if not isinstance(demo_sha256, dict) or set(demo_sha256.keys()) != expected_demo_keys:
        raise RuntimeError(
            f"E2E attestation demo_sha256 must contain exactly {sorted(expected_demo_keys)}"
        )
    for rel_str in expected_demo_keys:
        recorded_sha = demo_sha256.get(rel_str)
        if not _is_hex_sha256(recorded_sha):
            raise RuntimeError(f"E2E attestation invalid SHA-256 for {rel_str}: {recorded_sha!r}")
        file_abs = resolved_root / rel_str
        if not file_abs.is_file():
            raise RuntimeError(f"Missing tracked demo file: {file_abs}")
        actual_demo_sha = _sha256_file(file_abs).lower()
        if recorded_sha != actual_demo_sha:
            raise RuntimeError(
                f"E2E attestation demo_sha256 mismatch for {rel_str}: {recorded_sha} != {actual_demo_sha}"
            )

    demo_manifest = _read_json_dict(
        resolved_root / "data/demo/demo_manifest.json", "data/demo/demo_manifest.json"
    )
    sampling = demo_manifest.get("sampling") or {}
    if sampling.get("partition") != "validation":
        raise RuntimeError(
            f"demo_manifest sampling.partition must be 'validation', got {sampling.get('partition')!r}"
        )
    if (
        int(sampling.get("train_overlap_count", -1)) != 0
        or int(sampling.get("test_overlap_count", -1)) != 0
    ):
        raise RuntimeError("demo_manifest records non-zero train/test overlap")
    outputs = demo_manifest.get("outputs") or {}
    if (outputs.get("demo_flows_csv") or {}).get("sha256") != demo_sha256[
        "data/demo/demo_flows.csv"
    ]:
        raise RuntimeError("demo_manifest demo_flows_csv.sha256 mismatch with demo_sha256")
    if (outputs.get("demo_labels_csv") or {}).get("sha256") != demo_sha256[
        "data/demo/demo_labels.csv"
    ]:
        raise RuntimeError("demo_manifest demo_labels_csv.sha256 mismatch with demo_sha256")
    if demo_manifest.get("split_manifest_sha256") != actual_split_sha:
        raise RuntimeError("demo_manifest split_manifest_sha256 mismatch with split manifest")

    prep_manifest = _read_json_dict(
        resolved_root / PREPROCESSOR_MANIFEST_REL, str(PREPROCESSOR_MANIFEST_REL)
    )
    report_prep_sha = report.get("preprocessor_sha256")
    if not _is_hex_sha256(report_prep_sha) or report_prep_sha != prep_manifest.get(
        "artifact_sha256"
    ):
        raise RuntimeError("E2E attestation preprocessor_sha256 does not match tracked manifest.")
    if prep_manifest.get("split_manifest_sha256") != actual_split_sha:
        raise RuntimeError(
            "Tracked preprocessor manifest split_manifest_sha256 does not match split manifest."
        )

    analysis_ids: List[str] = []
    simulation_ids: List[str] = []

    for model_key, (_, manifest_candidates) in MODEL_SPECS.items():
        entry = models_report.get(model_key)
        if not isinstance(entry, dict):
            raise RuntimeError(f"E2E attestation missing model entry object for {model_key}")
        tracked_manifest = _read_json_dict(
            resolved_root / manifest_candidates[0], str(manifest_candidates[0])
        )
        expected_sha = (
            tracked_manifest.get("model_artifact_sha256")
            or tracked_manifest.get("model_sha256")
            or tracked_manifest.get("artifact_sha256")
        )
        if entry.get("artifact_sha256") != expected_sha:
            raise RuntimeError(
                f"E2E attestation artifact_sha256 mismatch for {model_key}: "
                f"{entry.get('artifact_sha256')} != {expected_sha}"
            )

        expected_run_id = tracked_manifest.get("run_id")
        if (
            not isinstance(expected_run_id, str)
            or not expected_run_id.strip()
            or entry.get("run_id") != expected_run_id
        ):
            raise RuntimeError(
                f"E2E attestation run_id mismatch for {model_key}: "
                f"{entry.get('run_id')!r} != {expected_run_id!r}"
            )

        manifest_prep_sha = _resolve_manifest_preprocessor_sha256(tracked_manifest)
        if (
            entry.get("preprocessor_sha256") != report_prep_sha
            or not manifest_prep_sha
            or entry.get("preprocessor_sha256") != manifest_prep_sha
        ):
            raise RuntimeError(
                f"E2E attestation preprocessor_sha256 mismatch for {model_key}: "
                f"entry={entry.get('preprocessor_sha256')!r}, manifest={manifest_prep_sha!r}"
            )

        if (
            tracked_manifest.get("split_manifest_sha256") is not None
            and tracked_manifest.get("split_manifest_sha256") != actual_split_sha
        ):
            raise RuntimeError(f"Tracked manifest split_manifest_sha256 mismatch for {model_key}")

        if entry.get("source_csv_sha256") != demo_sha256["data/demo/demo_flows.csv"]:
            raise RuntimeError(f"E2E attestation source_csv_sha256 mismatch for {model_key}")
        if entry.get("labels_sha256") != demo_sha256["data/demo/demo_labels.csv"]:
            raise RuntimeError(f"E2E attestation labels_sha256 mismatch for {model_key}")

        if entry.get("inference_mode") != "verified_model":
            raise RuntimeError(f"E2E attestation invalid inference_mode for {model_key}")

        if model_key == "autoencoder":
            th_cal = tracked_manifest.get("threshold_calibration")
            if not isinstance(th_cal, dict) or th_cal.get("threshold_frozen") is not True:
                raise RuntimeError(
                    "Autoencoder manifest threshold_calibration.threshold_frozen must be True"
                )
            emp_fpr = th_cal.get("empirical_val_fpr")
            target_fpr = th_cal.get("target_fpr")
            if (
                not _is_finite_number(emp_fpr)
                or not _is_finite_number(target_fpr)
                or float(emp_fpr) < 0.0
                or float(emp_fpr) > float(target_fpr)
                or float(target_fpr) > 0.05
            ):
                raise RuntimeError(
                    f"Autoencoder manifest empirical_val_fpr/target_fpr violates <= 0.05 constraint: {th_cal}"
                )

        _validate_confusion_matrix_and_metrics(model_key, entry)
        _validate_dry_run_gate(model_key, entry)

        aid = entry.get("analysis_id")
        sid = entry.get("dry_run_simulation_id")
        if not isinstance(aid, str) or not aid.startswith("csvrun_") or len(aid) <= len("csvrun_"):
            raise RuntimeError(f"E2E attestation invalid analysis_id for {model_key}: {aid!r}")
        if not isinstance(sid, str) or not sid.startswith("sim_") or len(sid) <= len("sim_"):
            raise RuntimeError(
                f"E2E attestation invalid dry_run_simulation_id for {model_key}: {sid!r}"
            )
        analysis_ids.append(aid)
        simulation_ids.append(sid)

    if len(set(analysis_ids)) != len(MODEL_SPECS):
        raise RuntimeError(f"E2E attestation analysis_id values are not unique: {analysis_ids}")
    if len(set(simulation_ids)) != len(MODEL_SPECS):
        raise RuntimeError(
            f"E2E attestation dry_run_simulation_id values are not unique: {simulation_ids}"
        )

    spoof = report.get("client_spoof_fail_closed")
    if (
        not isinstance(spoof, dict)
        or spoof.get("provenance_verification") != "client_supplied_unverified"
        or spoof.get("critical_downgraded_action") != "INVESTIGATE"
        or spoof.get("rotation_decision") != "HOLD_UNVERIFIED_PROVENANCE"
    ):
        raise RuntimeError(f"E2E attestation missing valid anti-spoof verification: {spoof}")

    nsis_present = "nsis_e2e" in report
    if require_nsis_e2e or expect_installer_sha256 is not None or nsis_present:
        nsis = report.get("nsis_e2e")
        if not isinstance(nsis, dict):
            raise RuntimeError("E2E attestation missing required 'nsis_e2e' verification block")
        if (
            nsis.get("status") != "PASS"
            or nsis.get("clean_install_verified") is not True
            or nsis.get("uninstaller_verified") is not True
            or nsis.get("compiled_exe_sha256_match") is not True
        ):
            raise RuntimeError(f"E2E attestation invalid nsis_e2e verification flags: {nsis}")
        inst_size = nsis.get("installer_size_bytes")
        if type(inst_size) is not int or inst_size < 1_000_000:
            raise RuntimeError(
                f"E2E attestation invalid nsis_e2e installer_size_bytes: {inst_size!r}"
            )
        inst_sha = nsis.get("installer_sha256")
        exe_sha = nsis.get("installed_exe_sha256")
        if not _is_hex_sha256(inst_sha) or not _is_hex_sha256(exe_sha):
            raise RuntimeError("E2E attestation nsis_e2e missing valid 64-hex SHA-256 digests")
        if expect_installer_sha256 is not None:
            expected_inst = expect_installer_sha256.strip().lower()
            if not _is_hex_sha256(expected_inst) or inst_sha != expected_inst:
                raise RuntimeError(
                    f"E2E attestation nsis_e2e.installer_sha256 mismatch: "
                    f"{inst_sha} != {expected_inst}"
                )

    return {
        "attestation_status": "PASS",
        "attestation_path": str(attestation_path),
        "verified_models": list(MODEL_SPECS.keys()),
        "verify_script_sha256": actual_script_sha,
        "source_commit": source_commit,
        "desktop_version": desktop_version,
        "split_manifest_sha256": actual_split_sha,
        "nsis_e2e_verified": isinstance(report.get("nsis_e2e"), dict),
    }


def _emit_json(payload: Dict[str, Any], output_json: Optional[Path]) -> None:
    payload_text = json.dumps(payload, indent=2)
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(payload_text + "\n", encoding="utf-8", newline="\n")
    print(payload_text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify or stage NetFlow Sentinel companion artifacts (preprocessor, 4 models, demo CSV)."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository root to inspect (defaults to project root).",
    )
    parser.add_argument(
        "--stage-dir",
        type=Path,
        default=None,
        help="Optional directory to stage verified companion files + COMPANION_SHA256SUMS.txt.",
    )
    parser.add_argument(
        "--verify-e2e",
        action="store_true",
        help="Run mandatory live 127.0.0.1 FastAPI 4-model E2E verification on real demo CSV (fails closed).",
    )
    parser.add_argument(
        "--verify-nsis-only",
        action="store_true",
        help="Run clean Windows NSIS silent install/exe SHA-256 parity/uninstall verification only.",
    )
    parser.add_argument(
        "--installer-path",
        type=Path,
        default=None,
        help="Path to NSIS Windows x64 setup executable for clean-install E2E verification.",
    )
    parser.add_argument(
        "--sums-file",
        type=Path,
        default=None,
        help="Optional SHA256SUMS.txt path to verify the NSIS installer digest against.",
    )
    parser.add_argument(
        "--compiled-exe",
        type=Path,
        default=None,
        help="Optional compiled release desktop .exe path for installed binary parity verification.",
    )
    parser.add_argument(
        "--verify-attestation",
        type=Path,
        default=None,
        help="Verify a 4-model E2E JSON attestation against tracked manifests.",
    )
    parser.add_argument(
        "--expect-commit",
        type=str,
        default=None,
        help="Expected 40-char git commit SHA when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--expect-installer-sha256",
        type=str,
        default=None,
        help="Expected 64-char NSIS installer SHA-256 when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--require-nsis-e2e",
        action="store_true",
        help="Require a valid nsis_e2e verification block when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional output path to write JSON verification report.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.stage_dir is not None:
        try:
            staged = stage_companion_bundle(destination=args.stage_dir, root=args.root)
        except Exception as exc:
            sys.stderr.write(f"[COMPANION ARTIFACTS BLOCKED] {exc}\n")
            return 1
        _emit_json(staged, args.output_json)
        return 0

    if args.verify_attestation is not None:
        try:
            att_report = verify_e2e_attestation(
                args.verify_attestation,
                root=args.root,
                expect_commit=args.expect_commit,
                expect_installer_sha256=args.expect_installer_sha256,
                require_nsis_e2e=args.require_nsis_e2e,
            )
        except Exception as exc:
            sys.stderr.write(f"[E2E ATTESTATION VERIFICATION FAILED] {exc}\n")
            return 1
        _emit_json(att_report, args.output_json)
        return 0

    if args.verify_nsis_only:
        if args.installer_path is None:
            sys.stderr.write("[NSIS E2E FAILED] --verify-nsis-only requires --installer-path.\n")
            return 1
        try:
            nsis_report = verify_nsis_installer_e2e(
                installer_path=args.installer_path,
                root=args.root,
                sums_file=args.sums_file,
                compiled_exe_path=args.compiled_exe,
            )
        except Exception as exc:
            sys.stderr.write(f"[NSIS E2E FAILED] {exc}\n")
            return 1
        _emit_json(nsis_report, args.output_json)
        return 0

    if args.verify_e2e:
        try:
            e2e_report = run_four_model_e2e_verification(
                root=args.root,
                installer_path=args.installer_path,
                sums_file=args.sums_file,
                compiled_exe_path=args.compiled_exe,
            )
        except Exception as exc:
            sys.stderr.write(f"[E2E VERIFICATION BLOCKED/FAILED] {exc}\n")
            return 1
        _emit_json(e2e_report, args.output_json)
        return 0

    summary = verify_companion_artifacts(root=args.root)
    _emit_json(summary, args.output_json)
    return 0 if summary["overall_status"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
