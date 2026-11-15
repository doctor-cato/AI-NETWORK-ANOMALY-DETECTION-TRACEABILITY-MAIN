#!/usr/bin/env python3
"""Audit and stage NetFlow Sentinel v0.6.0 companion model artifacts on Windows.

Verifies SHA-256 digests and manifest linkage across the preprocessor, 4 verified
ML models (Random Forest, XGBoost, Isolation Forest, Autoencoder), and Validation
demo CSV bundle without copying or bundling raw NF-UNSW-NB15-v3 dataset files.
"""

from __future__ import annotations

import argparse
import json
import os
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

    all_four_ready = prep_status["ready"] and len(ready_models) == len(MODEL_SPECS) and demo_ready
    unique_staged = sorted({p.as_posix() for p in staged_files})

    return {
        "overall_status": "READY" if all_four_ready else "BLOCKED / NOT READY",
        "ready_models": ready_models,
        "preprocessor": prep_status,
        "models": models_status,
        "demo": demo_status,
        "demo_ready": demo_ready,
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


def run_four_model_e2e_verification(root: Path = PROJECT_ROOT) -> Dict[str, Any]:
    """Fail-closed live loopback E2E verification across all 4 models on demo_flows.csv."""
    resolved_root = Path(root).resolve()
    summary = verify_companion_artifacts(root=resolved_root)
    if summary["overall_status"] != "READY":
        raise RuntimeError(
            "Mandatory 4-model E2E gate BLOCKED: companion artifacts incomplete or unverified "
            f"(ready_models={summary['ready_models']}, demo_ready={summary['demo_ready']})."
        )

    demo_flows = resolved_root / "data/demo/demo_flows.csv"
    demo_labels = resolved_root / "data/demo/demo_labels.csv"
    run_api_script = resolved_root / "scripts/run_api.py"
    if not run_api_script.is_file():
        raise RuntimeError(f"Missing server entrypoint: {run_api_script}")

    port = _find_free_loopback_port()
    base_url = f"http://127.0.0.1:{port}"
    tmp_dir = tempfile.TemporaryDirectory(prefix="netflow_e2e_")
    db_path = Path(tmp_dir.name) / "e2e_verify.db"

    env = os.environ.copy()
    src_path = str(resolved_root / "src")
    existing_py = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{existing_py}" if existing_py else src_path

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
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        deadline = time.monotonic() + 25.0
        health_payload: Optional[Dict[str, Any]] = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                output = proc.stdout.read() if proc.stdout else ""
                raise RuntimeError(f"run_api.py exited early ({proc.returncode}): {output}")
            try:
                status_code, health_payload = _http_json(f"{base_url}/api/v1/health", timeout=2.0)
                if status_code == 200:
                    break
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(0.25)

        if health_payload is None:
            raise RuntimeError("Timed out waiting for FastAPI /api/v1/health on 127.0.0.1.")

        _, models_payload = _http_json(f"{base_url}/api/v1/models", timeout=10.0)
        models_by_key = {item["model_key"]: item for item in models_payload}
        for key in MODEL_SPECS:
            entry = models_by_key.get(key)
            if not entry or not entry.get("ready") or entry.get("status") != "READY":
                raise RuntimeError(f"Model {key!r} is not READY in /api/v1/models: {entry}")

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
            cm = ev["confusion_matrix"]
            if cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"] != 198 or ev.get("abstained_rows") != 2:
                raise RuntimeError(f"{key}: invalid confusion matrix coverage: {ev}")

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

            per_model_results[key] = {
                "analysis_id": az["analysis_id"],
                "inference_mode": az["inference_mode"],
                "evaluated_rows": az["evaluated_rows"],
                "abstained_rows": az["abstained_rows"],
                "confusion_matrix": cm,
                "precision": ev["precision"],
                "recall": ev["recall"],
                "f1": ev["f1"],
                "fpr": ev["false_positive_rate"],
                "prediction_coverage": ev["prediction_coverage"],
                "dry_run_simulation_id": sim["simulation_id"],
                "dry_run_provenance": sim["provenance_verification"],
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

        return {
            "e2e_status": "PASS",
            "host": "127.0.0.1",
            "port": port,
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
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        tmp_dir.cleanup()


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
        payload_text = json.dumps(staged, indent=2)
        if args.output_json is not None:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(payload_text + "\n", encoding="utf-8")
        print(payload_text)
        return 0

    if args.verify_e2e:
        try:
            e2e_report = run_four_model_e2e_verification(root=args.root)
        except Exception as exc:
            sys.stderr.write(f"[E2E VERIFICATION BLOCKED/FAILED] {exc}\n")
            return 1
        payload_text = json.dumps(e2e_report, indent=2)
        if args.output_json is not None:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(payload_text + "\n", encoding="utf-8")
        print(payload_text)
        return 0

    summary = verify_companion_artifacts(root=args.root)
    payload_text = json.dumps(summary, indent=2)
    if args.output_json is not None:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(payload_text + "\n", encoding="utf-8")
    print(payload_text)
    return 0 if summary["overall_status"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
