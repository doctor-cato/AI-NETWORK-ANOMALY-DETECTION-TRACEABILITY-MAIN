"""Unit tests for companion artifact verification, NSIS E2E, and attestation checks."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import shutil
import subprocess
import urllib.request
import zipfile
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest

import scripts.verify_companion_artifacts as vca
from scripts.verify_companion_artifacts import (
    install_companion_bundle,
    package_companion_bundle,
    run_four_model_e2e_verification,
    stage_companion_bundle,
    verify_companion_artifacts,
    verify_e2e_attestation,
    verify_nsis_installer_e2e,
)
from scripts.verify_companion_artifacts import (
    main as verify_companion_main,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _head_commit(root: Path) -> str:
    git_dir = root / ".git"
    if git_dir.exists():
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and len(proc.stdout.strip()) == 40:
            return proc.stdout.strip().lower()
    return "a" * 40


def _recompute_model_metrics(tn: int, fp: int, fn: int, tp: int) -> Dict[str, float]:
    total_eval = tn + fp + fn + tp
    accuracy = (tp + tn) / total_eval
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "prediction_coverage": total_eval / 200.0,
    }


def _copy_attestation_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    rel_files = [
        "scripts/verify_companion_artifacts.py",
        "desktop/package.json",
        "data/V2_SPLIT_MANIFEST.json",
        "reports/preprocessing/v2_flow_preprocessing_manifest.json",
        "reports/models/random_forest_manifest.json",
        "reports/models/xgboost_manifest.json",
        "reports/models/isolation_forest_manifest.json",
        "reports/models/autoencoder_manifest.json",
    ]
    for rel in rel_files:
        src = REPO_ROOT / rel
        dst = ws / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    demo_dir = ws / "data/demo"
    demo_dir.mkdir(parents=True, exist_ok=True)
    flows_path = demo_dir / "demo_flows.csv"
    labels_path = demo_dir / "demo_labels.csv"
    flows_path.write_text(
        "duration_ms,bytes_in,bytes_out\n10.0,100,200\n20.0,300,400\n",
        encoding="utf-8",
        newline="\n",
    )
    labels_path.write_text("row_index,label_binary\n0,0\n1,1\n", encoding="utf-8", newline="\n")
    split_sha = _sha256_path(ws / "data/V2_SPLIT_MANIFEST.json")
    demo_manifest_payload = {
        "split_manifest_sha256": split_sha,
        "sampling": {
            "partition": "validation",
            "train_overlap_count": 0,
            "test_overlap_count": 0,
        },
        "outputs": {
            "demo_flows_csv": {"sha256": _sha256_path(flows_path)},
            "demo_labels_csv": {"sha256": _sha256_path(labels_path)},
        },
    }
    (demo_dir / "demo_manifest.json").write_text(
        json.dumps(demo_manifest_payload, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return ws


def _build_valid_attestation_payload(
    root: Path,
    *,
    include_nsis: bool = True,
    commit: str | None = None,
) -> Dict[str, Any]:
    split_sha = _sha256_path(root / "data/V2_SPLIT_MANIFEST.json")
    prep_manifest = json.loads(
        (root / "reports/preprocessing/v2_flow_preprocessing_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    prep_sha = prep_manifest["artifact_sha256"]
    desktop_pkg = json.loads((root / "desktop/package.json").read_text(encoding="utf-8"))
    demo_rels = [
        "data/demo/demo_flows.csv",
        "data/demo/demo_labels.csv",
        "data/demo/demo_manifest.json",
    ]
    if all((root / rel).is_file() for rel in demo_rels):
        demo_sha256 = {rel: _sha256_path(root / rel) for rel in demo_rels}
    else:
        # Demo CSV files are .gitignored on clean CI checkouts; reuse historical demo_sha256 only
        tracked_att_path = root / "reports/releases/v0.6.0_e2e_verification.json"
        if not tracked_att_path.is_file():
            tracked_att_path = REPO_ROOT / "reports/releases/v0.6.0_e2e_verification.json"
        tracked_att = json.loads(tracked_att_path.read_text(encoding="utf-8"))
        demo_sha256 = dict(tracked_att["demo_sha256"])

    cm_specs = {
        "random_forest": (98, 0, 0, 100),
        "xgboost": (98, 0, 0, 100),
        "isolation_forest": (90, 8, 8, 92),
        "autoencoder": (95, 3, 80, 20),
    }
    action_specs = {
        "random_forest": {
            "NO_ACTION": 98,
            "MONITOR": 2,
            "INVESTIGATE": 0,
            "ISOLATE_RECOMMENDED": 100,
        },
        "xgboost": {
            "NO_ACTION": 98,
            "MONITOR": 2,
            "INVESTIGATE": 100,
            "ISOLATE_RECOMMENDED": 0,
        },
        "isolation_forest": {
            "NO_ACTION": 90,
            "MONITOR": 10,
            "INVESTIGATE": 100,
            "ISOLATE_RECOMMENDED": 0,
        },
        "autoencoder": {
            "NO_ACTION": 95,
            "MONITOR": 82,
            "INVESTIGATE": 23,
            "ISOLATE_RECOMMENDED": 0,
        },
    }
    manifest_paths = {
        "random_forest": "reports/models/random_forest_manifest.json",
        "xgboost": "reports/models/xgboost_manifest.json",
        "isolation_forest": "reports/models/isolation_forest_manifest.json",
        "autoencoder": "reports/models/autoencoder_manifest.json",
    }

    models_payload: Dict[str, Any] = {}
    for key, (tn, fp, fn, tp) in cm_specs.items():
        manifest = json.loads((root / manifest_paths[key]).read_text(encoding="utf-8"))
        art_sha = (
            manifest.get("model_artifact_sha256")
            or manifest.get("model_sha256")
            or manifest.get("artifact_sha256")
        )
        metrics = _recompute_model_metrics(tn, fp, fn, tp)
        is_rf = key == "random_forest"
        models_payload[key] = {
            "artifact_sha256": art_sha,
            "run_id": manifest["run_id"],
            "inference_run_id": f"inference-20261115193743-{key[:6]}",
            "preprocessor_sha256": prep_sha,
            "source_csv_sha256": demo_sha256["data/demo/demo_flows.csv"],
            "labels_sha256": demo_sha256["data/demo/demo_labels.csv"],
            "inference_mode": "verified_model",
            "analysis_id": f"csvrun_{key}_001",
            "dry_run_simulation_id": f"sim_{key}_001",
            "total_rows": 200,
            "evaluated_rows": 198,
            "abstained_rows": 2,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            **metrics,
            "compatibility_status": "MODEL_VALIDATED" if is_rf else "RESEARCH_ONLY",
            "dry_run_provenance": "server_verified_analysis",
            "dry_run_rotation_decision": (
                "SIMULATED_ROTATION_RECOMMENDED" if is_rf else "HOLD_RESEARCH_ONLY_MODEL"
            ),
            "dry_run_action_counts": action_specs[key],
        }

    payload: Dict[str, Any] = {
        "e2e_status": "PASS",
        "e2e_backend_origin": "installed_nsis_desktop" if include_nsis else "api_only_run_api",
        "companion_status": "READY",
        "ready_models": list(cm_specs.keys()),
        "verify_script_sha256": _sha256_path(root / "scripts/verify_companion_artifacts.py"),
        "source_commit": commit if commit is not None else _head_commit(root),
        "desktop_version": desktop_pkg["version"],
        "split_manifest_sha256": split_sha,
        "preprocessor_sha256": prep_sha,
        "demo_sha256": demo_sha256,
        "models": models_payload,
        "client_spoof_fail_closed": {
            "provenance_verification": "client_supplied_unverified",
            "critical_downgraded_action": "INVESTIGATE",
            "rotation_decision": "HOLD_UNVERIFIED_PROVENANCE",
        },
    }
    if include_nsis:
        payload["nsis_e2e"] = {
            "status": "PASS",
            "installer_filename": "NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe",
            "installer_sha256": "b" * 64,
            "installer_size_bytes": 5_000_000,
            "sums_file_verified": True,
            "installed_exe_sha256": "c" * 64,
            "compiled_exe_sha256": "c" * 64,
            "compiled_exe_sha256_match": True,
            "uninstaller_verified": True,
            "clean_install_verified": True,
            "installed_app_launched": True,
            "installed_exe_path_verified": True,
            "frontend_webview_connected": True,
            "frontend_ready_models": list(cm_specs.keys()),
            "backend_spawned_on_loopback": True,
            "graceful_close_verified": True,
            "zero_orphan_processes_verified": True,
            "uninstall_cleanup_verified": True,
        }
    return payload


def test_verify_companion_artifacts_blocks_when_missing(tmp_path: Path):
    summary = verify_companion_artifacts(root=tmp_path)
    assert summary["overall_status"] == "BLOCKED / NOT READY"
    assert summary["ready_models"] == []
    assert summary["preprocessor"]["ready"] is False
    for key in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
        assert summary["models"][key]["status"] == "BLOCKED / NOT READY"


def test_stage_companion_bundle_fails_closed_when_incomplete(tmp_path: Path):
    empty_src = tmp_path / "src_repo"
    empty_src.mkdir()
    stage_out = tmp_path / "staged"

    with pytest.raises(RuntimeError, match="Cannot stage companion bundle"):
        stage_companion_bundle(destination=stage_out, root=empty_src)


def test_run_four_model_e2e_verification_fails_closed_when_artifacts_missing(tmp_path: Path):
    with pytest.raises(RuntimeError, match="Mandatory 4-model E2E gate BLOCKED"):
        run_four_model_e2e_verification(root=tmp_path)

    exit_code = verify_companion_main(["--root", str(tmp_path), "--verify-e2e"])
    assert exit_code == 1


def test_verify_e2e_attestation_accepts_valid_payload_and_cli(tmp_path: Path):
    head_sha = _head_commit(REPO_ROOT)
    payload = _build_valid_attestation_payload(REPO_ROOT, include_nsis=True, commit=head_sha)
    att_file = tmp_path / "valid_att.json"
    att_file.write_text(json.dumps(payload), encoding="utf-8")

    result = verify_e2e_attestation(
        att_file,
        root=REPO_ROOT,
        expect_commit=head_sha,
        expect_installer_sha256="b" * 64,
        require_nsis_e2e=True,
    )
    assert result["attestation_status"] == "PASS"
    assert len(result["verified_models"]) == 4
    assert result["source_commit"] == head_sha
    assert result["nsis_e2e_verified"] is True

    out_report = tmp_path / "cli_out.json"
    exit_code = verify_companion_main(
        [
            "--root",
            str(REPO_ROOT),
            "--verify-attestation",
            str(att_file),
            "--expect-commit",
            head_sha,
            "--expect-installer-sha256",
            "b" * 64,
            "--require-nsis-e2e",
            "--output-json",
            str(out_report),
        ]
    )
    assert exit_code == 0
    assert json.loads(out_report.read_text(encoding="utf-8"))["attestation_status"] == "PASS"


def test_verify_e2e_attestation_rejects_tampered_model_hash(tmp_path: Path):
    payload = _build_valid_attestation_payload(REPO_ROOT)
    payload["models"]["xgboost"]["artifact_sha256"] = "0" * 64
    tampered = tmp_path / "tampered_att.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match="artifact_sha256 mismatch"):
        verify_e2e_attestation(tampered, root=REPO_ROOT)


def test_verify_e2e_attestation_rejects_stale_script_and_commit_version_binding(tmp_path: Path):
    ws = _copy_attestation_workspace(tmp_path)
    payload = _build_valid_attestation_payload(ws, commit="a" * 40)
    att = tmp_path / "att.json"
    att.write_text(json.dumps(payload), encoding="utf-8")

    # Expect-commit mismatch
    with pytest.raises(RuntimeError, match="source_commit mismatch"):
        verify_e2e_attestation(att, root=ws, expect_commit="f" * 40)

    # Invalid source_commit format
    bad_fmt = copy.deepcopy(payload)
    bad_fmt["source_commit"] = "not-a-commit"
    att_bad_fmt = tmp_path / "att_bad_fmt.json"
    att_bad_fmt.write_text(json.dumps(bad_fmt), encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid 40-char source_commit"):
        verify_e2e_attestation(att_bad_fmt, root=ws)

    # Non-existent commit checked against real .git
    bad_git = _build_valid_attestation_payload(REPO_ROOT, commit="0" * 40)
    att_bad_git = tmp_path / "att_bad_git.json"
    att_bad_git.write_text(json.dumps(bad_git), encoding="utf-8")
    with pytest.raises(RuntimeError, match="is not a valid commit"):
        verify_e2e_attestation(att_bad_git, root=REPO_ROOT)

    # Desktop version mismatch
    bad_ver = copy.deepcopy(payload)
    bad_ver["desktop_version"] = "9.9.9"
    att_bad_ver = tmp_path / "att_bad_ver.json"
    att_bad_ver.write_text(json.dumps(bad_ver), encoding="utf-8")
    with pytest.raises(RuntimeError, match="desktop_version mismatch"):
        verify_e2e_attestation(att_bad_ver, root=ws)

    # Stale verify_companion_artifacts.py script
    (ws / "scripts/verify_companion_artifacts.py").write_text("# modified\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="stale"):
        verify_e2e_attestation(att, root=ws)


def test_verify_e2e_attestation_rejects_split_prep_demo_and_overlap_tampering(tmp_path: Path):
    ws = _copy_attestation_workspace(tmp_path)
    payload = _build_valid_attestation_payload(ws, commit="a" * 40)
    att = tmp_path / "att.json"
    att.write_text(json.dumps(payload), encoding="utf-8")

    bad_split = copy.deepcopy(payload)
    bad_split["split_manifest_sha256"] = "0" * 64
    p_split = tmp_path / "bad_split.json"
    p_split.write_text(json.dumps(bad_split), encoding="utf-8")
    with pytest.raises(RuntimeError, match="split_manifest_sha256 mismatch"):
        verify_e2e_attestation(p_split, root=ws)

    bad_prep = copy.deepcopy(payload)
    bad_prep["preprocessor_sha256"] = "0" * 64
    p_prep = tmp_path / "bad_prep.json"
    p_prep.write_text(json.dumps(bad_prep), encoding="utf-8")
    with pytest.raises(RuntimeError, match="preprocessor_sha256 does not match"):
        verify_e2e_attestation(p_prep, root=ws)

    bad_demo = copy.deepcopy(payload)
    bad_demo["demo_sha256"]["data/demo/demo_flows.csv"] = "0" * 64
    p_demo = tmp_path / "bad_demo.json"
    p_demo.write_text(json.dumps(bad_demo), encoding="utf-8")
    with pytest.raises(RuntimeError, match="demo_sha256 mismatch"):
        verify_e2e_attestation(p_demo, root=ws)

    # Mutate demo_manifest.json in workspace to simulate train overlap > 0
    dm_path = ws / "data/demo/demo_manifest.json"
    demo_manifest = json.loads(dm_path.read_text(encoding="utf-8"))
    demo_manifest["sampling"]["train_overlap_count"] = 2
    dm_path.write_text(json.dumps(demo_manifest), encoding="utf-8")
    payload_overlap = _build_valid_attestation_payload(ws, commit="a" * 40)
    p_overlap = tmp_path / "overlap.json"
    p_overlap.write_text(json.dumps(payload_overlap), encoding="utf-8")
    with pytest.raises(RuntimeError, match="non-zero train/test overlap"):
        verify_e2e_attestation(p_overlap, root=ws)

    # Mutate sampling.partition != validation
    demo_manifest["sampling"]["train_overlap_count"] = 0
    demo_manifest["sampling"]["partition"] = "test"
    dm_path.write_text(json.dumps(demo_manifest), encoding="utf-8")
    payload_part = _build_valid_attestation_payload(ws, commit="a" * 40)
    p_part = tmp_path / "part.json"
    p_part.write_text(json.dumps(payload_part), encoding="utf-8")
    with pytest.raises(RuntimeError, match="sampling.partition must be 'validation'"):
        verify_e2e_attestation(p_part, root=ws)


def test_verify_e2e_attestation_rejects_model_manifest_and_ae_calibration_tamper(tmp_path: Path):
    ws = _copy_attestation_workspace(tmp_path)
    payload = _build_valid_attestation_payload(ws, commit="a" * 40)

    bad_run = copy.deepcopy(payload)
    bad_run["models"]["random_forest"]["run_id"] = "wrong-run-id"
    p_run = tmp_path / "bad_run.json"
    p_run.write_text(json.dumps(bad_run), encoding="utf-8")
    with pytest.raises(RuntimeError, match="run_id mismatch"):
        verify_e2e_attestation(p_run, root=ws)

    bad_inf = copy.deepcopy(payload)
    bad_inf["models"]["xgboost"]["inference_run_id"] = "bad_run"
    p_inf = tmp_path / "bad_inf.json"
    p_inf.write_text(json.dumps(bad_inf), encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid inference_run_id"):
        verify_e2e_attestation(p_inf, root=ws)

    missing_inf = copy.deepcopy(payload)
    del missing_inf["models"]["xgboost"]["inference_run_id"]
    p_missing_inf = tmp_path / "missing_inf.json"
    p_missing_inf.write_text(json.dumps(missing_inf), encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid inference_run_id"):
        verify_e2e_attestation(p_missing_inf, root=ws)

    bad_csv = copy.deepcopy(payload)
    bad_csv["models"]["isolation_forest"]["source_csv_sha256"] = "0" * 64
    p_csv = tmp_path / "bad_csv.json"
    p_csv.write_text(json.dumps(bad_csv), encoding="utf-8")
    with pytest.raises(RuntimeError, match="source_csv_sha256 mismatch"):
        verify_e2e_attestation(p_csv, root=ws)

    ae_manifest_path = ws / "reports/models/autoencoder_manifest.json"
    ae_manifest = json.loads(ae_manifest_path.read_text(encoding="utf-8"))
    ae_manifest["threshold_calibration"]["empirical_val_fpr"] = 0.08
    ae_manifest_path.write_text(json.dumps(ae_manifest), encoding="utf-8")
    att = tmp_path / "valid.json"
    att.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="empirical_val_fpr/target_fpr"):
        verify_e2e_attestation(att, root=ws)

    ae_manifest["threshold_calibration"]["empirical_val_fpr"] = 0.04
    ae_manifest["threshold_calibration"]["threshold_frozen"] = False
    ae_manifest_path.write_text(json.dumps(ae_manifest), encoding="utf-8")
    with pytest.raises(RuntimeError, match="threshold_frozen must be True"):
        verify_e2e_attestation(att, root=ws)


def test_verify_e2e_attestation_rejects_cm_metrics_and_containment_bypass(tmp_path: Path):
    ws = _copy_attestation_workspace(tmp_path)
    base = _build_valid_attestation_payload(ws, commit="a" * 40)

    # Recomputed metric mismatch
    bad_f1 = copy.deepcopy(base)
    bad_f1["models"]["autoencoder"]["f1"] = 0.99
    p_f1 = tmp_path / "bad_f1.json"
    p_f1.write_text(json.dumps(bad_f1), encoding="utf-8")
    with pytest.raises(RuntimeError, match="metric inconsistency"):
        verify_e2e_attestation(p_f1, root=ws)

    # Boolean disguised as int in confusion_matrix
    bad_bool = copy.deepcopy(base)
    bad_bool["models"]["random_forest"]["confusion_matrix"]["fp"] = False
    p_bool = tmp_path / "bad_bool.json"
    p_bool.write_text(json.dumps(bad_bool), encoding="utf-8")
    with pytest.raises(RuntimeError, match="must be non-neg int"):
        verify_e2e_attestation(p_bool, root=ws)

    # Supervised degradation rejected even when metrics match confusion matrix
    bad_rf_gate = copy.deepcopy(base)
    bad_rf_gate["models"]["random_forest"]["confusion_matrix"] = {
        "tn": 97,
        "fp": 1,
        "fn": 0,
        "tp": 100,
    }
    bad_rf_gate["models"]["random_forest"].update(_recompute_model_metrics(97, 1, 0, 100))
    p_rf = tmp_path / "bad_rf.json"
    p_rf.write_text(json.dumps(bad_rf_gate), encoding="utf-8")
    with pytest.raises(RuntimeError, match="failed supervised threshold gate"):
        verify_e2e_attestation(p_rf, root=ws)

    # Duplicate analysis_id across models
    dup_aid = copy.deepcopy(base)
    dup_aid["models"]["xgboost"]["analysis_id"] = dup_aid["models"]["random_forest"]["analysis_id"]
    p_dup = tmp_path / "dup_aid.json"
    p_dup.write_text(json.dumps(dup_aid), encoding="utf-8")
    with pytest.raises(RuntimeError, match="analysis_id values are not unique"):
        verify_e2e_attestation(p_dup, root=ws)

    # RESEARCH_ONLY containment bypass
    bypass = copy.deepcopy(base)
    bypass["models"]["xgboost"]["dry_run_action_counts"] = {
        "NO_ACTION": 98,
        "MONITOR": 2,
        "INVESTIGATE": 0,
        "ISOLATE_RECOMMENDED": 100,
    }
    p_bypass = tmp_path / "bypass.json"
    p_bypass.write_text(json.dumps(bypass), encoding="utf-8")
    with pytest.raises(RuntimeError, match="RESEARCH_ONLY containment bypass"):
        verify_e2e_attestation(p_bypass, root=ws)

    # Anti-spoof verification tamper
    bad_spoof = copy.deepcopy(base)
    bad_spoof["client_spoof_fail_closed"]["critical_downgraded_action"] = "ISOLATE_RECOMMENDED"
    p_spoof = tmp_path / "bad_spoof.json"
    p_spoof.write_text(json.dumps(bad_spoof), encoding="utf-8")
    with pytest.raises(RuntimeError, match="anti-spoof verification"):
        verify_e2e_attestation(p_spoof, root=ws)


def test_verify_e2e_attestation_rejects_missing_or_mismatched_nsis_e2e(tmp_path: Path):
    ws = _copy_attestation_workspace(tmp_path)
    no_nsis = _build_valid_attestation_payload(ws, include_nsis=False, commit="a" * 40)
    p_no_nsis = tmp_path / "no_nsis.json"
    p_no_nsis.write_text(json.dumps(no_nsis), encoding="utf-8")

    # Default allow without nsis_e2e when not required
    assert verify_e2e_attestation(p_no_nsis, root=ws)["nsis_e2e_verified"] is False

    # Fail-closed when require_nsis_e2e=True
    with pytest.raises(RuntimeError, match="missing required 'nsis_e2e'"):
        verify_e2e_attestation(p_no_nsis, root=ws, require_nsis_e2e=True)

    with_nsis = _build_valid_attestation_payload(ws, include_nsis=True, commit="a" * 40)
    p_with_nsis = tmp_path / "with_nsis.json"
    p_with_nsis.write_text(json.dumps(with_nsis), encoding="utf-8")
    with pytest.raises(RuntimeError, match="installer_sha256 mismatch"):
        verify_e2e_attestation(p_with_nsis, root=ws, expect_installer_sha256="e" * 64)

    bad_match = copy.deepcopy(with_nsis)
    bad_match["nsis_e2e"]["compiled_exe_sha256_match"] = False
    p_bad_match = tmp_path / "bad_match.json"
    p_bad_match.write_text(json.dumps(bad_match), encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid nsis_e2e verification flags"):
        verify_e2e_attestation(p_bad_match, root=ws, require_nsis_e2e=True)


def _install_mocked_windows_desktop_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    installer: Path,
    installed_bytes: bytes,
    compiled_exe: Path | None = None,
    desktop_pid: int = 44001,
    backend_pid: int = 44002,
    backend_port: int = 54321,
    frontend_connected: bool = True,
    orphan_after_close: bool = False,
    leave_files_on_uninstall: bool = False,
) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "run_cmds": [],
        "launched_cmds": [],
        "launched_envs": [],
        "backend_alive": False,
        "closed": False,
        "installed_dir": None,
    }

    def _fake_run(cmd, **_kwargs):
        state["run_cmds"].append(list(cmd))
        exe_arg = Path(cmd[0])
        if exe_arg.resolve() == installer.resolve():
            d_arg = next(a for a in cmd if a.startswith("/D="))
            target_dir = Path(d_arg[3:])
            state["installed_dir"] = target_dir
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "netflow-sentinel-desktop.exe").write_bytes(installed_bytes)
            (target_dir / "uninstall.exe").write_bytes(b"UNINST")
        elif exe_arg.name.lower() == "uninstall.exe":
            target_dir = exe_arg.parent
            for item in ("netflow-sentinel-desktop.exe", "uninstall.exe"):
                p = target_dir / item
                if p.exists():
                    p.unlink()
            if leave_files_on_uninstall:
                (target_dir / "netflow-sentinel-backend.exe").write_bytes(b"LEFTOVER")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    class _FakeDesktopProc:
        def __init__(self, cmd, env):
            self.pid = desktop_pid
            self.returncode = None
            state["launched_cmds"].append(list(cmd))
            state["launched_envs"].append(dict(env))
            if compiled_exe is not None:
                assert Path(cmd[0]).resolve() != compiled_exe.resolve()
            assert Path(cmd[0]).parent.name == "CleanInstall"
            state["backend_alive"] = True
            tel_file = Path(env["NETWORK_ANOMALY_DESKTOP_TELEMETRY_FILE"])
            tel_file.parent.mkdir(parents=True, exist_ok=True)
            tel_file.write_text(
                json.dumps(
                    {
                        "desktop_pid": desktop_pid,
                        "frontend_connected": frontend_connected,
                        "backend_status": {
                            "base_url": f"http://127.0.0.1:{backend_port}",
                            "port": backend_port,
                            "running": True,
                            "managed_child": True,
                            "pid": backend_pid,
                        },
                        "summary": {
                            "connected": frontend_connected,
                            "health_status": "ok",
                            "ready_models": list(vca.MODEL_SPECS.keys()),
                        },
                    }
                ),
                encoding="utf-8",
            )

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):  # noqa: ARG002
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def kill(self):
            self.returncode = -9

    def _fake_popen(cmd, **kwargs):
        return _FakeDesktopProc(cmd, kwargs.get("env") or {})

    def _fake_http_json(url: str, **kwargs):
        req_headers = kwargs.get("headers") or {}
        expected_token = (
            state["launched_envs"][-1].get("NETWORK_ANOMALY_API_TOKEN")
            if state["launched_envs"]
            else None
        )
        if expected_token and req_headers.get("X-Sentinel-Session-Token") != expected_token:
            raise urllib.error.HTTPError(url, 401, "Unauthorized", Message(), None)
        if url.endswith("/api/v1/health"):
            return 200, {"status": "ok"}
        if url.endswith("/api/v1/models"):
            return 200, [{"model_key": k, "ready": True} for k in vca.MODEL_SPECS]
        raise AssertionError(f"Unexpected _http_json URL: {url}")

    def _fake_close(pid: int) -> str:
        assert pid == desktop_pid
        state["closed"] = True
        if not orphan_after_close:
            state["backend_alive"] = False
        return "wm_close"

    monkeypatch.setattr(vca, "os", SimpleNamespace(name="nt", environ={}))
    monkeypatch.setattr(vca.subprocess, "run", _fake_run)
    monkeypatch.setattr(vca.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(vca, "_http_json", _fake_http_json)
    monkeypatch.setattr(
        vca,
        "_is_windows_pid_alive",
        lambda pid: bool(state["backend_alive"]) and pid == backend_pid,
    )
    monkeypatch.setattr(vca, "_request_windows_graceful_close", _fake_close)
    monkeypatch.setattr(vca, "_is_loopback_port_open", lambda _port: False)
    monkeypatch.setattr(vca, "_terminate_pid_best_effort", lambda _pid: None)
    return state


def test_verify_nsis_installer_e2e_guards_and_mocked_windows_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    missing = tmp_path / "missing-setup.exe"
    with pytest.raises(RuntimeError, match="NSIS installer not found"):
        verify_nsis_installer_e2e(missing, root=tmp_path)

    tiny = tmp_path / "tiny-setup.exe"
    tiny.write_bytes(b"MZ" + b"\x00" * 100)
    with pytest.raises(RuntimeError, match="size too small"):
        verify_nsis_installer_e2e(tiny, root=tmp_path)

    installer = tmp_path / "NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe"
    installer.write_bytes(b"MZ" + b"\xab" * 1_100_000)
    installer_sha = _sha256_path(installer)

    bad_sums = tmp_path / "SHA256SUMS_BAD.txt"
    bad_sums.write_text(f"{'0' * 64}  {installer.name}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Installer SHA-256 mismatch"):
        verify_nsis_installer_e2e(installer, root=tmp_path, sums_file=bad_sums)

    monkeypatch.setattr(vca, "os", SimpleNamespace(name="posix"))
    with pytest.raises(RuntimeError, match="requires Windows"):
        verify_nsis_installer_e2e(installer, root=tmp_path)

    # Mock clean Windows install -> installed launch -> WebView2 IPC -> close -> zero orphan -> uninstall
    sums_file = tmp_path / "SHA256SUMS.txt"
    sums_file.write_text(f"{installer_sha}  {installer.name}\n", encoding="utf-8")
    compiled_exe = tmp_path / "netflow-sentinel-desktop.exe"
    exe_bytes = b"MZ" + b"\xcd" * 1_200_000
    compiled_exe.write_bytes(exe_bytes)
    compiled_sha = _sha256_bytes(exe_bytes)

    state = _install_mocked_windows_desktop_env(
        monkeypatch,
        installer=installer,
        installed_bytes=exe_bytes,
        compiled_exe=compiled_exe,
    )

    nsis_out = verify_nsis_installer_e2e(
        installer,
        root=tmp_path,
        sums_file=sums_file,
        compiled_exe_path=compiled_exe,
    )
    assert nsis_out["status"] == "PASS"
    assert nsis_out["sums_file_verified"] is True
    assert nsis_out["compiled_exe_sha256"] == compiled_sha
    assert nsis_out["compiled_exe_sha256_match"] is True
    assert nsis_out["clean_install_verified"] is True
    assert nsis_out["uninstaller_verified"] is True
    assert nsis_out["installed_app_launched"] is True
    assert nsis_out["frontend_webview_connected"] is True
    assert nsis_out["zero_orphan_processes_verified"] is True
    assert nsis_out["uninstall_cleanup_verified"] is True
    assert len(state["run_cmds"]) == 2
    assert len(state["launched_cmds"]) == 1

    # CLI --verify-nsis-only without --installer-path fails closed
    assert verify_companion_main(["--verify-nsis-only"]) == 1

    # CLI --verify-nsis-only success writes JSON
    cli_json = tmp_path / "nsis_cli.json"
    assert (
        verify_companion_main(
            [
                "--root",
                str(tmp_path),
                "--verify-nsis-only",
                "--installer-path",
                str(installer),
                "--sums-file",
                str(sums_file),
                "--compiled-exe",
                str(compiled_exe),
                "--output-json",
                str(cli_json),
            ]
        )
        == 0
    )
    assert json.loads(cli_json.read_text(encoding="utf-8"))["status"] == "PASS"

    # Compiled exe SHA-256 mismatch fails closed
    other_exe = tmp_path / "other.exe"
    other_exe.write_bytes(b"MZ" + b"\xef" * 1_200_000)
    with pytest.raises(RuntimeError, match="Installed desktop executable SHA-256 mismatch"):
        verify_nsis_installer_e2e(
            installer,
            root=tmp_path,
            sums_file=sums_file,
            compiled_exe_path=other_exe,
        )


def test_verify_nsis_installer_e2e_tauri_bundle_marker_normalized(tmp_path: Path, monkeypatch):
    installer = tmp_path / "NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe"
    installer.write_bytes(b"MZ" + b"\x00" * 1_200_000)
    sums_file = tmp_path / "SHA256SUMS.txt"
    sums_file.write_text(
        f"{hashlib.sha256(installer.read_bytes()).hexdigest()}  {installer.name}\n",
        encoding="utf-8",
    )

    compiled_bytes = b"MZ" + b"\xab" * 600_000 + b"BUNDLE_TYPE_VAR_UNKError" + b"\xcd" * 600_000
    installed_bytes = compiled_bytes.replace(b"BUNDLE_TYPE_VAR_UNK", b"BUNDLE_TYPE_VAR_NSS", 1)
    compiled_exe = tmp_path / "netflow-sentinel-desktop.exe"
    compiled_exe.write_bytes(compiled_bytes)

    _install_mocked_windows_desktop_env(
        monkeypatch,
        installer=installer,
        installed_bytes=installed_bytes,
        compiled_exe=compiled_exe,
    )

    nsis_out = verify_nsis_installer_e2e(
        installer,
        root=tmp_path,
        sums_file=sums_file,
        compiled_exe_path=compiled_exe,
    )
    assert nsis_out["status"] == "PASS"
    assert nsis_out["compiled_exe_sha256_match"] is True
    assert nsis_out["exe_parity_mode"] == "tauri_nsis_bundle_marker_normalized"
    assert (
        nsis_out["normalized_compiled_exe_sha256"]
        == nsis_out["installed_exe_sha256"]
        == hashlib.sha256(installed_bytes).hexdigest()
    )

    # Extra byte change outside the single Tauri UNK->NSS marker must fail closed
    tampered_compiled = compiled_exe
    tampered_bytes = bytearray(compiled_bytes)
    tampered_bytes[10] ^= 0xFF
    tampered_compiled.write_bytes(bytes(tampered_bytes))
    with pytest.raises(RuntimeError, match="Installed desktop executable SHA-256 mismatch"):
        verify_nsis_installer_e2e(
            installer,
            root=tmp_path,
            sums_file=sums_file,
            compiled_exe_path=tampered_compiled,
        )


def test_verify_nsis_installer_e2e_rejects_orphan_backend_and_uninstall_leftovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    installer = tmp_path / "NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe"
    installer.write_bytes(b"MZ" + b"\x11" * 1_100_000)
    exe_bytes = b"MZ" + b"\x22" * 1_200_000
    compiled_exe = tmp_path / "netflow-sentinel-desktop.exe"
    compiled_exe.write_bytes(exe_bytes)

    # Orphan Python backend after desktop exit must fail closed
    _install_mocked_windows_desktop_env(
        monkeypatch,
        installer=installer,
        installed_bytes=exe_bytes,
        compiled_exe=compiled_exe,
        orphan_after_close=True,
    )
    with pytest.raises(RuntimeError, match="Orphan Python backend process detected"):
        verify_nsis_installer_e2e(installer, root=tmp_path, compiled_exe_path=compiled_exe)

    # Leftover binary after NSIS uninstall must fail closed
    _install_mocked_windows_desktop_env(
        monkeypatch,
        installer=installer,
        installed_bytes=exe_bytes,
        compiled_exe=compiled_exe,
        leave_files_on_uninstall=True,
    )
    with pytest.raises(RuntimeError, match="NSIS uninstall left installed files behind"):
        verify_nsis_installer_e2e(installer, root=tmp_path, compiled_exe_path=compiled_exe)

    # Attestation must reject nsis_e2e missing installed-desktop flags or wrong backend origin
    ws = _copy_attestation_workspace(tmp_path / "att_ws")
    payload = _build_valid_attestation_payload(ws, include_nsis=True, commit="a" * 40)
    bad_orphan = copy.deepcopy(payload)
    bad_orphan["nsis_e2e"]["zero_orphan_processes_verified"] = False
    p_bad_orphan = tmp_path / "bad_orphan_att.json"
    p_bad_orphan.write_text(json.dumps(bad_orphan), encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid nsis_e2e verification flags"):
        verify_e2e_attestation(p_bad_orphan, root=ws, require_nsis_e2e=True)

    bad_origin = copy.deepcopy(payload)
    bad_origin["e2e_backend_origin"] = "api_only_run_api"
    p_bad_origin = tmp_path / "bad_origin_att.json"
    p_bad_origin.write_text(json.dumps(bad_origin), encoding="utf-8")
    with pytest.raises(RuntimeError, match="must record e2e_backend_origin in"):
        verify_e2e_attestation(p_bad_origin, root=ws, require_nsis_e2e=True)


def test_package_and_install_companion_bundle_security_and_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    ws = _setup_companion_source_workspace(tmp_path, monkeypatch)

    bundle_zip = tmp_path / "companion.zip"
    pkg_info = package_companion_bundle(bundle_zip, root=ws)
    assert pkg_info["package_status"] == "READY"
    bundle_sha = pkg_info["bundle_sha256"]
    bundle_bytes = bundle_zip.read_bytes()

    # URL allowlist and checksum guards fail closed
    target_ws = _copy_attestation_workspace(tmp_path / "target_ws")
    shutil.rmtree(target_ws / "data/demo")

    with pytest.raises(RuntimeError, match="HTTPS required"):
        install_companion_bundle(
            root=target_ws,
            bundle_url="http://github.com/doctor-cato/repo/releases/download/v0.6.0/c.zip",
            github_repo="doctor-cato/repo",
            expected_bundle_sha256=bundle_sha,
        )
    with pytest.raises(RuntimeError, match="Disallowed companion URL host"):
        install_companion_bundle(
            root=target_ws,
            bundle_url="https://evil.example.com/companion.zip",
            github_repo="doctor-cato/repo",
            expected_bundle_sha256=bundle_sha,
        )
    with pytest.raises(RuntimeError, match="must belong to repository"):
        install_companion_bundle(
            root=target_ws,
            bundle_url="https://github.com/other-owner/other-repo/releases/download/v1/c.zip",
            github_repo="doctor-cato/repo",
            expected_bundle_sha256=bundle_sha,
        )
    with pytest.raises(RuntimeError, match="Missing required expected bundle SHA-256"):
        install_companion_bundle(
            root=target_ws,
            bundle_url="https://github.com/doctor-cato/repo/releases/download/v1/c.zip",
            github_repo="doctor-cato/repo",
            expected_bundle_sha256=None,
        )
    with pytest.raises(RuntimeError, match="archive SHA-256 mismatch"):
        install_companion_bundle(
            root=target_ws,
            bundle_archive=bundle_zip,
            expected_bundle_sha256="0" * 64,
        )

    # ZipSlip path traversal and untracked reports/ injection rejected
    bad_zip_slip = tmp_path / "slip.zip"
    with zipfile.ZipFile(bad_zip_slip, "w") as zf:
        zf.writestr("../escape.txt", b"pwn")
    with pytest.raises(RuntimeError, match="Path traversal archive entry rejected"):
        install_companion_bundle(
            root=target_ws,
            bundle_archive=bad_zip_slip,
            expected_bundle_sha256=_sha256_path(bad_zip_slip),
        )

    bad_untracked_report = tmp_path / "bad_report.zip"
    with zipfile.ZipFile(bad_untracked_report, "w") as zf:
        payload_bytes = b"{}"
        zf.writestr("reports/untracked_fake.json", payload_bytes)
        zf.writestr(
            "COMPANION_SHA256SUMS.txt",
            f"{_sha256_bytes(payload_bytes)}  reports/untracked_fake.json\n",
        )
    with pytest.raises(RuntimeError, match="Untracked reports/ path rejected"):
        install_companion_bundle(
            root=target_ws,
            bundle_archive=bad_untracked_report,
            expected_bundle_sha256=_sha256_path(bad_untracked_report),
        )

    # Mock GitHub Actions run artifact download (artifact_run_id) + happy-path install into clean checkout
    def _fake_download(url: str, **_kwargs):
        if "/actions/runs/987654/artifacts" in url:
            return json.dumps(
                {
                    "artifacts": [
                        {
                            "name": "netflow-sentinel-companion-bundle",
                            "expired": False,
                            "archive_download_url": "https://api.github.com/repos/doctor-cato/repo/actions/artifacts/555/zip",
                        }
                    ]
                }
            ).encode("utf-8")
        if url.endswith("/actions/artifacts/555/zip"):
            return bundle_bytes
        raise AssertionError(f"Unexpected download URL: {url}")

    monkeypatch.setenv("GH_TOKEN", "test-token-value")
    monkeypatch.setattr(vca, "_download_allowlisted_bytes", _fake_download)
    installed = install_companion_bundle(
        root=target_ws,
        artifact_run_id="987654",
        github_repo="doctor-cato/repo",
        expected_bundle_sha256=bundle_sha,
    )
    assert installed["install_status"] == "READY"
    assert installed["archive_sha256"] == bundle_sha
    assert (target_ws / "data/demo/demo_flows.csv").is_file()
    assert (target_ws / "artifacts/models/autoencoder/autoencoder_model.joblib").is_file()


def test_repo_governance_manifest_blocks_unapproved_public_model_release():
    res_local = vca.verify_distribution_permission(
        "research-only", target_channel="local_offline", root=REPO_ROOT
    )
    assert res_local["status"] == "APPROVED"
    assert res_local["upload_allowed"] is False
    assert res_local["public_release_allowed"] is False

    # Actual repo governance state has approved=False; public channels & private-build on public repo MUST fail closed
    for channel in ("public_ci_artifact", "public_github_release"):
        with pytest.raises(RuntimeError, match="DISTRIBUTION PERMISSION"):
            vca.verify_distribution_permission(
                "public-release-approved",
                target_channel=channel,
                repo_is_private=False,
                root=REPO_ROOT,
            )
        with pytest.raises(RuntimeError, match="DISTRIBUTION PERMISSION"):
            vca.verify_distribution_permission(
                "private-build-only",
                target_channel=channel,
                repo_is_private=False,
                root=REPO_ROOT,
            )

    # Even private-build-only on private_ci_artifact MUST fail closed when repo_is_private is False or None
    for non_private in (False, None):
        with pytest.raises(RuntimeError, match="repository privacy is not verified private"):
            vca.verify_distribution_permission(
                "private-build-only",
                target_channel="private_ci_artifact",
                repo_is_private=non_private,
                root=REPO_ROOT,
            )


def test_verify_e2e_attestation_clean_checkout_without_demo_files_and_require_demo_flag(
    tmp_path: Path,
):
    ws = _copy_attestation_workspace(tmp_path)
    payload = _build_valid_attestation_payload(ws, include_nsis=True, commit="a" * 40)
    att = tmp_path / "att.json"
    att.write_text(json.dumps(payload), encoding="utf-8")

    # Simulate a clean Git checkout where .gitignore-d data/demo/* files are absent
    shutil.rmtree(ws / "data/demo")

    res_clean = verify_e2e_attestation(att, root=ws, require_nsis_e2e=True)
    assert res_clean["attestation_status"] == "PASS"
    assert res_clean["demo_files_verified_on_disk"] is False

    # Cross-model demo hash consistency still fails closed even without demo files on disk
    bad_cross = copy.deepcopy(payload)
    bad_cross["models"]["xgboost"]["source_csv_sha256"] = "0" * 64
    p_bad_cross = tmp_path / "bad_cross.json"
    p_bad_cross.write_text(json.dumps(bad_cross), encoding="utf-8")
    with pytest.raises(RuntimeError, match="source_csv_sha256 mismatch"):
        verify_e2e_attestation(p_bad_cross, root=ws)

    # Release gate (--require-demo-files) must fail closed when data/demo/* is absent
    with pytest.raises(RuntimeError, match="Missing required demo files"):
        verify_e2e_attestation(att, root=ws, require_nsis_e2e=True, require_demo_files=True)
    assert (
        verify_companion_main(
            [
                "--root",
                str(ws),
                "--verify-attestation",
                str(att),
                "--require-nsis-e2e",
                "--require-demo-files",
            ]
        )
        == 1
    )

    # Partial data/demo/* on disk must always fail closed
    partial_dir = ws / "data/demo"
    partial_dir.mkdir(parents=True, exist_ok=True)
    (partial_dir / "demo_flows.csv").write_text("duration_ms\n10.0\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Incomplete tracked demo files"):
        verify_e2e_attestation(att, root=ws)


def _setup_companion_source_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ws = _copy_attestation_workspace(tmp_path / "src_ws")
    prep_manifest = json.loads(
        (ws / "reports/preprocessing/v2_flow_preprocessing_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    prep_sha = str(prep_manifest["artifact_sha256"]).lower()
    model_shas: Dict[str, str] = {}
    model_runs: Dict[str, str] = {}
    for key, rel_m in (
        ("random_forest", "reports/models/random_forest_manifest.json"),
        ("xgboost", "reports/models/xgboost_manifest.json"),
        ("isolation_forest", "reports/models/isolation_forest_manifest.json"),
        ("autoencoder", "reports/models/autoencoder_manifest.json"),
    ):
        md = json.loads((ws / rel_m).read_text(encoding="utf-8"))
        model_shas[key] = str(
            md.get("model_artifact_sha256") or md.get("model_sha256") or md.get("artifact_sha256")
        ).lower()
        model_runs[key] = str(md["run_id"])

    fake_files = {
        "artifacts/preprocessing/v2_flow_preprocessor.joblib": b"prep",
        "artifacts/models/random_forest/random_forest_baseline.joblib": b"rf",
        "artifacts/models/xgboost/xgboost_baseline.joblib": b"xgb",
        "artifacts/models/isolation_forest/isolation_forest.joblib": b"if",
        "artifacts/models/autoencoder/autoencoder_model.joblib": b"ae",
    }
    for rel, content in fake_files.items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)

    all_companion_files = sorted(
        [
            *fake_files.keys(),
            "data/demo/demo_flows.csv",
            "data/demo/demo_labels.csv",
            "data/demo/demo_manifest.json",
            "reports/preprocessing/v2_flow_preprocessing_manifest.json",
            "reports/models/random_forest_manifest.json",
            "reports/models/xgboost_manifest.json",
            "reports/models/isolation_forest_manifest.json",
            "reports/models/autoencoder_manifest.json",
        ]
    )

    def _ready_summary(root: Path) -> Dict[str, Any]:
        demo_info = {
            rel: {
                "present": (root / rel).is_file(),
                "sha256": _sha256_path(root / rel) if (root / rel).is_file() else None,
            }
            for rel in (
                "data/demo/demo_flows.csv",
                "data/demo/demo_labels.csv",
                "data/demo/demo_manifest.json",
            )
        }
        all_present = all((root / rel).is_file() for rel in all_companion_files)
        return {
            "overall_status": "READY" if all_present else "BLOCKED / NOT READY",
            "ready_models": (
                ["random_forest", "xgboost", "isolation_forest", "autoencoder"]
                if all_present
                else []
            ),
            "preprocessor": {
                "ready": all_present,
                "sha256": prep_sha if all_present else None,
            },
            "models": {
                key: {
                    "ready": all_present,
                    "sha256": model_shas[key],
                    "run_id": model_runs[key],
                }
                for key in ("random_forest", "xgboost", "isolation_forest", "autoencoder")
            },
            "demo": demo_info,
            "demo_ready": all_present,
            "companion_files": all_companion_files,
        }

    monkeypatch.setattr(vca, "verify_companion_artifacts", _ready_summary)
    return ws


class _FakeHttpResponse:
    def __init__(self, url: str, body: bytes):
        self._url = url
        self._bio = io.BytesIO(body)

    def geturl(self) -> str:
        return self._url

    def read(self, n: int = -1) -> bytes:
        return self._bio.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def _make_mock_opener(
    routes: Dict[str, tuple[int, str | bytes]],
    recorded_requests: list[tuple[str, Dict[str, str]]],
):
    def _factory(
        allowed_hosts,
        github_repo,
        *,
        allow_actions_storage_redirects: bool = False,
    ):
        redir_handler = vca._AllowlistedRedirectHandler(
            allowed_hosts,
            github_repo,
            allow_actions_storage_redirects=allow_actions_storage_redirects,
        )

        class _MockOpener:
            def open(self, req: urllib.request.Request, timeout=60.0):  # noqa: ARG002
                curr_req = req
                for _hop in range(5):
                    merged_headers = {**curr_req.unredirected_hdrs, **curr_req.headers}
                    recorded_requests.append(
                        (
                            curr_req.full_url,
                            {k.lower(): v for k, v in merged_headers.items()},
                        )
                    )
                    status, payload = routes[curr_req.full_url]
                    if status in (301, 302, 303, 307, 308):
                        next_req = redir_handler.redirect_request(
                            curr_req, None, status, "Found", Message(), str(payload)
                        )
                        assert next_req is not None
                        curr_req = next_req
                        continue
                    assert isinstance(payload, bytes)
                    return _FakeHttpResponse(curr_req.full_url, payload)
                raise AssertionError("Too many redirect hops in test mock")

        return _MockOpener()

    return _factory


def test_companion_url_token_scoping_and_redirect_security_f05(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    ws = _setup_companion_source_workspace(tmp_path, monkeypatch)
    bundle_zip = tmp_path / "companion.zip"
    pkg_info = package_companion_bundle(bundle_zip, root=ws)
    bundle_sha = pkg_info["bundle_sha256"]
    bundle_bytes = bundle_zip.read_bytes()

    monkeypatch.setenv("GH_TOKEN", "ghp_super_secret_token")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_workflow_secret_token")
    monkeypatch.setenv("COMPANION_BUNDLE_TOKEN", "dedicated_bundle_secret")
    monkeypatch.setenv("CUSTOM_EXT_TOKEN", "explicit_external_secret")

    # 1. External custom URL must NEVER receive GH_TOKEN/GITHUB_TOKEN or implicit COMPANION_BUNDLE_TOKEN
    recorded_ext: list[tuple[str, Dict[str, str]]] = []
    routes_ext: Dict[str, tuple[int, str | bytes]] = {
        "https://cdn.example.com/bundle.zip": (200, bundle_bytes),
    }
    monkeypatch.setattr(
        vca, "_build_allowlisted_opener", _make_mock_opener(routes_ext, recorded_ext)
    )
    target_ws1 = _copy_attestation_workspace(tmp_path / "target_ext_no_token")
    shutil.rmtree(target_ws1 / "data/demo")
    res1 = install_companion_bundle(
        root=target_ws1,
        bundle_url="https://cdn.example.com/bundle.zip",
        allowed_hosts=["cdn.example.com"],
        github_repo="doctor-cato/repo",
        expected_bundle_sha256=bundle_sha,
    )
    assert res1["install_status"] == "READY"
    assert len(recorded_ext) == 1
    assert "authorization" not in recorded_ext[0][1]

    # 2. Explicitly asking to send GH_TOKEN/GITHUB_TOKEN to non-GitHub-API host must fail closed
    for gh_var in ("GH_TOKEN", "GITHUB_TOKEN"):
        with pytest.raises(RuntimeError, match="Refusing to send"):
            install_companion_bundle(
                root=target_ws1,
                bundle_url="https://cdn.example.com/bundle.zip",
                allowed_hosts=["cdn.example.com"],
                github_repo="doctor-cato/repo",
                expected_bundle_sha256=bundle_sha,
                token_env_var=gh_var,
            )
    with pytest.raises(RuntimeError, match="Refusing to attach GitHub token"):
        vca._download_allowlisted_bytes(
            "https://cdn.example.com/bundle.zip",
            allowed_hosts=["cdn.example.com"],
            github_repo="doctor-cato/repo",
            token="ghp_super_secret_token",
            token_source_is_github=True,
        )

    # 3. External URL with explicit dedicated token strips Authorization on redirect (same & cross host)
    recorded_redir: list[tuple[str, Dict[str, str]]] = []
    routes_redir: Dict[str, tuple[int, str | bytes]] = {
        "https://cdn.example.com/start.zip": (302, "https://cdn.example.com/signed.zip"),
        "https://cdn.example.com/signed.zip": (302, "https://edge.example.com/final.zip"),
        "https://edge.example.com/final.zip": (200, bundle_bytes),
    }
    monkeypatch.setattr(
        vca, "_build_allowlisted_opener", _make_mock_opener(routes_redir, recorded_redir)
    )
    target_ws2 = _copy_attestation_workspace(tmp_path / "target_ext_redir")
    shutil.rmtree(target_ws2 / "data/demo")
    res2 = install_companion_bundle(
        root=target_ws2,
        bundle_url="https://cdn.example.com/start.zip",
        allowed_hosts=["cdn.example.com", "edge.example.com"],
        github_repo="doctor-cato/repo",
        expected_bundle_sha256=bundle_sha,
        token_env_var="CUSTOM_EXT_TOKEN",
    )
    assert res2["install_status"] == "READY"
    assert recorded_redir[0][1].get("authorization") == "Bearer explicit_external_secret"
    assert "authorization" not in recorded_redir[1][1]
    assert "authorization" not in recorded_redir[2][1]

    # 4. Redirects to evil host or another GitHub repo are blocked fail-closed
    routes_evil_redir: Dict[str, tuple[int, str | bytes]] = {
        "https://cdn.example.com/evil.zip": (302, "https://evil.attacker.net/pwn.zip"),
        "https://github.com/doctor-cato/repo/releases/download/v0.6.0/c.zip": (
            302,
            "https://github.com/attacker/evil-repo/releases/download/v1/c.zip",
        ),
    }
    monkeypatch.setattr(vca, "_build_allowlisted_opener", _make_mock_opener(routes_evil_redir, []))
    with pytest.raises(RuntimeError, match="Disallowed companion URL host"):
        install_companion_bundle(
            root=target_ws2,
            bundle_url="https://cdn.example.com/evil.zip",
            allowed_hosts=["cdn.example.com"],
            github_repo="doctor-cato/repo",
            expected_bundle_sha256=bundle_sha,
        )
    with pytest.raises(RuntimeError, match="must belong to repository"):
        install_companion_bundle(
            root=target_ws2,
            bundle_url="https://github.com/doctor-cato/repo/releases/download/v0.6.0/c.zip",
            github_repo="doctor-cato/repo",
            expected_bundle_sha256=bundle_sha,
        )


def test_github_actions_artifact_zip_wrapper_and_provenance_f06(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    ws = _setup_companion_source_workspace(tmp_path, monkeypatch)
    bundle_zip = tmp_path / "netflow-sentinel-v0.6.0-companion-bundle.zip"
    pkg_info = package_companion_bundle(bundle_zip, root=ws)
    inner_sha = pkg_info["bundle_sha256"]
    inner_bytes = bundle_zip.read_bytes()

    # Simulate real GitHub Actions actions/upload-artifact wrapper ZIP containing inner companion.zip
    outer_wrapper_zip = tmp_path / "actions_artifact_wrapper.zip"
    with zipfile.ZipFile(outer_wrapper_zip, "w") as outer_zf:
        outer_zf.writestr("netflow-sentinel-v0.6.0-companion-bundle.zip", inner_bytes)
    outer_bytes = outer_wrapper_zip.read_bytes()
    outer_sha = _sha256_bytes(outer_bytes)

    list_url = (
        "https://api.github.com/repos/doctor-cato/repo/actions/runs/"
        "987654/artifacts?name=netflow-sentinel-companion-bundle&per_page=100"
    )
    dl_api_url = "https://api.github.com/repos/doctor-cato/repo/actions/artifacts/555/zip"
    signed_storage_url = (
        "https://pipelinesghubeus1.actions.githubusercontent.com/dl/555?sig=signed-sas-token"
    )

    recorded_gh: list[tuple[str, Dict[str, str]]] = []
    routes_gh: Dict[str, tuple[int, str | bytes]] = {
        list_url: (
            200,
            json.dumps(
                {
                    "artifacts": [
                        {
                            "name": "netflow-sentinel-companion-bundle",
                            "expired": False,
                            "digest": f"sha256:{outer_sha}",
                            "archive_download_url": dl_api_url,
                        }
                    ]
                }
            ).encode("utf-8"),
        ),
        dl_api_url: (302, signed_storage_url),
        signed_storage_url: (200, outer_bytes),
    }

    monkeypatch.setenv("GH_TOKEN", "ghp_actions_secret")
    monkeypatch.setattr(vca, "_build_allowlisted_opener", _make_mock_opener(routes_gh, recorded_gh))

    target_ws = _copy_attestation_workspace(tmp_path / "clean_actions_ws")
    shutil.rmtree(target_ws / "data/demo")
    installed = install_companion_bundle(
        root=target_ws,
        artifact_run_id="987654",
        github_repo="doctor-cato/repo",
        expected_bundle_sha256=inner_sha,
    )
    assert installed["install_status"] == "READY"
    assert installed["archive_sha256"] == inner_sha
    assert installed["outer_wrapper_sha256"] == outer_sha
    assert (target_ws / "data/demo/demo_flows.csv").is_file()
    assert (target_ws / "artifacts/models/autoencoder/autoencoder_model.joblib").is_file()

    # GH_TOKEN sent ONLY to api.github.com endpoints, NEVER to redirected storage host
    assert recorded_gh[0] == (
        list_url,
        {
            "user-agent": "netflow-sentinel-companion-installer/0.6.0",
            "accept": "application/vnd.github+json",
            "authorization": "Bearer ghp_actions_secret",
        },
    )
    assert recorded_gh[1][0] == dl_api_url
    assert recorded_gh[1][1].get("authorization") == "Bearer ghp_actions_secret"
    assert recorded_gh[2][0] == signed_storage_url
    assert "authorization" not in recorded_gh[2][1]

    # Negative F-06 tests:
    # (a) Multi-file outer wrapper (extra file alongside zip) rejected fail-closed
    bad_multi_wrapper = tmp_path / "bad_multi.zip"
    with zipfile.ZipFile(bad_multi_wrapper, "w") as bad_zf:
        bad_zf.writestr("companion.zip", inner_bytes)
        bad_zf.writestr("unexpected.txt", b"extra")
    routes_gh[signed_storage_url] = (200, bad_multi_wrapper.read_bytes())
    routes_gh[list_url] = (
        200,
        json.dumps(
            {
                "artifacts": [
                    {
                        "name": "netflow-sentinel-companion-bundle",
                        "expired": False,
                        "digest": f"sha256:{_sha256_path(bad_multi_wrapper)}",
                        "archive_download_url": dl_api_url,
                    }
                ]
            }
        ).encode("utf-8"),
    )
    with pytest.raises(RuntimeError, match="Disallowed companion archive entry prefix"):
        install_companion_bundle(
            root=target_ws,
            artifact_run_id="987654",
            github_repo="doctor-cato/repo",
            expected_bundle_sha256=_sha256_path(bad_multi_wrapper),
        )

    # (b) GitHub API artifact digest mismatch rejected fail-closed
    routes_gh[signed_storage_url] = (200, outer_bytes)
    routes_gh[list_url] = (
        200,
        json.dumps(
            {
                "artifacts": [
                    {
                        "name": "netflow-sentinel-companion-bundle",
                        "expired": False,
                        "digest": f"sha256:{'0' * 64}",
                        "archive_download_url": dl_api_url,
                    }
                ]
            }
        ).encode("utf-8"),
    )
    with pytest.raises(RuntimeError, match="Downloaded GitHub Actions artifact digest mismatch"):
        install_companion_bundle(
            root=target_ws,
            artifact_run_id="987654",
            github_repo="doctor-cato/repo",
            expected_bundle_sha256=inner_sha,
        )

    # (c) Tampered inner COMPANION_BUNDLE_MANIFEST.json provenance rejected fail-closed
    tampered_inner = tmp_path / "tampered_inner.zip"
    with zipfile.ZipFile(bundle_zip, "r") as zin, zipfile.ZipFile(tampered_inner, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "COMPANION_BUNDLE_MANIFEST.json":
                m = json.loads(data.decode("utf-8"))
                m["models"]["random_forest"]["sha256"] = "f" * 64
                data = json.dumps(m).encode("utf-8")
            zout.writestr(item, data)
    with pytest.raises(RuntimeError, match="COMPANION_BUNDLE_MANIFEST provenance mismatch"):
        install_companion_bundle(
            root=target_ws,
            bundle_archive=tampered_inner,
            expected_bundle_sha256=_sha256_path(tampered_inner),
        )


def test_verify_e2e_attestation_requires_all_four_frontend_ready_models(tmp_path: Path):
    ws = _copy_attestation_workspace(tmp_path)
    payload = _build_valid_attestation_payload(ws, include_nsis=True)
    att_path = tmp_path / "att_valid.json"
    att_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    res = verify_e2e_attestation(att_path, root=ws, require_nsis_e2e=True)
    assert res["attestation_status"] == "PASS"

    # Missing frontend_ready_models fails closed
    bad_missing = copy.deepcopy(payload)
    bad_missing["nsis_e2e"].pop("frontend_ready_models")
    bad_missing_path = tmp_path / "att_missing_frm.json"
    bad_missing_path.write_text(json.dumps(bad_missing, indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError, match="frontend_ready_models"):
        verify_e2e_attestation(bad_missing_path, root=ws, require_nsis_e2e=True)

    # Incomplete frontend_ready_models fails closed
    bad_partial = copy.deepcopy(payload)
    bad_partial["nsis_e2e"]["frontend_ready_models"] = ["random_forest", "xgboost"]
    bad_partial_path = tmp_path / "att_partial_frm.json"
    bad_partial_path.write_text(json.dumps(bad_partial, indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError, match="frontend_ready_models"):
        verify_e2e_attestation(bad_partial_path, root=ws, require_nsis_e2e=True)


def test_stage_and_install_sync_xgboost_sidecar_and_support_runtime_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    src_ws = _copy_attestation_workspace(tmp_path / "src_ws")
    target_code_ws = _copy_attestation_workspace(tmp_path / "code_ws")
    runtime_dir = tmp_path / "PerUserRuntime"

    # Populate synthetic companion files in src_ws with a STALE XGBoost sidecar manifest
    companion_files = {
        "artifacts/preprocessing/v2_flow_preprocessor.joblib": b"prep",
        "artifacts/models/random_forest/random_forest_baseline.joblib": b"rf",
        "artifacts/models/xgboost/xgboost_baseline.joblib": b"xgb",
        "artifacts/models/isolation_forest/isolation_forest.joblib": b"if",
        "artifacts/models/autoencoder/autoencoder_model.joblib": b"ae",
        "artifacts/models/autoencoder/model_config.json": b"{}",
        "artifacts/models/autoencoder/threshold.json": b"{}",
        "artifacts/models/xgboost/xgboost_manifest.json": b'{"stale": true}\n',
    }
    for rel, content in companion_files.items():
        p = src_ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)

    def _ready_summary(root: Path, runtime_dir: Path | None = None) -> dict[str, Any]:
        eff_rt = (runtime_dir or root).resolve()
        prep_sha = json.loads(
            (root / "reports/preprocessing/v2_flow_preprocessing_manifest.json").read_text(
                encoding="utf-8"
            )
        )["artifact_sha256"]
        models_info: dict[str, Any] = {}
        for k, (_, cands) in vca.MODEL_SPECS.items():
            man = json.loads((root / cands[0]).read_text(encoding="utf-8"))
            sha = man.get("model_artifact_sha256") or man.get("model_sha256")
            models_info[k] = {
                "ready": True,
                "status": "READY",
                "sha256": sha,
                "run_id": man["run_id"],
            }
        demo_info = {
            rel: {
                "present": True,
                "sha256": _sha256_path(eff_rt / rel),
                "size_bytes": (eff_rt / rel).stat().st_size,
            }
            for rel in (
                "data/demo/demo_flows.csv",
                "data/demo/demo_labels.csv",
                "data/demo/demo_manifest.json",
            )
        }
        return {
            "overall_status": "READY",
            "ready_models": list(vca.MODEL_SPECS.keys()),
            "preprocessor": {"ready": True, "status": "READY", "sha256": prep_sha},
            "models": models_info,
            "demo": demo_info,
            "demo_ready": True,
            "companion_files": sorted(
                list(companion_files.keys())
                + [
                    "reports/preprocessing/v2_flow_preprocessing_manifest.json",
                    "reports/models/random_forest_manifest.json",
                    "reports/models/xgboost_manifest.json",
                    "reports/models/isolation_forest_manifest.json",
                    "reports/models/autoencoder_manifest.json",
                    "data/demo/demo_flows.csv",
                    "data/demo/demo_labels.csv",
                    "data/demo/demo_manifest.json",
                ]
            ),
        }

    monkeypatch.setattr(vca, "verify_companion_artifacts", _ready_summary)

    bundle_zip = tmp_path / "synced_companion.zip"
    pkg_res = package_companion_bundle(bundle_zip, root=src_ws)
    assert pkg_res["package_status"] == "READY"

    # Install into separate runtime_dir (code_ws stays untouched for artifacts/ and data/demo/)
    inst_res = install_companion_bundle(
        root=target_code_ws,
        runtime_dir=runtime_dir,
        bundle_archive=bundle_zip,
        expected_bundle_sha256=pkg_res["bundle_sha256"],
    )
    assert inst_res["install_status"] == "READY"
    assert (runtime_dir / "artifacts/models/xgboost/xgboost_manifest.json").read_bytes() == (
        target_code_ws / "reports/models/xgboost_manifest.json"
    ).read_bytes()
    assert (runtime_dir / "data/demo/demo_flows.csv").is_file()
    assert not (target_code_ws / "artifacts/models/xgboost/xgboost_baseline.joblib").exists()


def test_extract_safe_companion_zip_rejects_zip_bomb_entry_and_byte_limits(
    tmp_path: Path, monkeypatch
):
    import zipfile

    import scripts.verify_companion_artifacts as vca

    bomb_zip = tmp_path / "too_many_entries.zip"
    monkeypatch.setattr(vca, "MAX_COMPANION_ARCHIVE_ENTRIES", 2)
    with zipfile.ZipFile(bomb_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("artifacts/a.txt", b"1")
        zf.writestr("artifacts/b.txt", b"2")
        zf.writestr("artifacts/c.txt", b"3")

    with pytest.raises(RuntimeError, match="maximum entry count"):
        vca._extract_safe_companion_zip(bomb_zip, tmp_path / "out_count")

    monkeypatch.setattr(vca, "MAX_COMPANION_ARCHIVE_ENTRIES", 64)
    monkeypatch.setattr(vca, "MAX_COMPANION_ENTRY_UNCOMPRESSED_BYTES", 1024)
    monkeypatch.setattr(vca, "MAX_COMPANION_TOTAL_UNCOMPRESSED_BYTES", 2048)

    big_entry_zip = tmp_path / "big_entry.zip"
    with zipfile.ZipFile(big_entry_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("artifacts/big.bin", b"A" * 2048)

    with pytest.raises(RuntimeError, match="exceeds limit"):
        vca._extract_safe_companion_zip(big_entry_zip, tmp_path / "out_entry")


def test_verify_e2e_attestation_require_bundled_resources_enforces_production_mode(tmp_path: Path):
    ws = _copy_attestation_workspace(tmp_path)
    base = _build_valid_attestation_payload(ws, include_nsis=True, commit="a" * 40)

    # Legacy or repo-root-env attestation must fail when bundled resources mode is strictly required
    bad_repo_env = json.loads(json.dumps(base))
    bad_repo_env["nsis_e2e"]["bundled_resources_mode"] = False
    bad_repo_env["nsis_e2e"]["repo_root_env_passed"] = True
    bad_repo_env["nsis_e2e"]["runtime_dir_isolated"] = True
    bad_path = tmp_path / "bad_att.json"
    bad_path.write_text(json.dumps(bad_repo_env), encoding="utf-8")

    with pytest.raises(RuntimeError, match="bundled resources"):
        vca.verify_e2e_attestation(
            bad_path,
            root=ws,
            require_nsis_e2e=True,
            require_bundled_resources=True,
        )

    good = json.loads(json.dumps(base))
    good["nsis_e2e"]["bundled_resources_mode"] = True
    good["nsis_e2e"]["repo_root_env_passed"] = False
    good["nsis_e2e"]["runtime_dir_isolated"] = True
    good_path = tmp_path / "good_att.json"
    good_path.write_text(json.dumps(good), encoding="utf-8")

    res = vca.verify_e2e_attestation(
        good_path,
        root=ws,
        require_nsis_e2e=True,
        require_bundled_resources=True,
    )
    assert res["bundled_resources_verified"] is True


def test_verify_distribution_permission_enforces_evidence_based_tiers(tmp_path: Path):
    (tmp_path / "NOTICE").write_text(
        "AIT NetFlow Data Set v2 | DOI: 10.5281/zenodo.13168643 | CTU-SME-11 | 10.5281/zenodo.7958258\n",
        encoding="utf-8",
    )
    (tmp_path / "THIRD_PARTY_NOTICES.md").write_text(
        "# Notices\nAIT NetFlow Data Set v2 | DOI: 10.5281/zenodo.13168643 | CTU-SME-11 | 10.5281/zenodo.7958258\n",
        encoding="utf-8",
    )
    (tmp_path / "LICENSE").write_text("Apache License 2.0\n", encoding="utf-8")

    gov_dir = tmp_path / "reports" / "governance"
    gov_dir.mkdir(parents=True, exist_ok=True)
    auth_path = gov_dir / "DISTRIBUTION_AUTHORIZATION.json"
    auth_base = json.loads(
        (REPO_ROOT / "reports/governance/DISTRIBUTION_AUTHORIZATION.json").read_text(
            encoding="utf-8"
        )
    )
    auth_path.write_text(json.dumps(auth_base, indent=2), encoding="utf-8")

    # Legacy variable string alone must be rejected
    with pytest.raises(RuntimeError, match="NOT legal evidence"):
        vca.verify_distribution_permission(
            "non-commercial-academic-approved",
            target_channel="public_github_release",
            root=tmp_path,
        )

    # Private build on public or unknown repository privacy must fail closed
    for non_private_flag in (False, None):
        with pytest.raises(RuntimeError, match="not verified private"):
            vca.verify_distribution_permission(
                "private-build-only",
                target_channel="private_ci_artifact",
                repo_is_private=non_private_flag,
                root=tmp_path,
            )

    # Private build on public_ci_artifact must fail closed even if caller passes private-build-only
    with pytest.raises(RuntimeError, match="forbids public channel"):
        vca.verify_distribution_permission(
            "private-build-only",
            target_channel="public_ci_artifact",
            repo_is_private=False,
            root=tmp_path,
        )

    # Corrupted attribution markers in NOTICE fail closed
    saved_notice = (tmp_path / "NOTICE").read_text(encoding="utf-8")
    (tmp_path / "NOTICE").write_text("NOTICE without license id\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="attribution markers"):
        vca.verify_distribution_permission(
            "research-only",
            target_channel="local_offline",
            root=tmp_path,
        )
    (tmp_path / "NOTICE").write_text(saved_notice, encoding="utf-8")

    # Private build on verified private repo/runner is approved for private_ci_artifact (but never public release)
    res_priv_ci = vca.verify_distribution_permission(
        "private-build-only",
        target_channel="private_ci_artifact",
        repo_is_private=True,
        root=tmp_path,
    )
    assert res_priv_ci["status"] == "APPROVED"
    assert res_priv_ci["upload_allowed"] is True
    assert res_priv_ci["public_release_allowed"] is False

    # research-only cannot upload CI artifacts
    with pytest.raises(RuntimeError, match="research-only"):
        vca.verify_distribution_permission(
            "research-only",
            target_channel="private_ci_artifact",
            repo_is_private=True,
            root=tmp_path,
        )

    # Unapproved public_release_authorization blocks public-release-approved fail-closed
    with pytest.raises(RuntimeError, match="NOT authorized"):
        vca.verify_distribution_permission(
            "public-release-approved",
            is_public_release=True,
            target_channel="public_github_release",
            repo_is_private=False,
            root=tmp_path,
        )

    # Populating valid verifiable evidence unlocks public release only when evidence hash matches
    evidence_sha = "d" * 64
    auth_approved = copy.deepcopy(auth_base)
    auth_approved["public_release_authorization"].update(
        {
            "approved": True,
            "status": "APPROVED",
            "legal_basis": "written-publisher-authorization",
            "maintainer_approver": "maintainer@example.org",
            "approved_at_utc": "2026-11-16T12:00:00Z",
            "evidence_ref": "UQ-AUTH-RECORD-001",
            "evidence_sha256": evidence_sha,
        }
    )
    auth_path.write_text(json.dumps(auth_approved, indent=2), encoding="utf-8")

    # Missing or wrong secret evidence hash fails closed when require_evidence_hash=True
    with pytest.raises(RuntimeError, match="Missing expected evidence SHA-256"):
        vca.verify_distribution_permission(
            "public-release-approved",
            is_public_release=True,
            target_channel="public_github_release",
            root=tmp_path,
            require_evidence_hash=True,
        )
    with pytest.raises(RuntimeError, match="evidence SHA-256 verification failed"):
        vca.verify_distribution_permission(
            "public-release-approved",
            is_public_release=True,
            target_channel="public_github_release",
            root=tmp_path,
            expected_evidence_sha256="e" * 64,
            require_evidence_hash=True,
        )

    res_public = vca.verify_distribution_permission(
        "public-release-approved",
        is_public_release=True,
        target_channel="public_github_release",
        root=tmp_path,
        expected_evidence_sha256=evidence_sha,
        require_evidence_hash=True,
    )
    assert res_public["public_release_allowed"] is True
    assert res_public["upload_allowed"] is True
    assert res_public["evidence_verified"] is True
    assert res_public["citation_doi"] == "10.5281/zenodo.13168643"

    # Attribution notices remain mandatory even when authorization exists
    (tmp_path / "NOTICE").unlink()
    with pytest.raises(RuntimeError, match="NOTICE"):
        vca.verify_distribution_permission(
            "public-release-approved",
            is_public_release=True,
            target_channel="public_github_release",
            root=tmp_path,
            expected_evidence_sha256=evidence_sha,
            require_evidence_hash=True,
        )


def test_tauri_standalone_config_covers_all_required_embedded_resources():
    base_cfg = json.loads(
        (REPO_ROOT / "desktop/src-tauri/tauri.conf.json").read_text(encoding="utf-8")
    )
    standalone_cfg = json.loads(
        (REPO_ROOT / "desktop/src-tauri/tauri.standalone.conf.json").read_text(encoding="utf-8")
    )
    assert standalone_cfg["bundle"]["externalBin"] == ["binaries/netflow-sentinel-backend"]
    base_res = base_cfg["bundle"]["resources"]
    standalone_res = standalone_cfg["bundle"]["resources"]
    destinations = set(standalone_res.values())
    # Must explicitly include sidecar-supporting artifacts for all 4 models, preprocessor, demo, and manifests
    required_standalone_dests = {
        "artifacts/preprocessing/v2_flow_preprocessor.joblib",
        "artifacts/models/random_forest/random_forest_baseline.joblib",
        "artifacts/models/random_forest/random_forest_manifest.json",
        "artifacts/models/xgboost/xgboost_baseline.joblib",
        "artifacts/models/xgboost/xgboost_manifest.json",
        "artifacts/models/isolation_forest/isolation_forest.joblib",
        "artifacts/models/isolation_forest/model_config.json",
        "artifacts/models/isolation_forest/threshold.json",
        "artifacts/models/isolation_forest/training_metadata.json",
        "artifacts/models/autoencoder/autoencoder_model.joblib",
        "artifacts/models/autoencoder/autoencoder_manifest.json",
        "artifacts/models/autoencoder/model_config.json",
        "artifacts/models/autoencoder/threshold.json",
        "data/demo/demo_flows.csv",
        "data/demo/demo_labels.csv",
        "data/demo/demo_manifest.json",
        "EMBEDDED_ARTIFACTS_MANIFEST.json",
        "EMBEDDED_SHA256SUMS.txt",
    }
    assert required_standalone_dests.issubset(destinations)
    for notice_key in ("../../NOTICE", "../../THIRD_PARTY_NOTICES.md", "../../LICENSE"):
        assert notice_key in base_res


def test_stage_embedded_bundle_and_installed_standalone_layout(tmp_path: Path):
    import hashlib

    import scripts.verify_companion_artifacts as vca

    if not (REPO_ROOT / "artifacts/models/random_forest/random_forest_baseline.joblib").is_file():
        pytest.skip("Local ML model binaries absent on runner")

    stage_dir = tmp_path / "staged"
    staged = vca.stage_embedded_bundle(
        stage_dir,
        root=REPO_ROOT,
        runtime_dir=REPO_ROOT,
        distribution_scope="private-build-only",
        target_channel="local_offline",
    )
    assert staged["stage_status"] == "READY"
    assert (stage_dir / "EMBEDDED_SHA256SUMS.txt").is_file()
    assert (stage_dir / "EMBEDDED_ARTIFACTS_MANIFEST.json").is_file()
    assert not (stage_dir / "COMPANION_SHA256SUMS.txt").exists()

    # Build a synthetic installed standalone directory matching staged files + sidecar
    install_dir = tmp_path / "install_dir"
    shutil.copytree(stage_dir, install_dir)
    (install_dir / "netflow-sentinel-desktop.exe").write_bytes(b"DESKTOP-STUB")
    sidecar_bytes = b"PYINSTALLER-SIDECAR-STUB"
    (install_dir / "netflow-sentinel-backend.exe").write_bytes(sidecar_bytes)
    (install_dir / "uninstall.exe").write_bytes(b"NSIS-UNINSTALL-STUB")
    expected_sidecar_sha = hashlib.sha256(sidecar_bytes).hexdigest()

    layout = vca.verify_installed_standalone_layout(
        install_dir, expected_sidecar_sha256=expected_sidecar_sha
    )
    assert layout["status"] == "READY"
    assert layout["sidecar_sha256"] == expected_sidecar_sha

    # Tamper sidecar or embedded file must fail closed
    with pytest.raises(RuntimeError, match="sidecar SHA-256 mismatch"):
        vca.verify_installed_standalone_layout(install_dir, expected_sidecar_sha256="0" * 64)

    (install_dir / "data/demo/demo_flows.csv").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        vca.verify_installed_standalone_layout(
            install_dir, expected_sidecar_sha256=expected_sidecar_sha
        )


def test_verify_e2e_attestation_require_standalone_embedded(tmp_path: Path):
    ws = _copy_attestation_workspace(tmp_path)
    head_commit = "a" * 40
    base = _build_valid_attestation_payload(ws, include_nsis=True, commit=head_commit)

    # Non-standalone attestation must fail --require-standalone-embedded
    legacy_payload = json.loads(json.dumps(base))
    legacy_payload["e2e_backend_origin"] = "installed_nsis_desktop"
    legacy_payload["nsis_e2e"]["standalone_embedded_mode"] = False
    legacy_payload["nsis_e2e"]["system_python_used"] = True
    legacy_path = tmp_path / "legacy_att.json"
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="standalone embedded NSIS"):
        vca.verify_e2e_attestation(
            legacy_path,
            root=ws,
            require_nsis_e2e=True,
            require_standalone_embedded=True,
        )

    standalone_att = json.loads(json.dumps(base))
    standalone_att["e2e_backend_origin"] = "installed_standalone_nsis"
    standalone_att["session_auth_fail_closed"] = False
    standalone_att["nsis_e2e"].update(
        {
            "bundled_resources_mode": True,
            "repo_root_env_passed": False,
            "runtime_dir_isolated": True,
            "standalone_embedded_mode": True,
            "sidecar_exe_verified": True,
            "sidecar_sha256": "f" * 64,
            "system_python_used": False,
            "external_companion_used": False,
            "restart_persistence_verified": True,
            "export_verified": True,
        }
    )
    standalone_att["attestation_environment"] = {
        "environment_tier": "local_developer_machine",
        "execution_context": "local_developer_machine",
        "clean_machine_status": "NOT VERIFIED",
        "source_tree_clean": True,
        "system_python_used": False,
        "clean_machine_verified": False,
        "runner_provenance_verified": False,
        "runner_identity": {
            "provenance_source": "none_local_developer_machine",
            "workflow_run_id": None,
            "run_attempt": None,
            "github_repository": None,
            "workflow_path": None,
            "runner_name": None,
            "runner_labels": [],
            "vm_provenance_ref": None,
            "vm_evidence_sha256": None,
        },
        "bindings": {
            "source_commit": head_commit,
            "installer_sha256": standalone_att["nsis_e2e"]["installer_sha256"],
            "sidecar_sha256": "f" * 64,
        },
        "standalone_verified": False,
    }
    standalone_path = tmp_path / "standalone_att.json"
    standalone_path.write_text(json.dumps(standalone_att), encoding="utf-8")

    # Missing session_auth_fail_closed=True fails standalone verification
    with pytest.raises(RuntimeError, match="session_auth_fail_closed"):
        vca.verify_e2e_attestation(
            standalone_path,
            root=ws,
            require_nsis_e2e=True,
            require_standalone_embedded=True,
        )

    standalone_att["session_auth_fail_closed"] = True
    standalone_path.write_text(json.dumps(standalone_att), encoding="utf-8")

    # F-03: stale source_commit != HEAD or mismatched sidecar_sha256 fails closed
    with pytest.raises(RuntimeError, match="source_commit mismatch"):
        vca.verify_e2e_attestation(
            standalone_path,
            root=ws,
            expect_commit="9" * 40,
            require_nsis_e2e=True,
            require_standalone_embedded=True,
        )
    with pytest.raises(RuntimeError, match="sidecar_sha256 mismatch"):
        vca.verify_e2e_attestation(
            standalone_path,
            root=ws,
            expect_commit=head_commit,
            expect_sidecar_sha256="e" * 64,
            require_nsis_e2e=True,
            require_standalone_embedded=True,
        )

    # F-03: local developer machine attestation passes local standalone check,
    # NOT --require-clean-machine-e2e
    res_local = vca.verify_e2e_attestation(
        standalone_path,
        root=ws,
        expect_commit=head_commit,
        expect_sidecar_sha256="f" * 64,
        require_nsis_e2e=True,
        require_bundled_resources=True,
        require_standalone_embedded=True,
    )
    assert res_local["standalone_embedded_verified"] is True
    assert res_local["clean_machine_verified"] is False
    assert res_local["clean_machine_status"] == "NOT VERIFIED"

    with pytest.raises(RuntimeError, match="require-clean-machine-e2e"):
        vca.verify_e2e_attestation(
            standalone_path,
            root=ws,
            expect_commit=head_commit,
            expect_sidecar_sha256="f" * 64,
            require_nsis_e2e=True,
            require_standalone_embedded=True,
            require_clean_machine_e2e=True,
        )

    # F-04: Self-declared bare 'clean_ci_runner' without runner identity & provenance MUST fail
    spoofed_clean = copy.deepcopy(standalone_att)
    spoofed_clean["attestation_environment"] = {
        "execution_context": "clean_ci_runner",
        "source_tree_clean": True,
        "system_python_used": False,
        "clean_machine_verified": True,
        "standalone_verified": True,
    }
    standalone_path.write_text(json.dumps(spoofed_clean), encoding="utf-8")
    with pytest.raises(RuntimeError, match="require-clean-machine-e2e"):
        vca.verify_e2e_attestation(
            standalone_path,
            root=ws,
            expect_commit=head_commit,
            expect_sidecar_sha256="f" * 64,
            require_nsis_e2e=True,
            require_bundled_resources=True,
            require_standalone_embedded=True,
            require_clean_machine_e2e=True,
        )

    # F-04: GitHub-hosted Windows runner attestation with full bindings passes
    gh_clean = copy.deepcopy(standalone_att)
    gh_clean["attestation_environment"] = {
        "environment_tier": "github_hosted_windows_runner",
        "execution_context": "github_hosted_windows_runner",
        "clean_machine_status": "VERIFIED",
        "source_tree_clean": True,
        "system_python_used": False,
        "clean_machine_verified": True,
        "runner_provenance_verified": True,
        "runner_identity": {
            "provenance_source": "github_actions_api",
            "workflow_run_id": "123456789",
            "run_attempt": 1,
            "github_repository": "owner/repo",
            "workflow_path": ".github/workflows/release.yml",
            "runner_name": "Hosted Agent",
            "runner_labels": ["windows-latest"],
            "vm_provenance_ref": None,
            "vm_evidence_sha256": None,
        },
        "bindings": {
            "source_commit": head_commit,
            "installer_sha256": standalone_att["nsis_e2e"]["installer_sha256"],
            "sidecar_sha256": "f" * 64,
        },
        "standalone_verified": True,
    }
    standalone_path.write_text(json.dumps(gh_clean), encoding="utf-8")
    res_clean = vca.verify_e2e_attestation(
        standalone_path,
        root=ws,
        expect_commit=head_commit,
        expect_sidecar_sha256="f" * 64,
        require_nsis_e2e=True,
        require_bundled_resources=True,
        require_standalone_embedded=True,
        require_clean_machine_e2e=True,
    )
    assert res_clean["clean_machine_verified"] is True
    assert res_clean["clean_machine_status"] == "VERIFIED"
    assert res_clean["environment_tier"] == "github_hosted_windows_runner"

    # F-07: Self-declared independent_windows_vm (bare vm_evidence_sha256 without signed witness + live probe) MUST fail closed
    legacy_vm = copy.deepcopy(gh_clean)
    legacy_vm["attestation_environment"]["environment_tier"] = "independent_windows_vm"
    legacy_vm["attestation_environment"]["execution_context"] = "independent_windows_vm"
    legacy_vm["attestation_environment"]["runner_identity"] = {
        "provenance_source": "independent_vm_verified_attestation",
        "workflow_run_id": None,
        "run_attempt": None,
        "github_repository": None,
        "workflow_path": None,
        "runner_name": "win11-clean-vm-01",
        "runner_labels": ["independent-windows-vm"],
        "vm_provenance_ref": "hyperv-snapshot-clean-2026-11-16",
        "vm_evidence_sha256": "c" * 64,
    }
    standalone_path.write_text(json.dumps(legacy_vm), encoding="utf-8")
    with pytest.raises(RuntimeError, match="require-clean-machine-e2e"):
        vca.verify_e2e_attestation(
            standalone_path,
            root=ws,
            expect_commit=head_commit,
            expect_sidecar_sha256="f" * 64,
            require_nsis_e2e=True,
            require_bundled_resources=True,
            require_standalone_embedded=True,
            require_clean_machine_e2e=True,
        )

    # A legacy VM report without challenge/evidence bindings must fail closed.
    vm_clean = copy.deepcopy(gh_clean)
    vm_clean["attestation_environment"]["environment_tier"] = "independent_windows_vm"
    vm_clean["attestation_environment"]["execution_context"] = "independent_windows_vm"
    vm_clean["attestation_environment"]["runner_identity"] = {
        "provenance_source": "independent_vm_signed_witness",
        "workflow_run_id": None,
        "run_attempt": None,
        "github_repository": None,
        "workflow_path": None,
        "runner_name": "win11-clean-vm-01",
        "runner_labels": ["independent-windows-vm"],
        "vm_provenance_ref": "hyperv-snapshot-clean-2026-11-16",
        "trusted_authority_id": "ci-vm-witness-authority",
        "issued_at_utc": "2026-11-16T14:30:00Z",
        "signature_algorithm": "hmac-sha256-external-witness",
        "signature_verified": True,
        "live_host_probe": {
            "platform": "win32",
            "observed_hostname": "win11-clean-vm-01",
            "git_dir_present": False,
            "dev_tools_absent": True,
            "found_dev_tools": [],
            "dev_models_tree_absent": True,
        },
    }
    standalone_path.write_text(json.dumps(vm_clean), encoding="utf-8")
    with pytest.raises(RuntimeError, match="require-clean-machine-e2e"):
        vca.verify_e2e_attestation(
            standalone_path,
            root=ws,
            expect_commit=head_commit,
            expect_sidecar_sha256="f" * 64,
            require_nsis_e2e=True,
            require_bundled_resources=True,
            require_standalone_embedded=True,
            require_clean_machine_e2e=True,
        )

    # F-04: Mismatched bindings (source_commit / sidecar_sha256 / installer_sha256) must fail
    bad_bind = copy.deepcopy(gh_clean)
    bad_bind["attestation_environment"]["bindings"]["installer_sha256"] = "1" * 64
    standalone_path.write_text(json.dumps(bad_bind), encoding="utf-8")
    with pytest.raises(RuntimeError, match="bindings.installer_sha256 mismatch"):
        vca.verify_e2e_attestation(
            standalone_path,
            root=ws,
            expect_commit=head_commit,
            expect_sidecar_sha256="f" * 64,
            require_nsis_e2e=True,
            require_standalone_embedded=True,
            require_clean_machine_e2e=True,
        )


def test_f04_clean_machine_e2e_rejects_local_and_spoofed_env_and_verifies_api_provenance(
    tmp_path: Path, monkeypatch
):
    commit = "a" * 40
    # 1) Local developer machine passing clean_machine_e2e=True must fail closed
    with pytest.raises(RuntimeError, match="REFUSED --clean-machine-e2e"):
        vca._resolve_clean_machine_provenance(
            clean_machine_e2e=True,
            standalone_embedded=True,
            pass_repo_root_env=False,
            source_tree_clean=True,
            source_commit=commit,
            github_repo=None,
            github_run_id=None,
            token_env_var=None,
            independent_vm_evidence=None,
        )

    # 2) Spoofed env vars without API provenance or VM evidence still fail closed
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_NAME", "Hosted Agent")
    monkeypatch.setenv("GITHUB_RUN_ID", "999999")
    with pytest.raises(RuntimeError, match="REFUSED --clean-machine-e2e"):
        vca._resolve_clean_machine_provenance(
            clean_machine_e2e=True,
            standalone_embedded=True,
            pass_repo_root_env=False,
            source_tree_clean=True,
            source_commit=commit,
            github_repo=None,
            github_run_id=None,
            token_env_var=None,
            independent_vm_evidence=None,
        )

    # 3) Historical completed workflow run MUST be refused when asserting live clean-machine E2E
    monkeypatch.setenv("GH_TOKEN", "dummy-ci-token")

    def _mock_completed_api(url: str, **_kwargs) -> bytes:
        if url.endswith("/actions/runs/999999"):
            return json.dumps(
                {
                    "id": 999999,
                    "head_sha": commit,
                    "status": "completed",
                    "run_attempt": 1,
                    "path": ".github/workflows/release.yml",
                    "repository": {"full_name": "owner/repo"},
                }
            ).encode("utf-8")
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(vca, "_download_allowlisted_bytes", _mock_completed_api)
    with pytest.raises(RuntimeError, match="status must be 'in_progress'"):
        vca._resolve_clean_machine_provenance(
            clean_machine_e2e=True,
            standalone_embedded=True,
            pass_repo_root_env=False,
            source_tree_clean=True,
            source_commit=commit,
            github_repo="owner/repo",
            github_run_id="999999",
            token_env_var="GH_TOKEN",
            independent_vm_evidence=None,
        )

    # 4) Active live in_progress GitHub-hosted Windows runner passes and captures runner_identity
    def _mock_live_windows_api(url: str, **_kwargs) -> bytes:
        if url.endswith("/actions/runs/999999"):
            return json.dumps(
                {
                    "id": 999999,
                    "head_sha": commit,
                    "status": "in_progress",
                    "run_attempt": 2,
                    "path": ".github/workflows/release.yml",
                    "repository": {"full_name": "owner/repo"},
                }
            ).encode("utf-8")
        if "/jobs" in url:
            return json.dumps(
                {
                    "jobs": [
                        {
                            "status": "in_progress",
                            "runner_name": "Hosted Agent",
                            "labels": ["windows-latest"],
                        }
                    ]
                }
            ).encode("utf-8")
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(vca, "_download_allowlisted_bytes", _mock_live_windows_api)
    tier, ident = vca._resolve_clean_machine_provenance(
        clean_machine_e2e=True,
        standalone_embedded=True,
        pass_repo_root_env=False,
        source_tree_clean=True,
        source_commit=commit,
        github_repo="owner/repo",
        github_run_id="999999",
        token_env_var="GH_TOKEN",
        independent_vm_evidence=None,
    )
    assert tier == "github_hosted_windows_runner"
    assert ident is not None
    assert ident["workflow_run_id"] == "999999"
    assert ident["runner_name"] == "Hosted Agent"
    assert ident["runner_labels"] == ["windows-latest"]

    # The same-host legacy path cannot bypass Controller nonce consumption.
    with pytest.raises(RuntimeError, match="persistent --consumed-nonces-file"):
        vca._resolve_clean_machine_provenance(
            clean_machine_e2e=True,
            standalone_embedded=True,
            pass_repo_root_env=False,
            source_tree_clean=True,
            source_commit=commit,
            github_repo=None,
            github_run_id=None,
            token_env_var=None,
            independent_vm_evidence=tmp_path / "vm_evidence.json",
        )
