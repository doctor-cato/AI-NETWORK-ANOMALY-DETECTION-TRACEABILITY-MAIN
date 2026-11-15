"""Unit tests for companion artifact verification, NSIS E2E, and attestation checks."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest

import scripts.verify_companion_artifacts as vca
from scripts.verify_companion_artifacts import (
    main as verify_companion_main,
)
from scripts.verify_companion_artifacts import (
    run_four_model_e2e_verification,
    stage_companion_bundle,
    verify_companion_artifacts,
    verify_e2e_attestation,
    verify_nsis_installer_e2e,
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
        "data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
        "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json",
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
        "L4_SRC_PORT,L4_DST_PORT\n80,443\n443,51234\n", encoding="utf-8", newline="\n"
    )
    labels_path.write_text("row_index,Label\n0,0\n1,1\n", encoding="utf-8", newline="\n")
    split_sha = _sha256_path(ws / "data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json")
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
    split_sha = _sha256_path(root / "data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json")
    prep_manifest = json.loads(
        (root / "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json").read_text(
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

    # Mock clean Windows install/uninstall verification
    sums_file = tmp_path / "SHA256SUMS.txt"
    sums_file.write_text(f"{installer_sha}  {installer.name}\n", encoding="utf-8")
    compiled_exe = tmp_path / "netflow-sentinel-desktop.exe"
    exe_bytes = b"MZ" + b"\xcd" * 1_200_000
    compiled_exe.write_bytes(exe_bytes)
    compiled_sha = _sha256_bytes(exe_bytes)

    seen_cmds: list[list[str]] = []

    def _fake_subprocess_run(cmd, **_kwargs):
        seen_cmds.append(list(cmd))
        exe_arg = Path(cmd[0])
        if exe_arg.resolve() == installer.resolve():
            d_arg = next(a for a in cmd if a.startswith("/D="))
            target_dir = Path(d_arg[3:])
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "netflow-sentinel-desktop.exe").write_bytes(exe_bytes)
            (target_dir / "uninstall.exe").write_bytes(b"UNINST")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(vca, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(vca.subprocess, "run", _fake_subprocess_run)

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
    assert len(seen_cmds) == 2

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

    def _fake_subprocess_run(cmd, **_kwargs):
        exe_arg = Path(cmd[0])
        if exe_arg.resolve() == installer.resolve():
            d_arg = next(a for a in cmd if a.startswith("/D="))
            target_dir = Path(d_arg[3:])
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "netflow-sentinel-desktop.exe").write_bytes(installed_bytes)
            (target_dir / "uninstall.exe").write_bytes(b"UNINST")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(vca, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(vca.subprocess, "run", _fake_subprocess_run)

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


def test_verify_shipped_v060_e2e_attestation_passes():
    att_path = REPO_ROOT / "reports" / "releases" / "v0.6.0_e2e_verification.json"
    result = verify_e2e_attestation(att_path, root=REPO_ROOT)
    assert result["attestation_status"] == "PASS"
    assert len(result["verified_models"]) == 4


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
    (partial_dir / "demo_flows.csv").write_text("L4_SRC_PORT\n80\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Incomplete tracked demo files"):
        verify_e2e_attestation(att, root=ws)
