"""Integration tests for Controller -> Clean Windows Target -> Evidence -> Verification (F-07/F-10)."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

from scripts.verify_companion_artifacts import (
    issue_vm_target_challenge,
    sign_vm_witness_receipt,
    verify_e2e_attestation,
    verify_vm_target_evidence,
)
from scripts.verify_companion_artifacts import (
    main as verify_companion_main,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().lower()


def _recompute_metrics(tn: int, fp: int, fn: int, tp: int) -> Dict[str, float]:
    total = tn + fp + fn + tp
    acc = (tp + tn) / total
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = (2.0 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "prediction_coverage": total / 200.0,
    }


def _create_controller_git_repo(tmp_path: Path) -> Dict[str, Any]:
    """Create a real Git repository checkout representing the Build/Verification Controller."""
    ctrl = tmp_path / "controller_repo"
    rel_files = [
        "scripts/verify_companion_artifacts.py",
        "desktop/package.json",
        "data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
        "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json",
        "reports/models/random_forest_manifest.json",
        "reports/models/xgboost_manifest.json",
        "reports/models/isolation_forest_manifest.json",
        "reports/models/autoencoder_manifest.json",
        "reports/governance/DISTRIBUTION_AUTHORIZATION.json",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
        "LICENSE",
    ]
    for rel in rel_files:
        src = REPO_ROOT / rel
        dst = ctrl / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    subprocess.run(["git", "init"], cwd=str(ctrl), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "controller@example.invalid"],
        cwd=str(ctrl),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Controller CI"],
        cwd=str(ctrl),
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "add", "."], cwd=str(ctrl), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init controller snapshot"],
        cwd=str(ctrl),
        check=True,
        capture_output=True,
    )
    head_sha = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ctrl), text=True)
        .strip()
        .lower()
    )

    build_dir = tmp_path / "controller_build"
    build_dir.mkdir(parents=True, exist_ok=True)
    installer = build_dir / "NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe"
    installer.write_bytes(b"MZ" + b"\xab" * 1_200_000)
    compiled_exe = build_dir / "netflow-sentinel-desktop.exe"
    compiled_bytes = b"MZ" + b"\x10" * 550_000 + b"BUNDLE_TYPE_VAR_UNK" + b"\x20" * 550_000
    compiled_exe.write_bytes(compiled_bytes)
    installed_bytes = compiled_bytes.replace(b"BUNDLE_TYPE_VAR_UNK", b"BUNDLE_TYPE_VAR_NSS", 1)
    sidecar_sha = "7" * 64

    return {
        "repo": ctrl,
        "head_sha": head_sha,
        "installer": installer,
        "installer_sha": _sha256_path(installer),
        "compiled_exe": compiled_exe,
        "installed_exe_sha": hashlib.sha256(installed_bytes).hexdigest().lower(),
        "sidecar_sha": sidecar_sha,
    }


def _simulate_clean_target_execution(
    *,
    target_dir: Path,
    challenge: Dict[str, Any],
    ctrl_repo: Path,
    installed_exe_sha: str,
    observed_hostname: str = "WIN11-CLEAN-TARGET-VM",
) -> Path:
    """Produce Target VM evidence inside an isolated non-Git directory with zero secrets."""
    target_dir.mkdir(parents=True, exist_ok=True)
    assert not (target_dir / ".git").exists()
    assert not (target_dir / "scripts").exists()

    split_sha = _sha256_path(ctrl_repo / "data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json")
    prep_sha = json.loads(
        (ctrl_repo / "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json").read_text(
            encoding="utf-8"
        )
    )["artifact_sha256"]
    demo_sha256 = {
        "data/demo/demo_flows.csv": "1" * 64,
        "data/demo/demo_labels.csv": "2" * 64,
        "data/demo/demo_manifest.json": "3" * 64,
    }

    cm_specs = {
        "random_forest": (98, 0, 0, 100),
        "xgboost": (98, 0, 0, 100),
        "isolation_forest": (89, 9, 12, 88),
        "autoencoder": (93, 5, 87, 13),
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
            "NO_ACTION": 89,
            "MONITOR": 11,
            "INVESTIGATE": 100,
            "ISOLATE_RECOMMENDED": 0,
        },
        "autoencoder": {
            "NO_ACTION": 93,
            "MONITOR": 89,
            "INVESTIGATE": 18,
            "ISOLATE_RECOMMENDED": 0,
        },
    }
    manifest_map = {
        "random_forest": "reports/models/random_forest_manifest.json",
        "xgboost": "reports/models/xgboost_manifest.json",
        "isolation_forest": "reports/models/isolation_forest_manifest.json",
        "autoencoder": "reports/models/autoencoder_manifest.json",
    }

    models_payload: Dict[str, Any] = {}
    for key, (tn, fp, fn, tp) in cm_specs.items():
        man = json.loads((ctrl_repo / manifest_map[key]).read_text(encoding="utf-8"))
        art_sha = (
            man.get("model_artifact_sha256")
            or man.get("model_sha256")
            or man.get("artifact_sha256")
        )
        is_rf = key == "random_forest"
        models_payload[key] = {
            "artifact_sha256": art_sha,
            "run_id": man["run_id"],
            "inference_run_id": f"inference-20261116220000-{key[:6]}",
            "preprocessor_sha256": prep_sha,
            "source_csv_sha256": demo_sha256["data/demo/demo_flows.csv"],
            "labels_sha256": demo_sha256["data/demo/demo_labels.csv"],
            "inference_mode": "verified_model",
            "analysis_id": f"csvrun_{key}_vm01",
            "dry_run_simulation_id": f"sim_{key}_vm01",
            "total_rows": 200,
            "evaluated_rows": 198,
            "abstained_rows": 2,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            **_recompute_metrics(tn, fp, fn, tp),
            "compatibility_status": "MODEL_VALIDATED" if is_rf else "RESEARCH_ONLY",
            "dry_run_provenance": "server_verified_analysis",
            "dry_run_rotation_decision": (
                "SIMULATED_ROTATION_RECOMMENDED" if is_rf else "HOLD_RESEARCH_ONLY_MODEL"
            ),
            "dry_run_action_counts": action_specs[key],
        }

    evidence = {
        "format": "netflow-sentinel-vm-target-evidence-v1",
        "challenge_nonce": challenge["challenge_nonce"],
        "completed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "desktop_version": challenge["desktop_version"],
        "port": 55123,
        "split_manifest_sha256": split_sha,
        "preprocessor_sha256": prep_sha,
        "demo_sha256": demo_sha256,
        "ready_models": list(cm_specs.keys()),
        "models": models_payload,
        "session_auth_fail_closed": True,
        "client_spoof_fail_closed": {
            "provenance_verification": "client_supplied_unverified",
            "critical_downgraded_action": "INVESTIGATE",
            "rotation_decision": "HOLD_UNVERIFIED_PROVENANCE",
        },
        "target_probe": {
            "platform": "win32",
            "observed_hostname": observed_hostname,
            "vm_name": observed_hostname,
            "git_dir_present": False,
            "dev_tools_checked": [
                "git",
                "python",
                "python3",
                "py",
                "rustc",
                "cargo",
                "node",
                "npm",
            ],
            "dev_tools_absent": True,
            "found_dev_tools": [],
            "standard_tool_dirs_checked": [],
            "found_standard_tool_dirs": [],
            "dev_models_tree_absent": True,
            "cleanliness_claim_scope": "observed_path_and_standard_dirs_only_not_cryptographic_clean_os_proof",
        },
        "nsis_e2e": {
            "status": "PASS",
            "installer_filename": challenge["installer_filename"],
            "installer_sha256": challenge["installer_sha256"],
            "installer_size_bytes": challenge["installer_size_bytes"],
            "sums_file_verified": True,
            "installed_exe_sha256": installed_exe_sha,
            "compiled_exe_sha256": challenge["compiled_exe_sha256"],
            "normalized_compiled_exe_sha256": challenge["normalized_compiled_exe_sha256"],
            "compiled_exe_sha256_match": True,
            "exe_parity_mode": "tauri_nsis_bundle_marker_normalized",
            "uninstaller_verified": True,
            "clean_install_verified": True,
            "installed_app_launched": True,
            "installed_exe_path_verified": True,
            "frontend_webview_connected": True,
            "frontend_ready_models": list(cm_specs.keys()),
            "bundled_resources_mode": True,
            "repo_root_env_passed": False,
            "runtime_dir_isolated": True,
            "backend_spawned_on_loopback": True,
            "backend_port": 55123,
            "graceful_close_verified": True,
            "graceful_close_method": "close_main_window",
            "zero_orphan_processes_verified": True,
            "uninstall_cleanup_verified": True,
            "standalone_embedded_mode": True,
            "sidecar_exe_verified": True,
            "sidecar_sha256": challenge["sidecar_sha256"],
            "sidecar_size_bytes": 162_000_000,
            "system_python_used": False,
            "external_companion_used": False,
            "restart_persistence_verified": True,
            "export_verified": True,
        },
    }
    ev_path = target_dir / "target_evidence.json"
    ev_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return ev_path


def test_controller_target_vm_e2e_full_lifecycle_and_negative_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F-10/F-07 E2E: Controller has Git, Target has no Git/Python/secret; anti-replay & fail-closed."""
    ctrl_info = _create_controller_git_repo(tmp_path)
    ctrl_repo: Path = ctrl_info["repo"]
    installer: Path = ctrl_info["installer"]
    compiled_exe: Path = ctrl_info["compiled_exe"]
    sidecar_sha: str = ctrl_info["sidecar_sha"]

    challenge_path = tmp_path / "out" / "vm_challenge.json"
    rc_challenge = verify_companion_main(
        [
            "--root",
            str(ctrl_repo),
            "--issue-vm-challenge",
            "--require-clean-git",
            "--installer-path",
            str(installer),
            "--compiled-exe",
            str(compiled_exe),
            "--expect-sidecar-sha256",
            sidecar_sha,
            "--vm-provenance-ref",
            "hyperv-win11-clean-2026-11-16",
            "--output-json",
            str(challenge_path),
        ]
    )
    assert rc_challenge == 0
    challenge = json.loads(challenge_path.read_text(encoding="utf-8"))
    assert challenge["source_commit"] == ctrl_info["head_sha"]
    assert challenge["installer_sha256"] == ctrl_info["installer_sha"]

    # Target executes without Git, Python, repo checkout, or signing secret
    target_ev_path = _simulate_clean_target_execution(
        target_dir=tmp_path / "isolated_clean_vm",
        challenge=challenge,
        ctrl_repo=ctrl_repo,
        installed_exe_sha=ctrl_info["installed_exe_sha"],
        observed_hostname="WIN11-CLEAN-VM-01",
    )

    # 1. Missing witness evidence MUST remain NOT VERIFIED (never self-declare clean_machine_verified=true)
    tampered_self_claim = json.loads(target_ev_path.read_text(encoding="utf-8"))
    tampered_self_claim["clean_machine_verified"] = True
    tampered_self_claim["clean_machine_status"] = "VERIFIED"
    self_claim_path = tmp_path / "self_claim_target_ev.json"
    self_claim_path.write_text(json.dumps(tampered_self_claim, indent=2), encoding="utf-8")

    unwitnessed_report = verify_vm_target_evidence(
        target_evidence_path=self_claim_path,
        challenge_path=challenge_path,
        root=ctrl_repo,
        installer_path=installer,
        compiled_exe_path=compiled_exe,
        expected_sidecar_sha256=sidecar_sha,
        clean_machine_e2e=False,
    )
    assert unwitnessed_report["attestation_environment"]["clean_machine_status"] == "NOT VERIFIED"
    assert unwitnessed_report["attestation_environment"]["clean_machine_verified"] is False
    assert unwitnessed_report["attestation_environment"]["standalone_verified"] is False

    # And with --clean-machine-e2e, missing witness fails closed
    nonces_ledger = tmp_path / "controller_state" / "consumed_nonces.json"
    with pytest.raises(RuntimeError, match="NOT VERIFIED"):
        verify_vm_target_evidence(
            target_evidence_path=target_ev_path,
            challenge_path=challenge_path,
            root=ctrl_repo,
            installer_path=installer,
            compiled_exe_path=compiled_exe,
            expected_sidecar_sha256=sidecar_sha,
            clean_machine_e2e=True,
            consumed_nonces_file=nonces_ledger,
        )

    # 2. Trusted-boundary witness signing (secret lives ONLY on witness authority / Controller, never Target)
    witness_secret = "trusted-authority-hmac-key-2026"
    monkeypatch.setenv("NETFLOW_VM_ATTESTATION_HMAC_KEY", witness_secret)
    witness_path = tmp_path / "out" / "vm_witness.json"
    rc_sign = verify_companion_main(
        [
            "--sign-vm-witness",
            "--vm-challenge",
            str(challenge_path),
            "--verify-target-evidence",
            str(target_ev_path),
            "--vm-provenance-ref",
            "hyperv-win11-clean-2026-11-16",
            "--trusted-authority-id",
            "ci-hypervisor-authority",
            "--output-json",
            str(witness_path),
        ]
    )
    assert rc_sign == 0

    # 3. Full Controller verification with anti-replay ledger succeeds despite Controller having .git!
    final_att_path = tmp_path / "out" / "release_e2e_verification.json"
    verify_args = [
        "--root",
        str(ctrl_repo),
        "--verify-target-evidence",
        str(target_ev_path),
        "--vm-challenge",
        str(challenge_path),
        "--vm-witness",
        str(witness_path),
        "--installer-path",
        str(installer),
        "--compiled-exe",
        str(compiled_exe),
        "--expect-sidecar-sha256",
        sidecar_sha,
        "--require-clean-git",
        "--clean-machine-e2e",
        "--output-json",
        str(final_att_path),
    ]
    for args in (verify_args, [arg for arg in verify_args if arg != "--clean-machine-e2e"]):
        assert verify_companion_main(args) == 1
        assert not final_att_path.exists()

    nonces_ledger.parent.mkdir()
    for invalid_ledger in ('{"schema_version":2,"consumed_nonces":[]}', '{"consumed_nonces":[1]}'):
        nonces_ledger.write_text(invalid_ledger, encoding="utf-8")
        assert (
            verify_companion_main([*verify_args, "--consumed-nonces-file", str(nonces_ledger)]) == 1
        )
        assert nonces_ledger.read_text(encoding="utf-8") == invalid_ledger
        assert not final_att_path.exists()
    nonces_ledger.unlink()
    nonces_ledger.mkdir()
    assert verify_companion_main([*verify_args, "--consumed-nonces-file", str(nonces_ledger)]) == 1
    assert not final_att_path.exists()
    nonces_ledger.rmdir()
    assert verify_companion_main([*verify_args, "--consumed-nonces-file", str(final_att_path)]) == 1
    assert not final_att_path.exists()

    rc_verify = verify_companion_main([*verify_args, "--consumed-nonces-file", str(nonces_ledger)])
    assert rc_verify == 0
    final_att = json.loads(final_att_path.read_text(encoding="utf-8"))
    assert final_att["attestation_environment"]["environment_tier"] == "independent_windows_vm"
    assert final_att["attestation_environment"]["clean_machine_status"] == "VERIFIED"
    assert final_att["attestation_environment"]["clean_machine_verified"] is True
    assert final_att["attestation_environment"]["standalone_verified"] is True

    # Verify final attestation with strict --verify-attestation + --verify-vm-witness
    att_res = verify_e2e_attestation(
        final_att_path,
        root=ctrl_repo,
        expect_commit=ctrl_info["head_sha"],
        expect_installer_sha256=ctrl_info["installer_sha"],
        expect_sidecar_sha256=sidecar_sha,
        require_nsis_e2e=True,
        require_bundled_resources=True,
        require_standalone_embedded=True,
        require_clean_machine_e2e=True,
        verify_vm_witness=True,
    )
    assert att_res["clean_machine_verified"] is True
    assert att_res["clean_machine_status"] == "VERIFIED"
    with pytest.raises(RuntimeError, match="NOT VERIFIED for windows_10_x64"):
        verify_e2e_attestation(
            final_att_path,
            root=ctrl_repo,
            expect_commit=ctrl_info["head_sha"],
            require_stable_windows_e2e=True,
        )

    altered_report = copy.deepcopy(final_att)
    altered_report["nsis_e2e"]["frontend_interactive_gui_clicks"] = "PASS"
    altered_report_path = tmp_path / "out" / "altered_attestation.json"
    altered_report_path.write_text(json.dumps(altered_report), encoding="utf-8")
    with pytest.raises(RuntimeError, match="Controller attestation signature"):
        verify_e2e_attestation(
            altered_report_path,
            root=ctrl_repo,
            expect_commit=ctrl_info["head_sha"],
            require_clean_machine_e2e=True,
        )

    # 4. Replay of same challenge + target evidence + witness MUST be rejected
    with pytest.raises(RuntimeError, match="REPLAY REJECTED"):
        verify_vm_target_evidence(
            target_evidence_path=target_ev_path,
            challenge_path=challenge_path,
            root=ctrl_repo,
            installer_path=installer,
            compiled_exe_path=compiled_exe,
            expected_sidecar_sha256=sidecar_sha,
            clean_machine_e2e=True,
            vm_witness_path=witness_path,
            consumed_nonces_file=nonces_ledger,
        )

    # 5. Tampered target evidence (1 field changed) MUST fail target_evidence_sha256 check
    fresh_challenge = issue_vm_target_challenge(
        installer_path=installer,
        expected_sidecar_sha256=sidecar_sha,
        root=ctrl_repo,
        compiled_exe_path=compiled_exe,
    )
    fresh_ch_path = tmp_path / "out" / "fresh_challenge.json"
    fresh_ch_path.write_text(json.dumps(fresh_challenge, indent=2), encoding="utf-8")
    fresh_ev_path = _simulate_clean_target_execution(
        target_dir=tmp_path / "isolated_clean_vm_2",
        challenge=fresh_challenge,
        ctrl_repo=ctrl_repo,
        installed_exe_sha=ctrl_info["installed_exe_sha"],
        observed_hostname="WIN11-CLEAN-VM-02",
    )
    fresh_witness = sign_vm_witness_receipt(
        challenge_path=fresh_ch_path,
        target_evidence_path=fresh_ev_path,
        vm_provenance_ref="hyperv-win11-clean-2026-11-16",
    )
    fresh_w_path = tmp_path / "out" / "fresh_witness.json"
    fresh_w_path.write_text(json.dumps(fresh_witness, indent=2), encoding="utf-8")

    tampered_ev = json.loads(fresh_ev_path.read_text(encoding="utf-8"))
    tampered_ev["port"] = 55999
    tampered_ev_path = tmp_path / "out" / "tampered_ev.json"
    tampered_ev_path.write_text(json.dumps(tampered_ev, indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError, match="target_evidence_sha256 mismatch"):
        verify_vm_target_evidence(
            target_evidence_path=tampered_ev_path,
            challenge_path=fresh_ch_path,
            root=ctrl_repo,
            installer_path=installer,
            compiled_exe_path=compiled_exe,
            expected_sidecar_sha256=sidecar_sha,
            clean_machine_e2e=True,
            vm_witness_path=fresh_w_path,
            consumed_nonces_file=nonces_ledger,
        )

    # 6. Wrong HMAC witness signature MUST fail
    bad_witness = copy.deepcopy(fresh_witness)
    bad_witness["witness_signature_hex"] = "0" * 64
    bad_w_path = tmp_path / "out" / "bad_witness.json"
    bad_w_path.write_text(json.dumps(bad_witness, indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError, match="cryptographic signature verification failed"):
        verify_vm_target_evidence(
            target_evidence_path=fresh_ev_path,
            challenge_path=fresh_ch_path,
            root=ctrl_repo,
            installer_path=installer,
            compiled_exe_path=compiled_exe,
            expected_sidecar_sha256=sidecar_sha,
            clean_machine_e2e=True,
            vm_witness_path=bad_w_path,
            consumed_nonces_file=nonces_ledger,
        )

    # 7. Local developer machine masquerading as clean VM (same hostname OR dev tools present) MUST fail
    dev_host_ev_path = _simulate_clean_target_execution(
        target_dir=tmp_path / "dev_masquerade_same_host",
        challenge=fresh_challenge,
        ctrl_repo=ctrl_repo,
        installed_exe_sha=ctrl_info["installed_exe_sha"],
        observed_hostname=socket.gethostname(),
    )
    with pytest.raises(RuntimeError, match="matches Controller hostname"):
        sign_vm_witness_receipt(
            challenge_path=fresh_ch_path,
            target_evidence_path=dev_host_ev_path,
            vm_provenance_ref="fake-local-vm",
        )
    with pytest.raises(RuntimeError, match="matches Controller hostname"):
        verify_vm_target_evidence(
            target_evidence_path=dev_host_ev_path,
            challenge_path=fresh_ch_path,
            root=ctrl_repo,
            installer_path=installer,
            compiled_exe_path=compiled_exe,
            expected_sidecar_sha256=sidecar_sha,
            clean_machine_e2e=True,
            vm_witness_path=fresh_w_path,
            consumed_nonces_file=nonces_ledger,
        )

    dirty_tools_ev = json.loads(fresh_ev_path.read_text(encoding="utf-8"))
    dirty_tools_ev["target_probe"]["dev_tools_absent"] = False
    dirty_tools_ev["target_probe"]["found_dev_tools"] = ["git", "python"]
    dirty_tools_ev_path = tmp_path / "out" / "dirty_tools_ev.json"
    dirty_tools_ev_path.write_text(json.dumps(dirty_tools_ev, indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError, match="developer tools present"):
        verify_vm_target_evidence(
            target_evidence_path=dirty_tools_ev_path,
            challenge_path=fresh_ch_path,
            root=ctrl_repo,
            installer_path=installer,
            compiled_exe_path=compiled_exe,
            expected_sidecar_sha256=sidecar_sha,
            clean_machine_e2e=True,
            vm_witness_path=fresh_w_path,
            consumed_nonces_file=nonces_ledger,
        )

    # 8. Mismatched installer or source_commit MUST fail
    wrong_installer = tmp_path / "wrong_setup.exe"
    wrong_installer.write_bytes(b"MZ" + b"\xef" * 1_200_000)
    with pytest.raises(RuntimeError, match="Installer SHA-256 mismatch"):
        verify_vm_target_evidence(
            target_evidence_path=fresh_ev_path,
            challenge_path=fresh_ch_path,
            root=ctrl_repo,
            installer_path=wrong_installer,
            compiled_exe_path=compiled_exe,
            expected_sidecar_sha256=sidecar_sha,
            clean_machine_e2e=True,
            vm_witness_path=fresh_w_path,
            consumed_nonces_file=nonces_ledger,
        )

    bad_commit_ch = copy.deepcopy(fresh_challenge)
    bad_commit_ch["source_commit"] = "f" * 40
    bad_commit_ch_path = tmp_path / "out" / "bad_commit_ch.json"
    bad_commit_ch_path.write_text(json.dumps(bad_commit_ch, indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError, match="source_commit mismatch"):
        verify_vm_target_evidence(
            target_evidence_path=fresh_ev_path,
            challenge_path=bad_commit_ch_path,
            root=ctrl_repo,
        )


def test_nonce_ledger_serializes_concurrent_processes(tmp_path: Path):
    ledger = tmp_path / "État contrôleur" / "consumed_nonces.json"
    shared_nonce = "a" * 64
    other_nonce = "b" * 64
    # The same persisted nonce may be claimed only once, across separate interpreters.
    script = """
import sys
from pathlib import Path
from scripts.verify_companion_artifacts import _record_consumed_nonce

try:
    _record_consumed_nonce(Path(sys.argv[1]), sys.argv[2])
except RuntimeError as exc:
    if "REPLAY REJECTED" not in str(exc):
        raise
    sys.exit(3)
"""
    processes = []
    try:
        for nonce in (shared_nonce, shared_nonce, other_nonce):
            processes.append(
                subprocess.Popen([sys.executable, "-c", script, str(ledger), nonce], cwd=REPO_ROOT)
            )
        assert sorted(process.wait(timeout=60) for process in processes) == [0, 0, 3]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()
    assert json.loads(ledger.read_text(encoding="utf-8"))["consumed_nonces"] == [
        shared_nonce,
        other_nonce,
    ]
    # A fresh process also rejects an already consumed challenge.
    assert (
        subprocess.run(
            [sys.executable, "-c", script, str(ledger), shared_nonce],
            cwd=REPO_ROOT,
            timeout=60,
            check=False,
        ).returncode
        == 3
    )


def test_vm_target_powershell_script_syntax_and_hash_mismatch_guard(tmp_path: Path):
    """Verify scripts/vm_target_e2e.ps1 parses cleanly and rejects mismatched installer SHA-256."""
    ps_script = REPO_ROOT / "scripts" / "vm_target_e2e.ps1"
    assert ps_script.is_file()
    text = ps_script.read_text(encoding="utf-8")
    assert "NETFLOW_VM_ATTESTATION_HMAC_KEY" not in text
    assert "git rev-parse" not in text
    assert "clean_machine_verified" not in text

    if os.name != "nt":
        pytest.skip("PowerShell execution test requires Windows")

    shell_exe = shutil.which("pwsh") or shutil.which("powershell")
    if not shell_exe:
        pytest.skip("Neither pwsh nor powershell.exe is available")

    parse_cmd = (
        "$errs = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{ps_script}', [ref]$null, [ref]$errs); "
        "if ($errs -and $errs.Count -gt 0) { $errs | ForEach-Object { Write-Error $_.Message }; exit 1 }"
    )
    parse_proc = subprocess.run(
        [shell_exe, "-NoProfile", "-NonInteractive", "-Command", parse_cmd],
        capture_output=True,
        text=True,
        check=False,
    )
    assert parse_proc.returncode == 0, parse_proc.stderr or parse_proc.stdout

    # Run script in an isolated workdir with mismatched installer hash -> must fail closed before install
    fake_inst = tmp_path / "fake-setup.exe"
    fake_inst.write_bytes(b"MZ" + b"\x00" * 1_100_000)
    fake_ch = tmp_path / "challenge.json"
    fake_ch.write_text(
        json.dumps(
            {
                "format": "netflow-sentinel-vm-challenge-v1",
                "challenge_nonce": "a" * 64,
                "installer_sha256": "0" * 64,
                "sidecar_sha256": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    out_json = tmp_path / "target_ev.json"
    run_proc = subprocess.run(
        [
            shell_exe,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(ps_script),
            "-InstallerPath",
            str(fake_inst),
            "-ChallengePath",
            str(fake_ch),
            "-OutputJson",
            str(out_json),
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )
    assert run_proc.returncode != 0
    assert "Installer SHA-256 mismatch" in (run_proc.stderr + run_proc.stdout)
    assert not out_json.exists()
